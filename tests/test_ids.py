"""
Tests for core IDS components.
Run with: pytest tests/ -v
"""

import sys
import os
import json
import pytest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


# ── Database ──────────────────────────────────────────────────────────────────

@pytest.fixture
def db():
    from core.database import DatabaseManager
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    yield DatabaseManager(path)
    os.unlink(path)


def make_packet(src="1.1.1.1", dst="2.2.2.2", proto="TCP",
                dst_port=80, flags="PA", length=200, ttl=64):
    from datetime import datetime
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": src,
        "dst_ip": dst,
        "src_port": 12345,
        "dst_port": dst_port,
        "protocol": proto,
        "length": length,
        "flags": flags,
        "ttl": ttl,
    }


class TestDatabase:
    def test_insert_and_count(self, db):
        assert db.get_packet_count() == 0
        db.insert_packet(make_packet())
        assert db.get_packet_count() == 1

    def test_recent_packets(self, db):
        for _ in range(5):
            db.insert_packet(make_packet())
        pkts = db.get_recent_packets(limit=3)
        assert len(pkts) == 3

    def test_insert_alert(self, db):
        alert = {
            "timestamp": "2024-01-01T00:00:00",
            "alert_type": "PORT_SCAN",
            "severity": "HIGH",
            "src_ip": "1.2.3.4",
            "dst_ip": "10.0.0.1",
            "description": "Test alert",
            "details": "{}",
        }
        aid = db.insert_alert(alert)
        assert aid > 0
        assert db.get_alert_count() == 1

    def test_protocol_distribution(self, db):
        db.insert_packet(make_packet(proto="TCP"))
        db.insert_packet(make_packet(proto="UDP"))
        dist = db.get_protocol_distribution()
        assert dist["TCP"] >= 1
        assert dist["UDP"] >= 1

    def test_top_src_ips(self, db):
        for _ in range(3):
            db.insert_packet(make_packet(src="10.0.0.1"))
        db.insert_packet(make_packet(src="10.0.0.2"))
        tops = db.get_top_src_ips(limit=2)
        assert tops[0]["ip"] == "10.0.0.1"
        assert tops[0]["count"] == 3


# ── Detection ─────────────────────────────────────────────────────────────────

class TestPortScanDetector:
    def test_no_alert_below_threshold(self, db):
        from core.detection import PortScanDetector
        det = PortScanDetector(db)
        for port in range(5):
            det.analyze(make_packet(dst_port=port, flags="S"))
        assert db.get_alert_count() == 0

    def test_alert_at_threshold(self, db):
        from core.detection import PortScanDetector
        det = PortScanDetector(db)
        for port in range(20):
            det.analyze(make_packet(dst_port=port, flags="S"))
        assert db.get_alert_count() >= 1
        alerts = db.get_recent_alerts()
        assert alerts[0]["alert_type"] == "PORT_SCAN"


class TestBruteForceDetector:
    def test_ssh_bruteforce_detected(self, db):
        from core.detection import BruteForceDetector
        det = BruteForceDetector(db)
        for _ in range(15):
            det.analyze(make_packet(dst_port=22, flags="PA"))
        assert db.get_alert_count() >= 1
        alerts = db.get_recent_alerts()
        assert alerts[0]["alert_type"] == "BRUTEFORCE"

    def test_non_sensitive_port_ignored(self, db):
        from core.detection import BruteForceDetector
        det = BruteForceDetector(db)
        for _ in range(20):
            det.analyze(make_packet(dst_port=8080, flags="PA"))
        assert db.get_alert_count() == 0


# ── ML Model ──────────────────────────────────────────────────────────────────

class TestMLModel:
    def test_feature_extraction(self):
        from ml.model import extract_features
        p = make_packet(proto="TCP", dst_port=22, flags="S", length=40, ttl=64)
        feats = extract_features(p)
        assert feats.shape == (11,)
        assert feats[0] == 1.0   # TCP
        assert feats[9] == 1.0   # is_ssh

    def test_train_and_predict(self):
        from ml.model import IDSModel, generate_training_data
        packets, labels = generate_training_data(500)
        model = IDSModel()
        metrics = model.train(packets, labels)
        assert metrics["accuracy"] > 0.5

        label, conf = model.predict(make_packet(dst_port=22, flags="PA"))
        assert label in ("normal", "port_scan", "bruteforce", "ddos")
        assert 0.0 <= conf <= 1.0

    def test_generate_training_data(self):
        from ml.model import generate_training_data
        pkts, labels = generate_training_data(100)
        assert len(pkts) == 100
        assert len(labels) == 100
        assert set(labels).issubset({"normal", "port_scan", "bruteforce", "ddos"})
