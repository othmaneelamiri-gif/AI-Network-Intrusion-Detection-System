"""
Detection engine: rule-based detection for Port Scan, Bruteforce, DDoS.
Each detector is a self-contained class with a sliding-window approach.
"""

import json
import logging
import threading
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional

from core.database import DatabaseManager

logger = logging.getLogger(__name__)


# ── Base ──────────────────────────────────────────────────────────────────────

class BaseDetector(ABC):
    def __init__(self, db: DatabaseManager, name: str):
        self.db = db
        self.name = name
        self._lock = threading.Lock()

    def _fire_alert(self, alert_type: str, severity: str, src_ip: str,
                    dst_ip: str, description: str, details: dict):
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "alert_type": alert_type,
            "severity": severity,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "description": description,
            "details": json.dumps(details),
        }
        alert_id = self.db.insert_alert(alert)
        logger.warning(f"[{severity}] {alert_type} — {description} (id={alert_id})")
        return alert_id

    @abstractmethod
    def analyze(self, packet: dict):
        ...


# ── Port Scan Detector ────────────────────────────────────────────────────────

class PortScanDetector(BaseDetector):
    """
    Detects horizontal/vertical port scans.
    Threshold: ≥15 distinct destination ports from one source within 10 seconds.
    """

    WINDOW_SECONDS = 10
    PORT_THRESHOLD = 15
    SYN_FLAGS = {"S", "2"}

    def __init__(self, db: DatabaseManager):
        super().__init__(db, "PortScan")
        # src_ip -> deque of (timestamp, dst_port)
        self._activity: dict[str, deque] = defaultdict(deque)
        self._alerted: dict[str, datetime] = {}      # cooldown per src_ip

    def analyze(self, packet: dict):
        if packet.get("protocol") != "TCP":
            return
        if packet.get("flags", "") not in self.SYN_FLAGS:
            return

        src_ip = packet["src_ip"]
        dst_port = packet.get("dst_port", 0)
        now = datetime.fromisoformat(packet["timestamp"])
        cutoff = now - timedelta(seconds=self.WINDOW_SECONDS)

        with self._lock:
            q = self._activity[src_ip]
            q.append((now, dst_port))
            # Evict stale entries
            while q and q[0][0] < cutoff:
                q.popleft()

            distinct_ports = len({p for _, p in q})

            # Cooldown: don't re-alert within 30 s
            last_alert = self._alerted.get(src_ip)
            if distinct_ports >= self.PORT_THRESHOLD and (
                last_alert is None or (now - last_alert).total_seconds() > 30
            ):
                self._alerted[src_ip] = now
                self._fire_alert(
                    alert_type="PORT_SCAN",
                    severity="HIGH",
                    src_ip=src_ip,
                    dst_ip=packet["dst_ip"],
                    description=f"Port scan detected: {distinct_ports} ports in {self.WINDOW_SECONDS}s",
                    details={"distinct_ports": distinct_ports, "window_seconds": self.WINDOW_SECONDS},
                )


# ── Brute Force Detector ──────────────────────────────────────────────────────

class BruteForceDetector(BaseDetector):
    """
    Detects SSH/FTP/RDP brute-force attempts.
    Threshold: ≥10 connection attempts to port 22/21/3389 from same IP in 30 s.
    """

    BRUTE_PORTS = {22, 21, 3389, 5900, 23}
    WINDOW_SECONDS = 30
    ATTEMPT_THRESHOLD = 10

    def __init__(self, db: DatabaseManager):
        super().__init__(db, "BruteForce")
        self._activity: dict[str, deque] = defaultdict(deque)
        self._alerted: dict[str, datetime] = {}

    def analyze(self, packet: dict):
        dst_port = packet.get("dst_port", 0)
        if dst_port not in self.BRUTE_PORTS:
            return

        src_ip = packet["src_ip"]
        now = datetime.fromisoformat(packet["timestamp"])
        cutoff = now - timedelta(seconds=self.WINDOW_SECONDS)

        with self._lock:
            q = self._activity[src_ip]
            q.append(now)
            while q and q[0] < cutoff:
                q.popleft()

            attempts = len(q)
            last_alert = self._alerted.get(src_ip)
            if attempts >= self.ATTEMPT_THRESHOLD and (
                last_alert is None or (now - last_alert).total_seconds() > 60
            ):
                self._alerted[src_ip] = now
                service_map = {22: "SSH", 21: "FTP", 3389: "RDP", 5900: "VNC", 23: "Telnet"}
                service = service_map.get(dst_port, str(dst_port))
                self._fire_alert(
                    alert_type="BRUTEFORCE",
                    severity="CRITICAL",
                    src_ip=src_ip,
                    dst_ip=packet["dst_ip"],
                    description=f"{service} brute-force: {attempts} attempts in {self.WINDOW_SECONDS}s",
                    details={"service": service, "attempts": attempts, "dst_port": dst_port},
                )


# ── DDoS Detector ─────────────────────────────────────────────────────────────

class DDoSDetector(BaseDetector):
    """
    Detects volumetric DDoS (SYN flood / UDP flood).
    Threshold: ≥200 packets/second targeting the same destination.
    """

    WINDOW_SECONDS = 5
    PACKET_THRESHOLD = 200

    def __init__(self, db: DatabaseManager):
        super().__init__(db, "DDoS")
        # dst_ip -> deque of timestamps
        self._activity: dict[str, deque] = defaultdict(deque)
        self._src_ips: dict[str, set] = defaultdict(set)
        self._alerted: dict[str, datetime] = {}

    def analyze(self, packet: dict):
        dst_ip = packet["dst_ip"]
        src_ip = packet["src_ip"]
        now = datetime.fromisoformat(packet["timestamp"])
        cutoff = now - timedelta(seconds=self.WINDOW_SECONDS)

        with self._lock:
            q = self._activity[dst_ip]
            q.append(now)
            self._src_ips[dst_ip].add(src_ip)

            while q and q[0] < cutoff:
                q.popleft()

            pps = len(q) / self.WINDOW_SECONDS
            last_alert = self._alerted.get(dst_ip)
            if pps >= self.PACKET_THRESHOLD and (
                last_alert is None or (now - last_alert).total_seconds() > 30
            ):
                self._alerted[dst_ip] = now
                unique_srcs = len(self._src_ips[dst_ip])
                ddos_type = "Distributed" if unique_srcs > 5 else "Volumetric"
                self._fire_alert(
                    alert_type="DDOS",
                    severity="CRITICAL",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    description=f"{ddos_type} DDoS: {pps:.0f} pps targeting {dst_ip}",
                    details={"pps": round(pps, 2), "unique_sources": unique_srcs, "ddos_type": ddos_type},
                )


# ── Anomaly Detector (ML) ──────────────────────────────────────────────────────

class AnomalyDetector(BaseDetector):
    """
    Wraps the ML model from ml/model.py for anomaly scoring.
    Falls back to rule-based if model is not trained.
    """

    def __init__(self, db: DatabaseManager):
        super().__init__(db, "Anomaly")
        self._model = None
        self._load_model()

    def _load_model(self):
        try:
            from ml.model import IDSModel
            self._model = IDSModel()
            self._model.load()
            logger.info("ML model loaded for anomaly detection")
        except Exception as e:
            logger.warning(f"ML model not available: {e}")

    def analyze(self, packet: dict):
        if self._model is None:
            return
        try:
            label, confidence = self._model.predict(packet)
            if label != "normal" and confidence > 0.80:
                self._fire_alert(
                    alert_type=f"ML_{label.upper()}",
                    severity="MEDIUM",
                    src_ip=packet["src_ip"],
                    dst_ip=packet.get("dst_ip", ""),
                    description=f"ML anomaly: {label} (confidence {confidence:.0%})",
                    details={"label": label, "confidence": round(confidence, 4)},
                )
        except Exception as e:
            logger.debug(f"ML predict error: {e}")


# ── Orchestrator ──────────────────────────────────────────────────────────────

class DetectionEngine:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self.detectors = [
            PortScanDetector(db),
            BruteForceDetector(db),
            DDoSDetector(db),
            AnomalyDetector(db),
        ]
        self._analyzed = 0

    def process(self, packet: dict):
        """Run all detectors against a single packet."""
        for detector in self.detectors:
            try:
                detector.analyze(packet)
            except Exception as e:
                logger.error(f"Detector {detector.name} error: {e}")
        self._analyzed += 1

    @property
    def analyzed_count(self):
        return self._analyzed
