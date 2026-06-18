# 🛡️ IDS Platform — AI-Powered Intrusion Detection System

> Detect. Alert. Protect.  
> A production-ready Network Intrusion Detection System using Python, Scapy, ML and a real-time web dashboard.

---

## Architecture

```
ids-platform/
├── core/
│   ├── capture.py       # Packet capture (Scapy / simulation mode)
│   ├── detection.py     # Rule-based detectors (PortScan, BruteForce, DDoS) + ML
│   └── database.py      # SQLite persistence layer
├── ml/
│   ├── model.py         # RandomForest classifier + feature engineering
│   └── train.py         # Training script
├── api/
│   └── app.py           # Flask REST API + SocketIO real-time events
├── dashboard/
│   └── templates/
│       └── index.html   # Dark-themed real-time dashboard
├── reports/
│   └── generator.py     # PDF report generation (ReportLab)
├── tests/
│   └── test_ids.py      # Pytest test suite
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
└── requirements.txt
```

---

## Quick Start

### 1. Local (simulation mode — no root needed)

```bash
# Install dependencies
pip install -r requirements.txt

# Train the ML model
python -m ml.train --samples 10000

# Start the IDS (simulation mode)
python -m api.app --port 5000

# Open the dashboard
open http://localhost:5000
```

### 2. Docker

```bash
cd docker
docker-compose up --build
# Dashboard → http://localhost:5000
```

### 3. Live Capture (requires root)

```bash
sudo python -m api.app --interface eth0 --port 5000
```

---

## Detection Modules

### Port Scan Detection
- **Algorithm**: Sliding window (10 seconds)
- **Trigger**: ≥ 15 distinct destination ports from same source IP
- **Severity**: HIGH
- **Technique**: TCP SYN flag filtering + deque-based time window

### Brute Force Detection
- **Algorithm**: Sliding window (30 seconds)
- **Trigger**: ≥ 10 connection attempts to SSH/FTP/RDP/Telnet
- **Severity**: CRITICAL
- **Monitored ports**: 22 (SSH), 21 (FTP), 3389 (RDP), 23 (Telnet), 5900 (VNC)

### DDoS Detection
- **Algorithm**: Packets-per-second calculation over 5-second window
- **Trigger**: ≥ 200 pps targeting same destination
- **Severity**: CRITICAL
- **Sub-types**: Volumetric / Distributed (based on unique source count)

### ML Anomaly Detection (Scikit-Learn)
- **Algorithm**: Random Forest Classifier (100 trees)
- **Features**: 11 engineered features from packet metadata
- **Classes**: normal / port_scan / bruteforce / ddos
- **Trigger**: confidence > 80% on non-normal class
- **Training**: Synthetic data bootstrap + live retraining via API

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard UI |
| GET | `/api/stats` | System statistics |
| GET | `/api/alerts?limit=N&type=X` | Alert feed |
| POST | `/api/alerts/<id>/acknowledge` | Acknowledge alert |
| GET | `/api/packets?limit=N` | Recent packets |
| GET | `/api/traffic/timeline?minutes=N` | Time-series data |
| GET | `/api/report` | Download PDF report |
| POST | `/api/ml/train` | Retrain ML model |

### WebSocket Events

| Event | Direction | Payload |
|-------|-----------|---------|
| `live_stats` | Server → Client | packet count, alert count, pps |
| `new_packet` | Server → Client | individual packet data |

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v

# With coverage
pip install pytest-cov
pytest tests/ -v --cov=core --cov=ml --cov-report=term-missing
```

Expected output:
```
tests/test_ids.py::TestDatabase::test_insert_and_count        PASSED
tests/test_ids.py::TestDatabase::test_recent_packets          PASSED
tests/test_ids.py::TestPortScanDetector::test_alert_at_threshold  PASSED
tests/test_ids.py::TestBruteForceDetector::test_ssh_bruteforce_detected  PASSED
tests/test_ids.py::TestMLModel::test_train_and_predict        PASSED
...
```

---

## Feature Flags

| Environment Variable | Default | Description |
|----------------------|---------|-------------|
| `IDS_SECRET` | `ids-dev-secret` | Flask session secret |
| `--interface` | `eth0` | Network interface |
| `--pcap` | None | Replay a PCAP file |
| `--port` | `5000` | Dashboard port |

---

## CV Modules Covered

| Module | Implementation |
|--------|----------------|
| **Réseaux** | Scapy packet capture, protocol parsing |
| **Sécurité Réseaux** | Port scan / BF / DDoS detection |
| **Cryptographie** | HTTPS-ready Flask, secret key management |
| **Python** | 100% Python, OOP architecture |
| **IA / ML** | RandomForest, feature engineering, live inference |
| **Détection d'intrusion** | Multi-detector engine, alert pipeline |
| **Cloud** | Docker, docker-compose, REST API |

---

## Roadmap

- [ ] GeoIP lookup for attacker locations
- [ ] Email/Slack alert notifications  
- [ ] PCAP export of malicious flows
- [ ] Suricata rule integration
- [ ] Multi-sensor distributed mode
- [ ] CVE correlation database
