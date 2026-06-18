"""
Flask REST API + SocketIO for the IDS dashboard.
"""

import json
import logging
import os
import sys
import threading
import time
from datetime import datetime

from flask import Flask, jsonify, render_template, request, send_file
from flask_socketio import SocketIO, emit

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from core.database import DatabaseManager
from core.capture import PacketCapture
from core.detection import DetectionEngine

logger = logging.getLogger(__name__)

# ── App setup ─────────────────────────────────────────────────────────────────

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app = Flask(
    __name__,
    template_folder=os.path.join(_root, "dashboard", "templates"),
    static_folder=os.path.join(_root, "dashboard", "static"),
)
app.config["SECRET_KEY"] = os.environ.get("IDS_SECRET", "ids-dev-secret")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Globals (initialised in main) ─────────────────────────────────────────────

db: DatabaseManager = None
engine: DetectionEngine = None
capture: PacketCapture = None


def on_packet(packet: dict):
    """Called for every captured packet — run detection, emit to browser."""
    engine.process(packet)
    socketio.emit("new_packet", packet)


# ── REST Endpoints ────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def stats():
    cap_stats = capture.get_stats() if capture else {}
    return jsonify({
        "packet_count": db.get_packet_count(),
        "alert_count": db.get_alert_count(),
        "protocol_distribution": db.get_protocol_distribution(),
        "top_src_ips": db.get_top_src_ips(),
        "capture": cap_stats,
    })


@app.route("/api/alerts")
def alerts():
    limit = int(request.args.get("limit", 50))
    alert_type = request.args.get("type")
    return jsonify(db.get_recent_alerts(limit=limit, alert_type=alert_type))


@app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
def acknowledge_alert(alert_id):
    db.acknowledge_alert(alert_id)
    return jsonify({"status": "ok"})


@app.route("/api/packets")
def packets():
    limit = int(request.args.get("limit", 100))
    return jsonify(db.get_recent_packets(limit=limit))


@app.route("/api/traffic/timeline")
def traffic_timeline():
    minutes = int(request.args.get("minutes", 60))
    return jsonify({
        "traffic": db.get_traffic_over_time(minutes=minutes),
        "alerts": db.get_alerts_over_time(minutes=minutes),
    })


@app.route("/api/report")
def report():
    from reports.generator import generate_pdf
    path = generate_pdf(db)
    return send_file(path, as_attachment=True, download_name="ids_report.pdf")


@app.route("/api/ml/train", methods=["POST"])
def train_model():
    from ml.model import IDSModel, generate_training_data
    n = int(request.json.get("samples", 5000)) if request.json else 5000
    packets, labels = generate_training_data(n)
    model = IDSModel()
    metrics = model.train(packets, labels)
    return jsonify(metrics)


# ── SocketIO ──────────────────────────────────────────────────────────────────

@socketio.on("connect")
def on_connect():
    logger.info(f"Client connected: {request.sid}")
    emit("stats", db.get_alert_count())


# ── Background stats broadcaster ─────────────────────────────────────────────

def _broadcast_stats():
    while True:
        try:
            payload = {
                "packet_count": db.get_packet_count(),
                "alert_count": db.get_alert_count(),
                "capture": capture.get_stats() if capture else {},
                "recent_alerts": db.get_recent_alerts(limit=5),
            }
            socketio.emit("live_stats", payload)
        except Exception as e:
            logger.error(f"Broadcast error: {e}")
        time.sleep(3)


# ── Entrypoint ────────────────────────────────────────────────────────────────

def create_app(interface: str = "eth0", pcap_file=None):
    global db, engine, capture

    os.makedirs("data", exist_ok=True)
    db = DatabaseManager("data/ids.db")
    engine = DetectionEngine(db)
    capture = PacketCapture(db, interface=interface, packet_callback=on_packet)
    capture.start(pcap_file=pcap_file)

    threading.Thread(target=_broadcast_stats, daemon=True).start()
    return app


if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="IDS Platform")
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--pcap")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    application = create_app(interface=args.interface, pcap_file=args.pcap)
    socketio.run(application, host="0.0.0.0", port=args.port, debug=args.debug)
