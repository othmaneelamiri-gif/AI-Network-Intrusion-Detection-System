"""
SQLite database layer for the IDS platform.
Handles packets, alerts, and statistics persistence.
"""

import sqlite3
import threading
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class DatabaseManager:
    def __init__(self, db_path: str = "data/ids.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    @contextmanager
    def _get_conn(self):
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        try:
            yield self._local.conn
        except Exception:
            self._local.conn.rollback()
            raise

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS packets (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT    NOT NULL,
                    src_ip      TEXT    NOT NULL,
                    dst_ip      TEXT    NOT NULL,
                    src_port    INTEGER DEFAULT 0,
                    dst_port    INTEGER DEFAULT 0,
                    protocol    TEXT    DEFAULT 'OTHER',
                    length      INTEGER DEFAULT 0,
                    flags       TEXT    DEFAULT '',
                    ttl         INTEGER DEFAULT 64
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp    TEXT    NOT NULL,
                    alert_type   TEXT    NOT NULL,
                    severity     TEXT    NOT NULL,
                    src_ip       TEXT    NOT NULL,
                    dst_ip       TEXT    DEFAULT '',
                    description  TEXT    NOT NULL,
                    details      TEXT    DEFAULT '{}',
                    acknowledged INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS stats_snapshots (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT NOT NULL,
                    total_packets   INTEGER DEFAULT 0,
                    total_alerts    INTEGER DEFAULT 0,
                    bytes_captured  INTEGER DEFAULT 0,
                    active_threats  INTEGER DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_packets_ts     ON packets(timestamp);
                CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip);
                CREATE INDEX IF NOT EXISTS idx_alerts_ts      ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_alerts_type    ON alerts(alert_type);
            """)
        logger.info(f"Database initialised at {self.db_path}")

    # ── Packets ─────────────────────────────────────────────────────────────

    def insert_packet(self, p: dict):
        sql = """
            INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port,
                                 protocol, length, flags, ttl)
            VALUES (:timestamp, :src_ip, :dst_ip, :src_port, :dst_port,
                    :protocol, :length, :flags, :ttl)
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(sql, p)

    def get_recent_packets(self, limit: int = 100) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_packet_count(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]

    def get_top_src_ips(self, limit: int = 10) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT src_ip, COUNT(*) AS count
                FROM packets
                GROUP BY src_ip
                ORDER BY count DESC
                LIMIT ?
            """, (limit,)).fetchall()
        return [{"ip": r[0], "count": r[1]} for r in rows]

    def get_protocol_distribution(self) -> Dict[str, int]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT protocol, COUNT(*) AS cnt
                FROM packets
                GROUP BY protocol
            """).fetchall()
        return {r[0]: r[1] for r in rows}

    def get_traffic_over_time(self, minutes: int = 60) -> List[Dict]:
        since = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT strftime('%Y-%m-%dT%H:%M:00', timestamp) AS minute,
                       COUNT(*) AS count
                FROM packets
                WHERE timestamp > ?
                GROUP BY minute
                ORDER BY minute
            """, (since,)).fetchall()
        return [{"time": r[0], "count": r[1]} for r in rows]

    # ── Alerts ───────────────────────────────────────────────────────────────

    def insert_alert(self, alert: dict) -> int:
        sql = """
            INSERT INTO alerts (timestamp, alert_type, severity, src_ip,
                                dst_ip, description, details)
            VALUES (:timestamp, :alert_type, :severity, :src_ip,
                    :dst_ip, :description, :details)
        """
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(sql, alert)
            return cur.lastrowid

    def get_recent_alerts(self, limit: int = 50, alert_type: Optional[str] = None) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if alert_type:
                rows = conn.execute(
                    "SELECT * FROM alerts WHERE alert_type=? ORDER BY id DESC LIMIT ?",
                    (alert_type, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
        return [dict(r) for r in rows]

    def get_alert_count(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def get_alert_summary(self) -> Dict:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT alert_type, severity, COUNT(*) AS cnt
                FROM alerts
                GROUP BY alert_type, severity
            """).fetchall()
        summary: Dict = {}
        for r in rows:
            summary.setdefault(r[0], {})[r[1]] = r[2]
        return summary

    def acknowledge_alert(self, alert_id: int):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))

    def get_alerts_over_time(self, minutes: int = 60) -> List[Dict]:
        since = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT strftime('%Y-%m-%dT%H:%M:00', timestamp) AS minute,
                       COUNT(*) AS count
                FROM alerts
                WHERE timestamp > ?
                GROUP BY minute
                ORDER BY minute
            """, (since,)).fetchall()
        return [{"time": r[0], "count": r[1]} for r in rows]

    # ── Snapshots ────────────────────────────────────────────────────────────

    def save_snapshot(self, snapshot: dict):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO stats_snapshots
                    (timestamp, total_packets, total_alerts, bytes_captured, active_threats)
                VALUES (:timestamp, :total_packets, :total_alerts, :bytes_captured, :active_threats)
            """, snapshot)

    def get_snapshots(self, limit: int = 100) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM stats_snapshots ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
