"""
Packet capture engine using Scapy.
Supports live capture and PCAP file replay.
"""

import threading
import time
import logging
from datetime import datetime
from collections import defaultdict, deque
from typing import Callable, Optional

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, wrpcap, rdpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from core.database import DatabaseManager

logger = logging.getLogger(__name__)


class PacketCapture:
    def __init__(self, db: DatabaseManager, interface: str = "eth0", 
                 packet_callback: Optional[Callable] = None):
        self.db = db
        self.interface = interface
        self.packet_callback = packet_callback
        self.running = False
        self.capture_thread = None
        self.stats = {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "other_packets": 0,
            "bytes_captured": 0,
            "start_time": None,
        }
        # Sliding window for rate calculations
        self.packet_window = deque(maxlen=10000)
        self._lock = threading.Lock()

    def start(self, pcap_file: Optional[str] = None):
        """Start packet capture, optionally from a PCAP file."""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available — running in simulation mode")
            self._start_simulation()
            return

        self.running = True
        self.stats["start_time"] = datetime.utcnow().isoformat()

        if pcap_file:
            self.capture_thread = threading.Thread(
                target=self._replay_pcap, args=(pcap_file,), daemon=True
            )
        else:
            self.capture_thread = threading.Thread(
                target=self._live_capture, daemon=True
            )

        self.capture_thread.start()
        logger.info(f"Capture started on {self.interface}")

    def stop(self):
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logger.info("Capture stopped")

    def _live_capture(self):
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                stop_filter=lambda _: not self.running,
                store=False,
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")

    def _replay_pcap(self, pcap_file: str):
        try:
            packets = rdpcap(pcap_file)
            for pkt in packets:
                if not self.running:
                    break
                self._process_packet(pkt)
                time.sleep(0.001)
        except Exception as e:
            logger.error(f"PCAP replay error: {e}")

    def _start_simulation(self):
        """Generate synthetic traffic for demo/testing."""
        self.running = True
        self.stats["start_time"] = datetime.utcnow()
        self.capture_thread = threading.Thread(target=self._simulate_traffic, daemon=True)
        self.capture_thread.start()
        logger.info("Simulation mode active")

    def _simulate_traffic(self):
        import random
        src_ips = [f"192.168.1.{i}" for i in range(1, 20)]
        dst_ips = [f"10.0.0.{i}" for i in range(1, 10)]
        
        # Simulate attack scenarios
        scenarios = [
            ("normal", 0.7),
            ("port_scan", 0.1),
            ("bruteforce", 0.1),
            ("ddos", 0.1),
        ]

        while self.running:
            scenario = random.choices(
                [s[0] for s in scenarios],
                weights=[s[1] for s in scenarios]
            )[0]

            if scenario == "normal":
                packet_data = self._gen_normal(random.choice(src_ips), random.choice(dst_ips))
            elif scenario == "port_scan":
                packet_data = self._gen_port_scan(random.choice(src_ips), random.choice(dst_ips))
            elif scenario == "bruteforce":
                packet_data = self._gen_bruteforce(random.choice(src_ips), random.choice(dst_ips))
            else:
                packet_data = self._gen_ddos(random.choice(src_ips), random.choice(dst_ips))

            self._store_packet(packet_data)
            
            if self.packet_callback:
                self.packet_callback(packet_data)

            time.sleep(random.uniform(0.01, 0.1))

    def _gen_normal(self, src, dst):
        import random
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 53, 22, 25]),
            "protocol": random.choice(["TCP", "UDP"]),
            "length": random.randint(64, 1500),
            "flags": "PA",
            "ttl": 64,
        }

    def _gen_port_scan(self, src, dst):
        import random
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(1024, 65535),
            "dst_port": random.randint(1, 1024),
            "protocol": "TCP",
            "length": 40,
            "flags": "S",
            "ttl": 64,
        }

    def _gen_bruteforce(self, src, dst):
        import random
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(1024, 65535),
            "dst_port": 22,
            "protocol": "TCP",
            "length": random.randint(40, 200),
            "flags": "PA",
            "ttl": 64,
        }

    def _gen_ddos(self, src, dst):
        import random
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": src,
            "dst_ip": dst,
            "src_port": random.randint(1024, 65535),
            "dst_port": 80,
            "protocol": random.choice(["TCP", "UDP"]),
            "length": random.randint(40, 100),
            "flags": "S",
            "ttl": random.randint(30, 64),
        }

    def _process_packet(self, pkt):
        """Parse a real Scapy packet."""
        if not pkt.haslayer(IP):
            return

        packet_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "src_port": 0,
            "dst_port": 0,
            "protocol": "OTHER",
            "length": len(pkt),
            "flags": "",
            "ttl": pkt[IP].ttl,
        }

        with self._lock:
            self.stats["total_packets"] += 1
            self.stats["bytes_captured"] += len(pkt)

        if pkt.haslayer(TCP):
            packet_data["protocol"] = "TCP"
            packet_data["src_port"] = pkt[TCP].sport
            packet_data["dst_port"] = pkt[TCP].dport
            packet_data["flags"] = str(pkt[TCP].flags)
            with self._lock:
                self.stats["tcp_packets"] += 1
        elif pkt.haslayer(UDP):
            packet_data["protocol"] = "UDP"
            packet_data["src_port"] = pkt[UDP].sport
            packet_data["dst_port"] = pkt[UDP].dport
            with self._lock:
                self.stats["udp_packets"] += 1
        elif pkt.haslayer(ICMP):
            packet_data["protocol"] = "ICMP"
            with self._lock:
                self.stats["icmp_packets"] += 1

        self.packet_window.append(packet_data)
        self._store_packet(packet_data)

        if self.packet_callback:
            self.packet_callback(packet_data)

    def _store_packet(self, packet_data: dict):
        with self._lock:
            self.stats["total_packets"] += 1
            self.stats["bytes_captured"] += packet_data.get("length", 0)
        self.db.insert_packet(packet_data)

    def get_stats(self) -> dict:
        with self._lock:
            stats = dict(self.stats)
        if stats["start_time"]:
            elapsed = (datetime.utcnow() - datetime.fromisoformat(stats["start_time"])).total_seconds()
            stats["uptime_seconds"] = int(elapsed)
            stats["pps"] = round(stats["total_packets"] / max(elapsed, 1), 2)
        return stats

    def get_recent_packets(self, n: int = 100) -> list:
        return list(self.packet_window)[-n:]
