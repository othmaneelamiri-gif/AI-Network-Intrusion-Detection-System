"""
ML model for IDS traffic classification.
Uses scikit-learn RandomForest with feature extraction from packet metadata.
Supports training, evaluation, persistence, and inference.
"""

import os
import json
import logging
import numpy as np
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

MODEL_PATH = "data/ids_model.pkl"
LABEL_MAP = {0: "normal", 1: "port_scan", 2: "bruteforce", 3: "ddos"}
REVERSE_LABEL = {v: k for k, v in LABEL_MAP.items()}

# ── Feature extraction ────────────────────────────────────────────────────────

def extract_features(packet: dict) -> np.ndarray:
    """
    Extract a fixed-length numeric feature vector from a packet dict.
    Features:
      [0]  Protocol one-hot: TCP=1,0,0 / UDP=0,1,0 / ICMP=0,0,1 / other=0,0,0
      [3]  dst_port normalised (0..1 over 65535)
      [4]  src_port normalised
      [5]  packet length normalised (0..1 over 1500)
      [6]  TTL normalised (0..1 over 255)
      [7]  is_syn_flag (1 if TCP SYN)
      [8]  dst_port_is_well_known (dst_port < 1024)
      [9]  dst_port_is_ssh (22)
      [10] dst_port_is_web (80 or 443)
    """
    proto = packet.get("protocol", "OTHER")
    tcp = 1 if proto == "TCP" else 0
    udp = 1 if proto == "UDP" else 0
    icmp = 1 if proto == "ICMP" else 0

    dst_port = int(packet.get("dst_port", 0))
    src_port = int(packet.get("src_port", 0))
    length = int(packet.get("length", 0))
    ttl = int(packet.get("ttl", 64))
    flags = str(packet.get("flags", ""))
    is_syn = 1 if flags in ("S", "2") else 0

    features = np.array([
        tcp,
        udp,
        icmp,
        dst_port / 65535.0,
        src_port / 65535.0,
        min(length, 1500) / 1500.0,
        ttl / 255.0,
        is_syn,
        1 if dst_port < 1024 else 0,
        1 if dst_port == 22 else 0,
        1 if dst_port in (80, 443) else 0,
    ], dtype=np.float32)

    return features


# ── Model wrapper ─────────────────────────────────────────────────────────────

class IDSModel:
    def __init__(self):
        self._clf = None
        self._is_trained = False

    def train(self, packets: list, labels: list) -> dict:
        """
        Train a RandomForest classifier.
        labels must be strings: 'normal', 'port_scan', 'bruteforce', 'ddos'
        Returns evaluation metrics.
        """
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report, accuracy_score

        X = np.array([extract_features(p) for p in packets])
        y = np.array([REVERSE_LABEL.get(l, 0) for l in labels])

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        self._clf = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1,
        )
        self._clf.fit(X_train, y_train)
        self._is_trained = True

        y_pred = self._clf.predict(X_test)
        report = classification_report(y_test, y_pred, target_names=list(LABEL_MAP.values()), output_dict=True)
        accuracy = accuracy_score(y_test, y_pred)

        logger.info(f"Model trained — accuracy: {accuracy:.3f}")
        self.save()
        return {"accuracy": round(accuracy, 4), "report": report}

    def predict(self, packet: dict) -> Tuple[str, float]:
        """Returns (label, confidence)."""
        if not self._is_trained or self._clf is None:
            raise RuntimeError("Model not trained")
        features = extract_features(packet).reshape(1, -1)
        label_idx = int(self._clf.predict(features)[0])
        probas = self._clf.predict_proba(features)[0]
        confidence = float(probas[label_idx])
        return LABEL_MAP[label_idx], confidence

    def save(self, path: str = MODEL_PATH):
        import pickle
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump({"clf": self._clf, "trained": self._is_trained}, f)
        logger.info(f"Model saved to {path}")

    def load(self, path: str = MODEL_PATH):
        import pickle
        if not os.path.exists(path):
            raise FileNotFoundError(f"No model at {path}")
        with open(path, "rb") as f:
            obj = pickle.load(f)
        self._clf = obj["clf"]
        self._is_trained = obj["trained"]
        logger.info(f"Model loaded from {path}")

    @property
    def is_trained(self):
        return self._is_trained


# ── Synthetic data generator for bootstrap training ───────────────────────────

def generate_training_data(n_samples: int = 5000) -> Tuple[list, list]:
    """Generate synthetic labelled packets for initial model training."""
    import random
    packets, labels = [], []

    for _ in range(n_samples):
        label = random.choices(
            ["normal", "port_scan", "bruteforce", "ddos"],
            weights=[0.55, 0.15, 0.15, 0.15]
        )[0]

        if label == "normal":
            p = {
                "protocol": random.choice(["TCP", "UDP"]),
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443, 53, 25, 110]),
                "length": random.randint(200, 1500),
                "ttl": 64,
                "flags": "PA",
            }
        elif label == "port_scan":
            p = {
                "protocol": "TCP",
                "src_port": random.randint(1024, 65535),
                "dst_port": random.randint(1, 1024),
                "length": 40,
                "ttl": 64,
                "flags": "S",
            }
        elif label == "bruteforce":
            p = {
                "protocol": "TCP",
                "src_port": random.randint(1024, 65535),
                "dst_port": 22,
                "length": random.randint(40, 200),
                "ttl": 64,
                "flags": "PA",
            }
        else:  # ddos
            p = {
                "protocol": random.choice(["TCP", "UDP"]),
                "src_port": random.randint(1024, 65535),
                "dst_port": 80,
                "length": random.randint(40, 100),
                "ttl": random.randint(30, 64),
                "flags": "S",
            }

        packets.append(p)
        labels.append(label)

    return packets, labels
