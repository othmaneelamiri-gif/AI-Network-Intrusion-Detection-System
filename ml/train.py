"""
Train the IDS ML model on synthetic data.
Run once before starting the IDS, or after collecting real labelled traffic.

Usage:
    python -m ml.train [--samples N]
"""

import argparse
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from ml.model import IDSModel, generate_training_data

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Train IDS ML model")
    parser.add_argument("--samples", type=int, default=10000, help="Number of synthetic samples")
    args = parser.parse_args()

    logger.info(f"Generating {args.samples} synthetic samples …")
    packets, labels = generate_training_data(args.samples)

    dist = {}
    for l in labels:
        dist[l] = dist.get(l, 0) + 1
    logger.info(f"Label distribution: {dist}")

    model = IDSModel()
    metrics = model.train(packets, labels)

    logger.info(f"Accuracy : {metrics['accuracy']:.4f}")
    logger.info("Per-class metrics:")
    for cls, m in metrics["report"].items():
        if isinstance(m, dict):
            logger.info(f"  {cls:12s}  precision={m['precision']:.3f}  recall={m['recall']:.3f}  f1={m['f1-score']:.3f}")

    logger.info("Model saved to data/ids_model.pkl")


if __name__ == "__main__":
    main()
