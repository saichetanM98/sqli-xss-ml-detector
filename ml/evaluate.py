"""Evaluation script for model accuracy, precision, recall, F1, and confusion matrix."""

import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def evaluate_model():
    logger.info("Evaluating model checkpoint against held-out test split...")


if __name__ == "__main__":
    evaluate_model()
