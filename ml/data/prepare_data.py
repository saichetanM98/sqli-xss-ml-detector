"""Data preparation script to clean, merge, and tokenize datasets into a 3-class schema."""

import os
import json
import logging
from typing import Dict, List, Tuple
import pandas as pd
from sklearn.model_selection import train_test_split

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def build_vocab(texts: List[str]) -> Dict[str, int]:
    """
    Build character-level vocabulary with special tokens.
    <PAD>: 0 (for padding sequences up to max length)
    <UNK>: 1 (for unknown characters encountered at runtime)
    """
    vocab = {"<PAD>": 0, "<UNK>": 1}
    for text in texts:
        for ch in str(text):
            if ch not in vocab:
                vocab[ch] = len(vocab)
    return vocab


def load_raw_datasets(raw_data_dir: str) -> pd.DataFrame:
    """Load and harmonize disparate CSV formats into a unified DataFrame."""
    records = []

    # 1. Load sqli.csv (UTF-16 encoding)
    sqli_path = os.path.join(raw_data_dir, "sqli.csv")
    if os.path.exists(sqli_path):
        logger.info("Reading %s (UTF-16)...", sqli_path)
        try:
            df_sqli = pd.read_csv(sqli_path, encoding="utf-16", on_bad_lines="skip")
            for _, row in df_sqli.iterrows():
                text = str(row.get("Sentence", "")).strip()
                raw_label = row.get("Label", 0)
                if text and pd.notna(raw_label):
                    label = 1 if int(raw_label) == 1 else 0
                    records.append({"payload": text, "label": label})
        except Exception as e:
            logger.warning("Error reading %s: %s", sqli_path, e)

    # 2. Load sqliv2.csv (UTF-16 encoding)
    sqliv2_path = os.path.join(raw_data_dir, "sqliv2.csv")
    if os.path.exists(sqliv2_path):
        logger.info("Reading %s (UTF-16)...", sqliv2_path)
        try:
            df_sqliv2 = pd.read_csv(sqliv2_path, encoding="utf-16", on_bad_lines="skip")
            for _, row in df_sqliv2.iterrows():
                text = str(row.get("Sentence", "")).strip()
                raw_label = row.get("Label", 0)
                if text and pd.notna(raw_label):
                    label = 1 if int(raw_label) == 1 else 0
                    records.append({"payload": text, "label": label})
        except Exception as e:
            logger.warning("Error reading %s: %s", sqliv2_path, e)

    # 3. Load SQLiV3.csv (UTF-8 encoding with potential ragged commas)
    sqliv3_path = os.path.join(raw_data_dir, "SQLiV3.csv")
    if os.path.exists(sqliv3_path):
        logger.info("Reading %s (UTF-8)...", sqliv3_path)
        try:
            df_sqliv3 = pd.read_csv(sqliv3_path, encoding="utf-8", on_bad_lines="skip")
            for _, row in df_sqliv3.iterrows():
                text = str(row.get("Sentence", "")).strip()
                raw_label = row.get("Label", 0)
                if text and pd.notna(raw_label):
                    try:
                        label = 1 if int(float(raw_label)) == 1 else 0
                        records.append({"payload": text, "label": label})
                    except (ValueError, TypeError):
                        continue
        except Exception as e:
            logger.warning("Error reading %s: %s", sqliv3_path, e)

    # 4. Load XSS_dataset.csv (UTF-8-SIG encoding)
    xss_path = os.path.join(raw_data_dir, "XSS_dataset.csv")
    if os.path.exists(xss_path):
        logger.info("Reading %s (UTF-8-SIG)...", xss_path)
        try:
            df_xss = pd.read_csv(xss_path, encoding="utf-8-sig", on_bad_lines="skip")
            for _, row in df_xss.iterrows():
                text = str(row.get("Sentence", "")).strip()
                raw_label = row.get("Label", 0)
                if text and pd.notna(raw_label):
                    # In XSS dataset, label 1 is XSS (class 2), label 0 is benign (class 0)
                    label = 2 if int(raw_label) == 1 else 0
                    records.append({"payload": text, "label": label})
        except Exception as e:
            logger.warning("Error reading %s: %s", xss_path, e)

    df = pd.DataFrame(records)
    logger.info("Total raw records collected: %d", len(df))

    # Clean duplicates and empty entries
    df.dropna(subset=["payload", "label"], inplace=True)
    df["payload"] = df["payload"].astype(str).str.strip()
    df = df[df["payload"].str.len() > 0]
    # Filter out obvious corrupt string representations like "nan"
    df = df[df["payload"].str.lower() != "nan"]
    df.drop_duplicates(subset=["payload"], keep="first", inplace=True)
    df.reset_index(drop=True, inplace=True)

    logger.info("Records after deduplication & cleaning: %d", len(df))
    logger.info("Class distribution:\n%s", df["label"].value_counts())
    return df


def prepare_datasets(raw_data_dir: str = "datasets", output_dir: str = "ml/artifacts") -> None:
    """Execute complete dataset preparation, vocabulary build, and split export."""
    os.makedirs(output_dir, exist_ok=True)

    # 1. Ingest and harmonize
    df = load_raw_datasets(raw_data_dir)

    # 2. Stratified Split (80% Train, 10% Val, 10% Test)
    train_df, temp_df = train_test_split(df, test_size=0.20, random_state=42, stratify=df["label"])
    val_df, test_df = train_test_split(temp_df, test_size=0.50, random_state=42, stratify=temp_df["label"])

    logger.info("Train set: %d samples", len(train_df))
    logger.info("Val set: %d samples", len(val_df))
    logger.info("Test set: %d samples", len(test_df))

    # 3. Build character vocabulary from training data only (prevents data leakage)
    vocab = build_vocab(train_df["payload"].tolist())
    vocab_path = os.path.join(output_dir, "vocab.json")
    with open(vocab_path, "w", encoding="utf-8") as f:
        json.dump(vocab, f, indent=2, ensure_ascii=False)
    logger.info("Saved vocabulary with %d characters to %s", len(vocab), vocab_path)

    # 4. Export CSV splits
    train_df.to_csv(os.path.join(output_dir, "train.csv"), index=False, encoding="utf-8")
    val_df.to_csv(os.path.join(output_dir, "val.csv"), index=False, encoding="utf-8")
    test_df.to_csv(os.path.join(output_dir, "test.csv"), index=False, encoding="utf-8")
    logger.info("Exported train.csv, val.csv, and test.csv to %s", output_dir)


if __name__ == "__main__":
    prepare_datasets()
