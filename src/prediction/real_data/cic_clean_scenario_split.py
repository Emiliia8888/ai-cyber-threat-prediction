
import os
from pathlib import Path

import pandas as pd

DATA_DIR = Path(
    os.environ.get(
        "CIC_IDS2017_DATA_DIR",
        str(Path.home() / "Desktop" / "CIC-IDS2017"),
    )
)

TARGET = "Label"


TRAIN_FILES = [
    "Benign-Monday-no-metadata.parquet",
    "Bruteforce-Tuesday-no-metadata.parquet",
    "DoS-Wednesday-no-metadata.parquet",
    "Infiltration-Thursday-no-metadata.parquet",
    "WebAttacks-Thursday-no-metadata.parquet",
]

TEST_FILES = [
    "Botnet-Friday-no-metadata.parquet",
    "DDoS-Friday-no-metadata.parquet",
    "Portscan-Friday-no-metadata.parquet",
]


def load_files(filenames: list[str]) -> pd.DataFrame:
    """Load and concatenate CIC-IDS2017 parquet files."""
    frames = []

    for filename in filenames:
        path = DATA_DIR / filename

        if not path.exists():
            raise FileNotFoundError(
                f"CIC-IDS2017 file not found: {path}"
            )

        print(f"Loading: {filename}")
        frames.append(pd.read_parquet(path))

    if not frames:
        raise ValueError("No input files were provided.")

    return pd.concat(frames, ignore_index=True)


def normalize_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize whitespace and replacement characters in labels."""
    if TARGET not in df.columns:
        raise KeyError(f"Target column '{TARGET}' is missing.")

    result = df.copy()

    result[TARGET] = (
        result[TARGET]
        .astype(str)
        .str.replace("\uFFFD", " ", regex=False)
        .str.replace(r"\s+", " ", regex=True)
        .str.strip()
    )

    return result


def remove_train_overlap(
    train: pd.DataFrame,
    test: pd.DataFrame,
) -> pd.DataFrame:
    """
    Remove test rows whose feature values occur in training data.

    The target label is excluded from comparison, so identical feature
    rows cannot remain in both sets merely because their labels differ.
    """
    if TARGET not in train.columns or TARGET not in test.columns:
        raise KeyError(f"Both datasets must contain '{TARGET}'.")

    feature_columns = [
        column for column in train.columns
        if column != TARGET
    ]

    if set(feature_columns) != {
        column for column in test.columns
        if column != TARGET
    }:
        raise ValueError(
            "Train and test feature columns do not match."
        )

    # Preserve the training column order.
    test_features = test[feature_columns]

    train_hashes = set(
        pd.util.hash_pandas_object(
            train[feature_columns],
            index=False,
        )
    )

    test_hashes = pd.util.hash_pandas_object(
        test_features,
        index=False,
    )

    overlap_mask = test_hashes.isin(train_hashes)
    removed_count = int(overlap_mask.sum())

    print(
        "\nTest rows removed due to feature overlap:",
        removed_count,
    )

    return test.loc[~overlap_mask].reset_index(drop=True)


def convert_to_binary(df: pd.DataFrame) -> pd.DataFrame:
    """Map Benign to 0 and all attack labels to 1."""
    result = normalize_labels(df)

    result[TARGET] = (
        result[TARGET]
        .ne("Benign")
        .astype("int8")
    )

    return result


def main() -> None:
    train = load_files(TRAIN_FILES)
    test = load_files(TEST_FILES)

    # Normalize labels before deduplication and overlap checking.
    train = normalize_labels(train).drop_duplicates().copy()
    test = normalize_labels(test).drop_duplicates().copy()

    print("\n=== BEFORE OVERLAP REMOVAL ===")
    print("Unique train rows:", len(train))
    print("Unique test rows before cleaning:", len(test))

    test = remove_train_overlap(
        train=train,
        test=test,
    )

    # Verify no exact feature overlap remains.
    feature_columns = [
        column for column in train.columns
        if column != TARGET
    ]

    train_hashes = set(
        pd.util.hash_pandas_object(
            train[feature_columns],
            index=False,
        )
    )

    test_hashes = pd.util.hash_pandas_object(
        test[feature_columns],
        index=False,
    )

    remaining_overlap = int(
        test_hashes.isin(train_hashes).sum()
    )

    print("\nRemaining feature overlap:", remaining_overlap)

    train = convert_to_binary(train)
    test = convert_to_binary(test)

    print("\n=== CLEAN SCENARIO SPLIT ===")
    print("Train shape:", train.shape)
    print("Test shape:", test.shape)

    print("\nTrain distribution (0 = Benign, 1 = Attack):")
    print(train[TARGET].value_counts().sort_index())

    print("\nTest distribution (0 = Benign, 1 = Attack):")
    print(test[TARGET].value_counts().sort_index())

    if remaining_overlap != 0:
        raise RuntimeError(
            "Feature overlap remains between train and test."
        )

    if train.empty or test.empty:
        raise RuntimeError(
            "Train or test dataset is empty after cleaning."
        )


if __name__ == "__main__":
    main()
