from pathlib import Path

import pandas as pd


TARGET_BINARY = "label"
TARGET_MULTICLASS = "attack_cat"


def load_unsw_dataset(path: str | Path) -> pd.DataFrame:
    """Load an UNSW-NB15 parquet file."""
    return pd.read_parquet(path)


def remove_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """Remove exact duplicate rows."""
    return df.drop_duplicates().reset_index(drop=True)


def remove_train_test_overlap(
    train: pd.DataFrame,
    test: pd.DataFrame,
) -> pd.DataFrame:
    """Remove exact rows from test that are already present in train."""

    train_hashes = pd.util.hash_pandas_object(
        train,
        index=False,
    )

    test_hashes = pd.util.hash_pandas_object(
        test,
        index=False,
    )

    train_hash_set = set(train_hashes)

    mask = ~test_hashes.isin(train_hash_set)

    return test.loc[mask].reset_index(drop=True)

def prepare_unsw_train_test(
    train_path: str | Path,
    test_path: str | Path,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load and clean UNSW-NB15 train and test datasets."""

    train = load_unsw_dataset(train_path)
    test = load_unsw_dataset(test_path)

    train = remove_duplicates(train)
    test = remove_duplicates(test)

    test = remove_train_test_overlap(
        train=train,
        test=test,
    )

    return train, test
