from pathlib import Path

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler


CATEGORICAL_FEATURES = [
    "proto",
    "service",
    "state",
]

TARGET_BINARY = "label"
TARGET_MULTICLASS = "attack_cat"


def load_unsw_dataset(path: str | Path) -> pd.DataFrame:
    """Load UNSW-NB15 parquet dataset."""
    return pd.read_parquet(path)


def remove_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """Remove exact duplicate rows."""
    return df.drop_duplicates().reset_index(drop=True)


def split_features_and_target(
    df: pd.DataFrame,
    target: str = TARGET_BINARY,
) -> tuple[pd.DataFrame, pd.Series]:
    """Separate input features from target."""
    X = df.drop(columns=[TARGET_BINARY, TARGET_MULTICLASS])
    y = df[target]

    return X, y


def build_preprocessor(
    X: pd.DataFrame,
) -> ColumnTransformer:
    """Build preprocessing pipeline for UNSW-NB15."""

    numeric_features = [
        column
        for column in X.columns
        if column not in CATEGORICAL_FEATURES
    ]

    return ColumnTransformer(
        transformers=[
            (
                "numeric",
                StandardScaler(),
                numeric_features,
            ),
            (
                "categorical",
                OneHotEncoder(
                    handle_unknown="ignore",
                    sparse_output=True,
                ),
                CATEGORICAL_FEATURES,
            ),
        ]
    )


def prepare_training_data(
    path: str | Path,
    target: str = TARGET_BINARY,
) -> tuple[pd.DataFrame, pd.Series, ColumnTransformer]:
    """Load, clean and prepare UNSW-NB15 training data."""

    df = load_unsw_dataset(path)
    df = remove_duplicates(df)

    X, y = split_features_and_target(
        df,
        target=target,
    )

    preprocessor = build_preprocessor(X)

    return X, y, preprocessor
