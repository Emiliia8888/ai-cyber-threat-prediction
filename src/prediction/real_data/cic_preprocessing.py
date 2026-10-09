from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


DATA_DIR = Path(
    "/Users/emiliia/Desktop/CIC-IDS2017"
)

TARGET = "Label"


EXCLUDED_CLASSES = {
    "Infiltration",
    "Web Attack  Sql Injection",
    "Heartbleed",
}


NON_NEGATIVE_FEATURES = [
    "Fwd Header Length",
    "Fwd Seg Size Min",
    "Bwd Header Length",
    "Flow Duration",
    "Flow Packets/s",
    "Flow Bytes/s",
    "Fwd IAT Min",
]


def load_cic_files(
    data_dir: str | Path = DATA_DIR,
) -> pd.DataFrame:
    data_dir = Path(data_dir)

    files = sorted(
        data_dir.glob("*.parquet")
    )

    frames = []

    for path in files:
        df = pd.read_parquet(path)
        frames.append(df)

    return pd.concat(
        frames,
        ignore_index=True,
    )


def prepare_multiclass_dataset(
    df: pd.DataFrame,
) -> pd.DataFrame:
    result = df[
        ~df[TARGET].isin(EXCLUDED_CLASSES)
    ].copy()

    return result.reset_index(drop=True)


def prepare_binary_dataset(
    df: pd.DataFrame,
) -> pd.DataFrame:
    result = df.copy()

    result[TARGET] = (
        result[TARGET]
        .ne("Benign")
        .astype("int8")
    )

    return result.reset_index(drop=True)


def clean_invalid_values(
    df: pd.DataFrame,
) -> pd.DataFrame:
    result = df.copy()

    numeric_columns = result.select_dtypes(
        include=np.number
    ).columns

    result[numeric_columns] = (
        result[numeric_columns]
        .replace(
            [np.inf, -np.inf],
            np.nan,
        )
    )

    for feature in NON_NEGATIVE_FEATURES:
        if feature in result.columns:
            result.loc[
                result[feature] < 0,
                feature,
            ] = np.nan

    return result


def split_features_and_target(
    df: pd.DataFrame,
):
    X = df.drop(
        columns=[TARGET]
    )

    y = df[TARGET]

    return X, y


def build_preprocessor(
    X: pd.DataFrame,
    scale_numeric: bool = False,
) -> ColumnTransformer:

    categorical_features = [
        column
        for column in X.columns
        if X[column].dtype == "object"
    ]

    numeric_features = [
        column
        for column in X.columns
        if column not in categorical_features
    ]

    numeric_steps = [
        (
            "imputer",
            SimpleImputer(
                strategy="median"
            ),
        )
    ]

    if scale_numeric:
        numeric_steps.append(
            (
                "scaler",
                StandardScaler(),
            )
        )

    numeric_pipeline = Pipeline(
        steps=numeric_steps
    )

    transformers = [
        (
            "numeric",
            numeric_pipeline,
            numeric_features,
        )
    ]

    if categorical_features:
        transformers.append(
            (
                "categorical",
                Pipeline(
                    steps=[
                        (
                            "imputer",
                            SimpleImputer(
                                strategy="most_frequent"
                            ),
                        ),
                        (
                            "encoder",
                            OneHotEncoder(
                                handle_unknown="ignore",
                                sparse_output=True,
                            ),
                        ),
                    ]
                ),
                categorical_features,
            )
        )

    return ColumnTransformer(
        transformers=transformers
    )
