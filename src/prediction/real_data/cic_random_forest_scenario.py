from pathlib import Path

import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


DATA_DIR = Path("/Users/emiliia/Desktop/CIC-IDS2017")

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

TARGET = "Label"


def load_files(files):
    frames = []

    for filename in files:
        path = DATA_DIR / filename
        print(f"Loading: {filename}")
        frames.append(pd.read_parquet(path))

    return pd.concat(frames, ignore_index=True)


def convert_to_binary(df):
    result = df.copy()

    result[TARGET] = (
        result[TARGET]
        .astype(str)
        .str.replace(r"\s+", " ", regex=True)
        .str.strip()
    )

    result[TARGET] = (
        result[TARGET]
        .ne("Benign")
        .astype("int8")
    )

    return result


def clean_features(df):
    result = df.copy()

    numeric_columns = result.select_dtypes(
        include="number"
    ).columns

    result[numeric_columns] = result[numeric_columns].replace(
        [float("inf"), float("-inf")],
        pd.NA,
    )

    return result


def main():
    print("Loading CIC-IDS2017 scenario split...")

    print("\nTRAIN:")
    train = load_files(TRAIN_FILES)

    print("\nTEST:")
    test = load_files(TEST_FILES)

    print(f"\nRaw train size: {len(train)}")
    print(f"Raw test size: {len(test)}")

    train = train.drop_duplicates().reset_index(drop=True)
    test = test.drop_duplicates().reset_index(drop=True)

    print(f"Unique train size: {len(train)}")
    print(f"Unique test size: {len(test)}")

    train = convert_to_binary(train)
    test = convert_to_binary(test)

    print("\nTrain class distribution:")
    print(train[TARGET].value_counts())

    print("\nTest class distribution:")
    print(test[TARGET].value_counts())

    X_train = train.drop(columns=[TARGET])
    y_train = train[TARGET]

    X_test = test.drop(columns=[TARGET])
    y_test = test[TARGET]

    X_train = clean_features(X_train)
    X_test = clean_features(X_test)

    numeric_columns = X_train.select_dtypes(
        include="number"
    ).columns.tolist()

    categorical_columns = X_train.select_dtypes(
        exclude="number"
    ).columns.tolist()

    # CIC-IDS2017 has Protocol as numeric,
    # so practically all model features are numeric.
    print(f"\nNumeric features: {len(numeric_columns)}")
    print(f"Categorical features: {len(categorical_columns)}")

    imputer = SimpleImputer(strategy="median")

    X_train_processed = imputer.fit_transform(X_train)
    X_test_processed = imputer.transform(X_test)

    print(
        f"Processed train shape: "
        f"{X_train_processed.shape}"
    )

    print(
        f"Processed test shape: "
        f"{X_test_processed.shape}"
    )

    print("\nTraining Random Forest...")

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )

    model.fit(
        X_train_processed,
        y_train,
    )

    predictions = model.predict(
        X_test_processed
    )

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    macro_f1 = f1_score(
        y_test,
        predictions,
        average="macro",
    )

    weighted_f1 = f1_score(
        y_test,
        predictions,
        average="weighted",
    )

    print("\n" + "=" * 80)
    print("CIC-IDS2017 RANDOM FOREST SCENARIO BENCHMARK")
    print("=" * 80)

    print(f"\nAccuracy:    {accuracy:.4f}")
    print(f"Macro F1:    {macro_f1:.4f}")
    print(f"Weighted F1: {weighted_f1:.4f}")

    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=["Benign", "Attack"],
            zero_division=0,
        )
    )

    print("Confusion matrix:")
    print(confusion_matrix(y_test, predictions))


if __name__ == "__main__":
    main()
