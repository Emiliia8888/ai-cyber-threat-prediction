import json
from pathlib import Path

import pandas as pd

from time import perf_counter

from xgboost import XGBClassifier

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from src.prediction.real_data.cic_clean_scenario_split import load_files
from src.prediction.real_data.cic_feature_engineering import add_cic_features
from src.prediction.real_data.cic_preprocessing import (
    build_preprocessor,
    clean_invalid_values,
)


FILES = [
    "Benign-Monday-no-metadata.parquet",
    "Bruteforce-Tuesday-no-metadata.parquet",
    "DoS-Wednesday-no-metadata.parquet",
    "Infiltration-Thursday-no-metadata.parquet",
    "WebAttacks-Thursday-no-metadata.parquet",
    "Botnet-Friday-no-metadata.parquet",
    "DDoS-Friday-no-metadata.parquet",
    "Portscan-Friday-no-metadata.parquet",
]


MIN_CLASS_COUNT = 100

ROOT_DIR = Path(__file__).resolve().parents[3]
REPORTS_DIR = ROOT_DIR / "reports"

def normalize_labels(df):
    result = df.copy()
    result["Label"] = (
        result["Label"]
        .astype(str)
        .str.replace(r"\s+", " ", regex=True)
        .str.strip()
    )
    return result


def main():
    print("Loading CIC-IDS2017...")

    df = load_files(FILES)

    print(f"Initial dataset size: {len(df)}")

    # Remove exact duplicates.
    df = df.drop_duplicates().copy()

    print(f"After duplicate removal: {len(df)}")

    # Normalize whitespace in labels.
    df = normalize_labels(df)

    # Remove classes with fewer than 100 samples.
    class_counts = df["Label"].value_counts()

    rare_classes = class_counts[
        class_counts < MIN_CLASS_COUNT
    ].index.tolist()

    print("\nRemoving rare classes:")

    for class_name in rare_classes:
        print(
            f"{class_name}: "
            f"{class_counts[class_name]} samples"
        )

    df = df[
        ~df["Label"].isin(rare_classes)
    ].copy()

    print(
        f"\nAfter rare-class removal: "
        f"{len(df)}"
    )

    print("\nClass distribution:")

    print(
        df["Label"].value_counts()
    )

    # Clean invalid numeric values.
    df = clean_invalid_values(df)

    # Feature engineering.
    print("\nApplying feature engineering...")

    df = add_cic_features(df)

    X = df.drop(columns=["Label"])
    y = df["Label"]

    print(
        f"\nFeature count: {X.shape[1]}"
    )

    # Stratified split.
    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.20,
            random_state=42,
            stratify=y,
        )
    )

    print(
        f"\nTrain size: {len(X_train)}"
    )

    print(
        f"Test size:  {len(X_test)}"
    )

    # Encode target classes.
    encoder = LabelEncoder()

    y_train_encoded = encoder.fit_transform(
        y_train
    )

    y_test_encoded = encoder.transform(
        y_test
    )

    print("\nClasses:")

    for index, class_name in enumerate(
        encoder.classes_
    ):
        print(
            f"{index}: {class_name}"
        )

    # Preprocessing.
    print("\nPreprocessing data...")

    preprocessor = build_preprocessor(
        X_train,
        scale_numeric=True,
    )

    X_train_processed = (
        preprocessor.fit_transform(X_train)
    )

    X_test_processed = (
        preprocessor.transform(X_test)
    )

    print(
        "Processed train shape: "
        f"{X_train_processed.shape}"
    )

    print(
        "Processed test shape: "
        f"{X_test_processed.shape}"
    )

    # Model.

    # Model.
    print("\nTraining XGBoost...")

    model = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="multi:softprob",
        num_class=len(encoder.classes_),
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
        tree_method="hist",
    )

    start_time = perf_counter()

    model.fit(
        X_train_processed,
        y_train_encoded,
        verbose=False,
    )

    training_time = perf_counter() - start_time

    print(f"Training time: {training_time:.2f} seconds")

    predictions = model.predict(X_test_processed)

    # Metrics.
    accuracy = accuracy_score(
        y_test_encoded,
        predictions,
    )

    macro_f1 = f1_score(
        y_test_encoded,
        predictions,
        average="macro",
        zero_division=0,
    )

    weighted_f1 = f1_score(
        y_test_encoded,
        predictions,
        average="weighted",
        zero_division=0,
    )


    # Save XGBoost evaluation reports.
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    metrics = {
        "model": "XGBoost",
        "test_rows": int(len(y_test_encoded)),
        "feature_count": int(X_test_processed.shape[1]),
        "training_time_seconds": round(training_time, 2),
        "accuracy": float(accuracy),
        "macro_f1": float(macro_f1),
        "weighted_f1": float(weighted_f1),
    }

    report = classification_report(
        y_test_encoded,
        predictions,
        labels=list(range(len(encoder.classes_))),
        target_names=encoder.classes_,
        output_dict=True,
        zero_division=0,
    )

    matrix = confusion_matrix(
        y_test_encoded,
        predictions,
        labels=list(range(len(encoder.classes_))),
    )

    pd.DataFrame(
        matrix,
        index=encoder.classes_,
        columns=encoder.classes_,
    ).to_csv(
        REPORTS_DIR / "cic_multiclass_xgboost_confusion_matrix.csv"
    )

    with (
        REPORTS_DIR / "cic_multiclass_xgboost_metrics.json"
    ).open("w", encoding="utf-8") as file:
        json.dump(metrics, file, indent=2)

    with (
        REPORTS_DIR / "cic_multiclass_xgboost_classification_report.json"
    ).open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)

    print(f"\nXGBoost reports saved in: {REPORTS_DIR}")

    print(
        "CIC-IDS2017 MULTICLASS XGBOOST BENCHMARK"
    )
    print("=" * 80)

    print(
        f"\nAccuracy:    {accuracy:.4f}"
    )

    print(
        f"Macro F1:    {macro_f1:.4f}"
    )

    print(
        f"Weighted F1: {weighted_f1:.4f}"
    )

    print(
        "\nClassification report:"
    )

    print(
        classification_report(
            y_test_encoded,
            predictions,
            target_names=encoder.classes_,
            zero_division=0,
        )
    )


if __name__ == "__main__":
    main()
