import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split

from src.prediction.real_data.cic_clean_scenario_split import load_files
from src.prediction.real_data.cic_feature_engineering import add_cic_features
from src.prediction.real_data.cic_model_persistence import load_cic_model
from src.prediction.real_data.cic_multiclass_random_forest import (
    FILES,
    MIN_CLASS_COUNT,
    normalize_labels,
)
from src.prediction.real_data.cic_preprocessing import clean_invalid_values


ROOT_DIR = Path(__file__).resolve().parents[3]
REPORTS_DIR = ROOT_DIR / "reports"


def main():
    print("Loading CIC-IDS2017 dataset...")

    df = load_files(FILES).drop_duplicates().copy()
    df = normalize_labels(df)

    counts = df["Label"].value_counts()
    df = df[
        df["Label"].isin(counts[counts >= MIN_CLASS_COUNT].index)
    ].copy()

    df = clean_invalid_values(df)
    df = add_cic_features(df)

    X = df.drop(columns=["Label"])
    y = df["Label"]

    _, X_test, _, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print("Loading saved model...")
    artifact = load_cic_model()

    X_test_processed = artifact["preprocessor"].transform(X_test)
    y_test_encoded = artifact["label_encoder"].transform(y_test)
    predictions = artifact["model"].predict(X_test_processed)

    class_names = artifact["label_encoder"].classes_

    metrics = {
        "test_rows": int(len(y_test)),
        "processed_feature_count": int(X_test_processed.shape[1]),
        "accuracy": float(accuracy_score(y_test_encoded, predictions)),
        "macro_f1": float(
            f1_score(
                y_test_encoded,
                predictions,
                average="macro",
                zero_division=0,
            )
        ),
        "weighted_f1": float(
            f1_score(
                y_test_encoded,
                predictions,
                average="weighted",
                zero_division=0,
            )
        ),
    }

    report = classification_report(
        y_test_encoded,
        predictions,
        labels=list(range(len(class_names))),
        target_names=class_names,
        output_dict=True,
        zero_division=0,
    )

    matrix = confusion_matrix(
        y_test_encoded,
        predictions,
        labels=list(range(len(class_names))),
    )

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    pd.DataFrame(
        matrix,
        index=class_names,
        columns=class_names,
    ).to_csv(REPORTS_DIR / "cic_multiclass_confusion_matrix.csv")

    with (REPORTS_DIR / "cic_multiclass_metrics.json").open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(metrics, file, indent=2)

    with (REPORTS_DIR / "cic_multiclass_classification_report.json").open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(report, file, indent=2, ensure_ascii=False)

    print("\n=== CIC MULTICLASS AUDIT ===")
    print(json.dumps(metrics, indent=2))
    print("\nClassification report:")
    print(
        classification_report(
            y_test_encoded,
            predictions,
            labels=list(range(len(class_names))),
            target_names=class_names,
            zero_division=0,
        )
    )
    print(f"\nReports saved in: {REPORTS_DIR}")


if __name__ == "__main__":
    main()
