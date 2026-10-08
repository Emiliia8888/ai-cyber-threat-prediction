from pathlib import Path

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)

from src.prediction.real_data.unsw_dataset import (
    prepare_unsw_train_test,
)
from src.prediction.real_data.unsw_feature_engineering import (
    add_unsw_features,
)
from src.prediction.real_data.unsw_preprocessing import (
    build_preprocessor,
    split_features_and_target,
)


BASE_DIR = Path(__file__).resolve().parents[3]

TRAIN_PATH = Path(
    "/Users/emiliia/Desktop/UNSW-NB15/UNSW_NB15_training-set.parquet"
)

TEST_PATH = Path(
    "/Users/emiliia/Desktop/UNSW-NB15/UNSW_NB15_testing-set.parquet"
)

def main():
    print("Loading UNSW-NB15 dataset...")

    train, test = prepare_unsw_train_test(
        train_path=TRAIN_PATH,
        test_path=TEST_PATH,
    )

    print(f"Train shape: {train.shape}")
    print(f"Test shape: {test.shape}")

    print("\nAdding engineered features...")

    train = add_unsw_features(train)
    test = add_unsw_features(test)

    X_train, y_train = split_features_and_target(
        train,
        target="attack_cat",
    )

    X_test, y_test = split_features_and_target(
        test,
        target="attack_cat",
    )

    print(f"Original feature count: 34")
    print(f"Engineered feature count: {X_train.shape[1]}")

    preprocessor = build_preprocessor(X_train)

    X_train_transformed = preprocessor.fit_transform(
        X_train
    )

    X_test_transformed = preprocessor.transform(
        X_test
    )

    print(
        "Transformed feature count:",
        X_train_transformed.shape[1],
    )

    print("\nTraining Random Forest...")

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight={
    "Normal": 0.5,
    "Exploits": 1.0,
    "Fuzzers": 1.5,
    "Reconnaissance": 1.5,
    "DoS": 2.0,
    "Generic": 1.5,
    "Analysis": 3.0,
    "Backdoor": 3.0,
    "Shellcode": 3.0,
    "Worms": 5.0,
},
    )

    model.fit(
        X_train_transformed,
        y_train,
    )

    y_pred = model.predict(
        X_test_transformed
    )

    accuracy = accuracy_score(
        y_test,
        y_pred,
    )

    macro_f1 = f1_score(
        y_test,
        y_pred,
        average="macro",
    )

    weighted_f1 = f1_score(
        y_test,
        y_pred,
        average="weighted",
    )

    print(
        "\n=== UNSW-NB15 Multiclass RF + "
        "Feature Engineering + Balanced ==="
    )

    print(
        f"Accuracy: {accuracy:.4f}"
    )

    print(
        f"Macro F1: {macro_f1:.4f}"
    )

    print(
        f"Weighted F1: {weighted_f1:.4f}"
    )

    print("\nClassification report:")

    print(
        classification_report(
            y_test,
            y_pred,
            zero_division=0,
        )
    )

    labels = sorted(
        y_test.unique()
    )

    cm = confusion_matrix(
        y_test,
        y_pred,
        labels=labels,
    )

    print("\nConfusion Matrix:")
    print("Labels:")
    print(labels)
    print()
    print(cm)


if __name__ == "__main__":
    main()
