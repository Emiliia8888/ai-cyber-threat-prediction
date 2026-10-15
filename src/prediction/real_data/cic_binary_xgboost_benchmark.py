from time import perf_counter

import numpy as np
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    recall_score,
    precision_score,
)

from src.prediction.real_data.cic_binary_benchmark import prepare_data


def main():
    (
        X_train,
        X_test,
        y_train,
        y_test,
        preprocessor,
    ) = prepare_data()

    print("\n=== CIC-IDS2017 BINARY XGBOOST BENCHMARK ===\n")
    print("Train:", X_train.shape)
    print("Test:", X_test.shape)

    print("\nFitting preprocessor on train data...")
    X_train_processed = preprocessor.fit_transform(X_train)
    X_test_processed = preprocessor.transform(X_test)

    scale_pos_weight = (
        (y_train == 0).sum() / (y_train == 1).sum()
    )
    print(f"Attack class weight: {scale_pos_weight:.4f}")

    model = XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        n_jobs=-1,
        tree_method="hist",
    )

    print("\nTraining XGBoost...")
    start_time = perf_counter()
    model.fit(X_train_processed, y_train)
    elapsed = perf_counter() - start_time

    print(f"Training time: {elapsed:.2f} seconds")

    train_probabilities = model.predict_proba(X_train_processed)[:, 1]
    probabilities = model.predict_proba(X_test_processed)[:, 1]

    print("\n=== TRAIN VS TEST DIAGNOSTICS ===")

    for name, labels, probs in [
        ("TRAIN", y_train, train_probabilities),
        ("TEST", y_test, probabilities),
    ]:
        predicted = (probs >= 0.5).astype(int)

        print(f"\n{name}")
        print(f"Attack recall: {recall_score(labels, predicted):.4f}")
        print(
            "Attack precision:",
            f"{precision_score(labels, predicted, zero_division=0):.4f}",
        )

    for label, name in [(0, "NORMAL"), (1, "ATTACK")]:
        class_probabilities = probabilities[
            y_test.to_numpy() == label
        ]

        print(f"\n{name} probabilities on TEST:")
        print(
            "Min / median / 90th / 99th percentile:",
            np.percentile(class_probabilities, [0, 50, 90, 99]).round(4),
        )

    print("\n=== THRESHOLD DIAGNOSTICS ===")

    for threshold in [0.5, 0.4, 0.3, 0.2, 0.1, 0.05]:
        predictions = (probabilities >= threshold).astype(int)

        print(
            f"Threshold={threshold:.2f} | "
            f"Predicted attacks={predictions.sum():,} | "
            f"Attack recall={recall_score(y_test, predictions):.4f} | "
            f"Attack precision={precision_score(y_test, predictions, zero_division=0):.4f} | "
            f"Macro F1={f1_score(y_test, predictions, average='macro', zero_division=0):.4f}"
        )

    predictions = (probabilities >= 0.5).astype(int)

    print(
        f"\nAccuracy at threshold 0.50: "
        f"{accuracy_score(y_test, predictions):.4f}"
    )

    print("\nClassification report at threshold 0.50:\n")
    print(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["normal", "attack"],
            digits=4,
            zero_division=0,
        )
    )


if __name__ == "__main__":
    main()