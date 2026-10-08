from pathlib import Path

import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)

from src.prediction.real_data.unsw_pipeline import (
    prepare_multiclass_data,
)


TRAIN_PATH = Path(
    "~/Desktop/UNSW-NB15/UNSW_NB15_training-set.parquet"
).expanduser()

TEST_PATH = Path(
    "~/Desktop/UNSW-NB15/UNSW_NB15_testing-set.parquet"
).expanduser()


def main():
    (
        X_train,
        X_test,
        y_train,
        y_test,
        _,
    ) = prepare_multiclass_data(
        TRAIN_PATH,
        TEST_PATH,
    )

    # Remove Normal class.
    train_mask = np.asarray(y_train != "Normal")
    test_mask = np.asarray(y_test != "Normal")

    X_train = X_train[train_mask]
    y_train = y_train.loc[train_mask].reset_index(drop=True)

    X_test = X_test[test_mask]
    y_test = y_test.loc[test_mask].reset_index(drop=True)
    
    print("Training Random Forest on attack classes only...")

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
    )

    model.fit(
        X_train,
        y_train,
    )

    predictions = model.predict(X_test)

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

    print()
    print("=== UNSW-NB15 Attack-Only Random Forest ===")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Macro F1: {macro_f1:.4f}")
    print(f"Weighted F1: {weighted_f1:.4f}")

    print()
    print("Classification report:")
    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0,
        )
    )

    print("Confusion matrix:")
    print(
        confusion_matrix(
            y_test,
            predictions,
        )
    )


if __name__ == "__main__":
    main()
