import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.pipeline import Pipeline

from src.prediction.real_data.cic_binary_benchmark import (
    prepare_data,
)


def main():
    (
        X_train,
        X_test,
        y_train,
        y_test,
        preprocessor,
    ) = prepare_data()

    print(
        "\n=== CIC-IDS2017 RANDOM FOREST ===\n"
    )

    print(
        "Train:",
        X_train.shape,
    )

    print(
        "Test:",
        X_test.shape,
    )

    model = Pipeline(
        steps=[
            (
                "preprocessor",
                preprocessor,
            ),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=200,
                    max_depth=None,
                    class_weight="balanced",
                    n_jobs=-1,
                    random_state=42,
                ),
            ),
        ]
    )

    print(
        "\nTraining Random Forest..."
    )

    model.fit(
        X_train,
        y_train,
    )

    print(
        "Training complete."
    )

    predictions = model.predict(
        X_test
    )

    probabilities = model.predict_proba(
        X_test
    )[:, 1]

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

    print(
        f"\nAccuracy: {accuracy:.4f}"
    )

    print(
        f"Macro F1: {macro_f1:.4f}"
    )

    print(
        f"Weighted F1: {weighted_f1:.4f}"
    )

    print(
        "\nClassification report:\n"
    )

    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "normal",
                "attack",
            ],
            digits=4,
        )
    )

    print(
        "\nConfusion matrix:"
    )

    print(
        confusion_matrix(
            y_test,
            predictions,
        )
    )

    print(
        "\nAttack probability percentiles:"
    )

    print(
        {
            "min": float(
                probabilities.min()
            ),
            "25%": float(
                np.percentile(
                    probabilities,
                    25,
                )
            ),
            "50%": float(
                np.percentile(
                    probabilities,
                    50,
                )
            ),
            "75%": float(
                np.percentile(
                    probabilities,
                    75,
                )
            ),
            "90%": float(
                np.percentile(
                    probabilities,
                    90,
                )
            ),
            "95%": float(
                np.percentile(
                    probabilities,
                    95,
                )
            ),
            "99%": float(
                np.percentile(
                    probabilities,
                    99,
                )
            ),
            "max": float(
                probabilities.max()
            ),
        }
    )


if __name__ == "__main__":
    main()
