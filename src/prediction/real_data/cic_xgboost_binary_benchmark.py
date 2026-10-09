from xgboost import XGBClassifier

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
        "\n=== CIC-IDS2017 XGBOOST BINARY ===\n"
    )

    print(
        "Train:",
        X_train.shape,
    )

    print(
        "Test:",
        X_test.shape,
    )

    negative_count = (
        y_train == 0
    ).sum()

    positive_count = (
        y_train == 1
    ).sum()

    scale_pos_weight = (
        negative_count / positive_count
    )

    print(
        "\nClass distribution:"
    )

    print(
        "Normal:",
        int(negative_count),
    )

    print(
        "Attack:",
        int(positive_count),
    )

    print(
        "scale_pos_weight:",
        round(
            scale_pos_weight,
            4,
        ),
    )

    model = Pipeline(
        steps=[
            (
                "preprocessor",
                preprocessor,
            ),
            (
                "classifier",
                XGBClassifier(
                    n_estimators=300,
                    max_depth=8,
                    learning_rate=0.1,
                    subsample=0.8,
                    colsample_bytree=0.8,
                    objective="binary:logistic",
                    eval_metric="logloss",
                    scale_pos_weight=scale_pos_weight,
                    random_state=42,
                    n_jobs=-1,
                    tree_method="hist",
                ),
            ),
        ]
    )

    print(
        "\nTraining XGBoost..."
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
                __import__("numpy").percentile(
                    probabilities,
                    25,
                )
            ),
            "50%": float(
                __import__("numpy").percentile(
                    probabilities,
                    50,
                )
            ),
            "75%": float(
                __import__("numpy").percentile(
                    probabilities,
                    75,
                )
            ),
            "90%": float(
                __import__("numpy").percentile(
                    probabilities,
                    90,
                )
            ),
            "95%": float(
                __import__("numpy").percentile(
                    probabilities,
                    95,
                )
            ),
            "99%": float(
                __import__("numpy").percentile(
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
