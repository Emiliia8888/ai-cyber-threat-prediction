from pathlib import Path

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
        preprocessor,
    ) = prepare_multiclass_data(
        TRAIN_PATH,
        TEST_PATH,
    )

    print("Training Random Forest...")

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )

    model.fit(X_train, y_train)

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
    print("=== UNSW-NB15 Multiclass Random Forest ===")
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

    print()
    print("Top 15 feature importances:")

    feature_names = preprocessor.get_feature_names_out()
    importances = model.feature_importances_

    feature_importance = sorted(
        zip(
            feature_names,
            importances,
        ),
        key=lambda item: item[1],
        reverse=True,
    )

    for feature, importance in feature_importance[:15]:
        print(
            f"{feature}: {importance:.4f}"
        )


if __name__ == "__main__":
    main()
