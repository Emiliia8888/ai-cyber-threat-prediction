from pathlib import Path
from sklearn.svm import LinearSVC

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)

from src.prediction.real_data.unsw_pipeline import (
    prepare_binary_data,
)


TRAIN_PATH = Path(
    "~/Desktop/UNSW-NB15/UNSW_NB15_training-set.parquet"
).expanduser()

TEST_PATH = Path(
    "~/Desktop/UNSW-NB15/UNSW_NB15_testing-set.parquet"
).expanduser()


def evaluate_model(model, name, X_train, X_test, y_train, y_test):
    print()
    print(f"=== {name} ===")

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

    print(f"Accuracy: {accuracy:.4f}")
    print(f"Macro F1: {macro_f1:.4f}")

    print()
    print("Classification report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=["normal", "attack"],
        )
    )

    print("Confusion matrix:")
    print(confusion_matrix(y_test, predictions))

    return model


def main():
    X_train, X_test, y_train, y_test, _ = prepare_binary_data(
        TRAIN_PATH,
        TEST_PATH,
    )

    logistic_regression = LogisticRegression(
        max_iter=1000,
        random_state=42,
    )

    evaluate_model(
        logistic_regression,
        "Logistic Regression",
        X_train,
        X_test,
        y_train,
        y_test,
    )

    random_forest = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
    )

    linear_svm = LinearSVC(
        random_state=42,
        max_iter=2000,
    )

    evaluate_model(
        linear_svm,
        "Linear SVM",
        X_train,
        X_test,
        y_train,
        y_test,
    )

    evaluate_model(
        random_forest,
        "Random Forest",
        X_train,
        X_test,
        y_train,
        y_test,
    )


if __name__ == "__main__":
    main()
