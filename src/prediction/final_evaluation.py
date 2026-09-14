from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

from src.prediction.dataset import split_dataset


RANDOM_STATE = 42


def build_models():
    return {
        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            random_state=RANDOM_STATE,
        ),
        "Logistic Regression": Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "model",
                    LogisticRegression(
                        max_iter=2000,
                        random_state=RANDOM_STATE,
                    ),
                ),
            ]
        ),
        "SVM": Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "model",
                    SVC(
                        kernel="rbf",
                        random_state=RANDOM_STATE,
                    ),
                ),
            ]
        ),
    }


def evaluate_models():
    X_train, X_test, y_train, y_test = split_dataset()

    models = build_models()
    results = []

    for name, model in models.items():
        print("=" * 70)
        print(name)
        print("=" * 70)

        model.fit(X_train, y_train)
        predictions = model.predict(X_test)

        accuracy = accuracy_score(y_test, predictions)
        macro_f1 = f1_score(
            y_test,
            predictions,
            average="macro",
        )

        results.append(
            {
                "name": name,
                "accuracy": accuracy,
                "macro_f1": macro_f1,
            }
        )

        print(f"Accuracy: {accuracy:.4f}")
        print(f"Macro F1: {macro_f1:.4f}")

        print("\nClassification report:")
        print(
            classification_report(
                y_test,
                predictions,
                zero_division=0,
            )
        )

        print("Confusion matrix:")
        print(confusion_matrix(y_test, predictions))
        print()

    best_model = max(
        results,
        key=lambda result: (
            result["macro_f1"],
            result["accuracy"],
        ),
    )

    print("=" * 70)
    print("FINAL MODEL")
    print("=" * 70)
    print(f"Model: {best_model['name']}")
    print(f"Accuracy: {best_model['accuracy']:.4f}")
    print(f"Macro F1: {best_model['macro_f1']:.4f}")


if __name__ == "__main__":
    evaluate_models()
