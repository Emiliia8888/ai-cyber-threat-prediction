from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from src.prediction.dataset import split_dataset


RANDOM_STATE = 42


def compare_models():
    X_train, X_test, y_train, y_test = split_dataset()

    models = {
        "Decision Tree": DecisionTreeClassifier(
            random_state=RANDOM_STATE,
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            random_state=RANDOM_STATE,
        ),
        "Logistic Regression": Pipeline(
            [
                ("scaler", StandardScaler()),
                (
                    "classifier",
                    LogisticRegression(
                        max_iter=2000,
                        random_state=RANDOM_STATE,
                    ),
                ),
            ]
        ),
    }

    results = {}

    for name, model in models.items():
        model.fit(X_train, y_train)
        predictions = model.predict(X_test)

        accuracy = accuracy_score(y_test, predictions)
        results[name] = accuracy

        print()
        print("=" * 60)
        print(name)
        print("=" * 60)
        print(f"Accuracy: {accuracy:.4f}")
        print()
        print(
            classification_report(
                y_test,
                predictions,
                zero_division=0,
            )
        )

    print()
    print("=" * 60)
    print("MODEL COMPARISON")
    print("=" * 60)

    for name, accuracy in sorted(
        results.items(),
        key=lambda item: item[1],
        reverse=True,
    ):
        print(f"{name}: {accuracy:.4f}")


if __name__ == "__main__":
    compare_models()
