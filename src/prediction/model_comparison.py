from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

from src.prediction.dataset import split_dataset


RANDOM_STATE = 42


def build_models():
    return {
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


def compare_models():
    X_train, X_test, y_train, y_test = split_dataset()

    models = build_models()

    results = []

    for name, model in models.items():
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

        results.append(
            (
                name,
                accuracy,
                macro_f1,
                weighted_f1,
            )
        )

    print(
        f"{'Model':<22}"
        f"{'Accuracy':>12}"
        f"{'Macro F1':>12}"
        f"{'Weighted F1':>14}"
    )

    print("-" * 60)

    for name, accuracy, macro_f1, weighted_f1 in results:
        print(
            f"{name:<22}"
            f"{accuracy:>12.4f}"
            f"{macro_f1:>12.4f}"
            f"{weighted_f1:>14.4f}"
        )

    return results


if __name__ == "__main__":
    compare_models()
