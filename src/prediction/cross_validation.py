from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

from src.prediction.dataset import load_dataset

RANDOM_STATE = 42
N_SPLITS = 5


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


def evaluate_cross_validation():
    X, y = load_dataset()

    cv = StratifiedKFold(
        n_splits=N_SPLITS,
        shuffle=True,
        random_state=RANDOM_STATE,
    )

    models = build_models()

    print(
        f"{'Model':<22}"
        f"{'Mean Accuracy':>16}"
        f"{'Std':>10}"
    )
    print("-" * 50)

    results = []

    for name, model in models.items():
        scores = cross_val_score(
            model,
            X,
            y,
            cv=cv,
            scoring="accuracy",
        )

        mean_score = scores.mean()
        std_score = scores.std()

        results.append(
            (
                name,
                mean_score,
                std_score,
            )
        )

        print(
            f"{name:<22}"
            f"{mean_score:>16.4f}"
            f"{std_score:>10.4f}"
        )

    return results


if __name__ == "__main__":
    evaluate_cross_validation()
