from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src.prediction.dataset import load_dataset
from src.prediction.persistence import save_model


RANDOM_STATE = 42


def train_final_model():
    X, y = load_dataset()

    model = Pipeline(
        [
            ("scaler", StandardScaler()),
            (
                "model",
                LogisticRegression(
                    max_iter=5000,
                    random_state=RANDOM_STATE,
                ),
            ),
        ]
    )

    model.fit(X, y)

    model_path = save_model(model)

    print(f"Training samples: {len(X)}")
    print(f"Features: {len(X[0])}")
    print(f"Classes: {sorted(set(y))}")
    print(f"Model: Logistic Regression")
    print(f"Model saved to: {model_path}")

    return model


if __name__ == "__main__":
    train_final_model()
