from sklearn.ensemble import RandomForestClassifier

from src.prediction.dataset import load_dataset
from src.prediction.persistence import load_model, save_model


def test_model_save_and_load(tmp_path):
    X, y = load_dataset()

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
    )
    model.fit(X, y)

    original_prediction = model.predict([X[0]])[0]
    original_probabilities = model.predict_proba([X[0]])[0]

    model_path = tmp_path / "test_model.joblib"

    save_model(model, model_path)
    loaded_model = load_model(model_path)

    loaded_prediction = loaded_model.predict([X[0]])[0]
    loaded_probabilities = loaded_model.predict_proba([X[0]])[0]

    assert loaded_prediction == original_prediction

    assert loaded_probabilities.tolist() == original_probabilities.tolist()
