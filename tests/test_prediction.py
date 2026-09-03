from src.preprocessing.events import events
from src.prediction.features import extract_features, features_to_vector
from src.prediction.model import prepare_data, train_model, predict_threat


def test_predict_high_threat():

    X, y = prepare_data()

    model = train_model(X, y)

    features = features_to_vector(extract_features(events))

    prediction = predict_threat(model, features)

    assert prediction == "high"

def test_predict_medium_threat():

    X, y = prepare_data()

    model = train_model(X, y)

    prediction = predict_threat(model, [1, 1, 0])

    assert prediction == "medium"


def test_predict_low_threat():

    X, y = prepare_data()

    model = train_model(X, y)

    prediction = predict_threat(model, [0, 1, 0])

    assert prediction == "low"


def test_predict_normal_threat():

    X, y = prepare_data()

    model = train_model(X, y)

    prediction = predict_threat(model, [0, 0, 0])

    assert prediction == "normal"

