from src.prediction.features import features_to_vector
from src.prediction.persistence import load_model


def predict_with_saved_model(features):
    model = load_model()
    vector = features_to_vector(features)

    prediction = model.predict([vector])[0]
    probabilities = model.predict_proba([vector])[0]

    class_index = list(model.classes_).index(prediction)
    confidence = probabilities[class_index]

    return prediction, confidence


if __name__ == "__main__":
    sample_features = {
        "port_scan_count": 2,
        "failed_login_count": 2,
        "successful_login_count": 1,
        "event_count": 5,
        "unique_source_count": 1,
        "time_span_seconds": 120.0,
        "failed_login_rate": 2 / 120,
        "successful_login_rate": 1 / 120,
        "rapid_failed_login_count": 1,
        "port_scan_followed_by_failed_login": 1,
        "failed_login_followed_by_successful_login": 1,
    }

    prediction, confidence = predict_with_saved_model(
        sample_features
    )

    print(f"Prediction: {prediction}")
    print(f"Confidence: {confidence:.4f}")
