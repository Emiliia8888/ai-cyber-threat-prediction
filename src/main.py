import sys

from src.preprocessing.event_loader import load_events
from src.preprocessing.normalize import normalize_events, add_time_differences
from src.detection.rules import assess_threat_level
from src.prediction.features import extract_features, features_to_vector
from src.prediction.model import prepare_data, train_model, predict_threat


def predict_threat_from_events(events):
    normalize_events(events)
    add_time_differences(events)

    X, y = prepare_data()
    model = train_model(X, y)

    features = features_to_vector(extract_features(events))
    ml_prediction = predict_threat(model, features)

    threat_level = assess_threat_level(events)

    return ml_prediction, threat_level


def main():
    if len(sys.argv) > 1:
        events_path = sys.argv[1]
    else:
        events_path = "data/events.json"

    events = load_events(events_path)

    print("AI Cyber Threat Prediction System")
    print("Project started successfully!")
    print(f"Input: {events_path}")

    ml_prediction, threat_level = predict_threat_from_events(events)

    print(f"ML prediction: {ml_prediction}")
    print(f"Threat level: {threat_level}")


if __name__ == "__main__":
    main()

