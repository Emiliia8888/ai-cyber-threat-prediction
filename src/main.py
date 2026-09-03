import argparse

from src.preprocessing.event_loader import load_events
from src.preprocessing.normalize import normalize_events, add_time_differences
from src.detection.rules import assess_threat_level
from src.prediction.features import extract_features, features_to_vector
from src.prediction.model import build_model, predict_threat_with_confidence
from src.prediction.evaluate import evaluate_model


def predict_threat_from_events(events):
    normalize_events(events)
    add_time_differences(events)

    model = build_model()

    features = features_to_vector(extract_features(events))
    ml_prediction, confidence = predict_threat_with_confidence(model, features)

    threat_level = assess_threat_level(events)

    return ml_prediction, confidence, threat_level



def main():
    parser = argparse.ArgumentParser(
        description="AI Cyber Threat Prediction System"
    )

    parser.add_argument(
        "events_file",
        nargs="?",
        default="data/events.json",
        help="Path to JSON file containing security events",
    )

    parser.add_argument(
        "--evaluate",
        action="store_true",
        help="Evaluate the ML model using the evaluation dataset",
    )

    args = parser.parse_args()

    if args.evaluate:
        evaluate_model("data/evaluation.json")
        return

    events = load_events(args.events_file)

    print("AI Cyber Threat Prediction System")
    print("Project started successfully!")
    print(f"Input: {args.events_file}")

    ml_prediction, confidence, threat_level = predict_threat_from_events(events)

    print(f"ML prediction: {ml_prediction}")
    print(f"Confidence: {confidence:.2%}")
    print(f"Threat level: {threat_level}")


if __name__ == "__main__":
    main()
