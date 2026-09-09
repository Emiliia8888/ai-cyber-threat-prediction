import argparse

from src.preprocessing.event_loader import load_events
from src.preprocessing.normalize import normalize_events, add_time_differences

from src.detection.rules import assess_threat_level
from src.detection.explanation import explain_risk
from src.detection.severity import calculate_event_severity
from src.detection.assessment import compare_assessments
from src.detection.attack_type import detect_attack_type
from src.application.alert_ports import AlertEnginePort
from src.alerts.legacy_alert_engine import LegacyAlertEngine

from src.prediction.features import extract_features, features_to_vector
from src.prediction.model import (
    build_model,
    predict_threat_with_confidence,
    get_feature_importance,
)

from src.prediction.evaluate import evaluate_model
from src.pipeline.threat_pipeline import ThreatPipeline


def predict_threat_from_events(events, model=None):
    pipeline = ThreatPipeline()

    # Preserve the existing function contract.
    # The pipeline operates on the same event dictionaries
    # and reproduces the existing prediction/risk logic.
    #
    # The optional model argument is kept for backward compatibility.
    if model is not None:
        normalize_events(events)
        add_time_differences(events)

        features = features_to_vector(
            extract_features(events)
        )

        ml_prediction, confidence = predict_threat_with_confidence(
            model,
            features,
        )

        risk = pipeline.risk_engine.assess(
            events,
            ml_prediction,
        )
    else:
        result = pipeline.run_from_events(events)

        ml_prediction = result["prediction"]
        confidence = result["confidence"]
        risk = result

    return (
        ml_prediction,
        confidence,
        risk["threat_level"],
        risk["agreement"],
        risk["attack_type"],
    )

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
        help="Evaluate the ML model using evaluation dataset",
    )

    args = parser.parse_args()

    if args.evaluate:
        evaluate_model("data/evaluation.json")
        return

    events = load_events(args.events_file)

    print("AI Cyber Threat Prediction System")
    print("Project started successfully!")
    print(f"Input: {args.events_file}")

    model = build_model()

    (
        ml_prediction,
        confidence,
        threat_level,
        agreement,
        attack_type,
    ) = predict_threat_from_events(
        events,
        model,
    )

    print(f"ML prediction: {ml_prediction}")
    print(f"Confidence: {confidence:.2%}")
    print(f"Threat level: {threat_level}")
    print(f"Attack type: {attack_type}")

    alert_engine: AlertEnginePort = LegacyAlertEngine()
    alert = alert_engine.generate(
        attack_type,
        threat_level,
        confidence,
    )

    print(f"Alert: {alert}")
    print(
        f"Assessment agreement: {'YES' if agreement else 'NO'}"
    )

    print("Risk explanation:")
    explanations = explain_risk(events)
    for explanation in explanations:
        print(f"  - {explanation}")

    print("Risk severity:")
    severity = calculate_event_severity(events)
    for item in severity:
        print(
            f"  - {item['level']}: {item['message']}"
        )

    feature_importance = get_feature_importance(model)

    print("Feature importance:")
    for feature, importance in feature_importance.items():
        print(
            f"  {feature}: {importance:.2%}"
        )


if __name__ == "__main__":
    main()
