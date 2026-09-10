import argparse

from src.application.alert_ports import AlertEnginePort
from src.application.analysis_presenter import AnalysisPresenter
from src.application.composition import create_alert_engine
from src.application.model_evaluation import ModelEvaluation
from src.application.threat_analysis import ThreatAnalysis
from src.prediction.features import extract_features, features_to_vector
from src.prediction.model import (
    predict_threat_with_confidence,
)
from src.preprocessing.normalize import (
    add_time_differences,
    normalize_events,
)


def predict_threat_from_events(events, model=None):
    """
    Preserve the legacy public function contract.

    Existing callers may provide a trained model explicitly.
    The application use case is used when no model is provided.
    """

    if model is None:
        result = ThreatAnalysis().analyze_events(events)

        return (
            result.prediction,
            result.confidence,
            result.threat_level,
            result.agreement,
            result.attack_type,
        )

    normalize_events(events)
    add_time_differences(events)

    features = features_to_vector(
        extract_features(events)
    )

    ml_prediction, confidence = predict_threat_with_confidence(
        model,
        features,
    )

    analysis = ThreatAnalysis()

    risk = analysis.pipeline.risk_engine.assess(
        events,
        ml_prediction,
    )

    return (
        ml_prediction,
        confidence,
        risk.threat_level,
        risk.agreement,
        risk.attack_type,
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
        evaluator = ModelEvaluation()
        evaluator.evaluate("data/evaluation.json")
        return

    print("AI Cyber Threat Prediction System")
    print("Project started successfully!")
    print(f"Input: {args.events_file}")

    analysis = ThreatAnalysis()
    result = analysis.analyze_file(args.events_file)

    presenter = AnalysisPresenter()
    presenter.present(result)

    alert_engine: AlertEnginePort = create_alert_engine()

    alert = alert_engine.generate(
        result.attack_type,
        result.threat_level,
        result.confidence,
    )

    print(f"Alert: {alert}")


if __name__ == "__main__":
    main()
