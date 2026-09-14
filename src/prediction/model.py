from typing import Any


FEATURE_NAMES = [
    "port_scan_count",
    "failed_login_count",
    "successful_login_count",
    "event_count",
    "unique_source_count",
    "time_span_seconds",
    "failed_login_rate",
    "successful_login_rate",
    "rapid_failed_login_count",
    "port_scan_followed_by_failed_login",
    "failed_login_followed_by_successful_login",
]


def predict_threat(model: Any, features: list[float]) -> str:
    return model.predict([features])[0]


def predict_threat_with_confidence(
    model: Any,
    features: list[float],
) -> tuple[str, float]:
    prediction = model.predict([features])[0]
    probabilities = model.predict_proba([features])[0]

    class_index = list(model.classes_).index(prediction)
    confidence = probabilities[class_index]

    return prediction, confidence


def get_feature_importance(model: Any) -> dict[str, float]:
    if hasattr(model, "feature_importances_"):
        importance = model.feature_importances_
    elif hasattr(model, "named_steps"):
        final_model = model.named_steps.get("model")

        if hasattr(final_model, "coef_"):
            importance = abs(final_model.coef_).mean(axis=0)
        else:
            raise ValueError(
                "Model does not expose feature importance."
            )
    else:
        raise ValueError(
            "Model does not expose feature importance."
        )

    return dict(zip(FEATURE_NAMES, importance))
