from src.ingestion.ssh_log_event_source import SSHLogEventSource
from src.prediction.features import extract_features, features_to_vector
from src.prediction.persistence import load_model


def test_real_ssh_log_is_classified_as_high():
    source = SSHLogEventSource(year=2026)

    events = source.load("data/ssh/auth.log")

    features = extract_features(events)
    vector = features_to_vector(features)

    model = load_model()

    prediction = model.predict([vector])[0]

    assert len(vector) == 11
    assert features["failed_login_count"] == 17
    assert features["successful_login_count"] == 5
    assert features["rapid_failed_login_count"] == 14
    assert features["failed_login_followed_by_successful_login"] == 1
    assert prediction == "high"
