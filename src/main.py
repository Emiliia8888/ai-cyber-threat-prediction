from src.preprocessing.events import events
from src.preprocessing.normalize import normalize_events, add_time_differences
from src.detection.rules import assess_threat_level
from src.prediction.features import extract_features, features_to_vector
from src.prediction.model import prepare_data, train_model, predict_threat
print("AI Cyber Threat Prediction System")
print("Project started successfully!")

normalize_events(events)
add_time_differences(events)

X, y = prepare_data()

model = train_model(X, y)

features = features_to_vector(extract_features(events))

prediction = predict_threat(model, features)

print(f"ML prediction: {prediction}")
threat_level = assess_threat_level(events)
print(f"Threat level: {threat_level}")
