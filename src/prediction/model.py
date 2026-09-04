from sklearn.tree import DecisionTreeClassifier

from src.prediction.training_data import training_data


FEATURE_NAMES = [
    "port_scan_count",
    "failed_login_count",
    "successful_login_count",
]


def prepare_data():

    X = []
    y = []

    for features, label in training_data:
        X.append(features)
        y.append(label)

    return X, y


def create_model():

    return DecisionTreeClassifier(random_state=42)


def train_model(X, y):

    model = create_model()

    model.fit(X, y)

    return model


def build_model():

    X, y = prepare_data()

    return train_model(X, y)


def predict_threat(model, features):

    return model.predict([features])[0]


def predict_threat_with_confidence(model, features):

    prediction = model.predict([features])[0]
    probabilities = model.predict_proba([features])[0]

    class_index = list(model.classes_).index(prediction)
    confidence = probabilities[class_index]

    return prediction, confidence


def get_feature_importance(model):

    return dict(zip(FEATURE_NAMES, model.feature_importances_))

