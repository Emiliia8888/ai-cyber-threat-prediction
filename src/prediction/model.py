from sklearn.tree import DecisionTreeClassifier

from src.prediction.training_data import training_data


def prepare_data():

    X = []
    y = []

    for features, label in training_data:
        X.append(features)
        y.append(label)

    return X, y


def train_model(X, y):

    model = DecisionTreeClassifier(random_state=42)

    model.fit(X, y)

    return model


def build_model():

    X, y = prepare_data()

    return train_model(X, y)


def predict_threat(model, features):

    return model.predict([features])[0]

