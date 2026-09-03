import json

from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from src.prediction.model import prepare_data, train_model


def load_evaluation_data(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def evaluate_model(path):
    evaluation_data = load_evaluation_data(path)

    X_test = [item["features"] for item in evaluation_data]
    y_test = [item["label"] for item in evaluation_data]

    X_train, y_train = prepare_data()
    model = train_model(X_train, y_train)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)

    print(f"Accuracy: {accuracy:.2f}")
    print("\nClassification report:")
    print(classification_report(y_test, predictions, zero_division=0))

    print("Confusion matrix:")
    print(confusion_matrix(y_test, predictions))


if __name__ == "__main__":
    evaluate_model("data/evaluation.json")

