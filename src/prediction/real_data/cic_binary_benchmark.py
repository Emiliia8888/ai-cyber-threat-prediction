from pathlib import Path

import pandas as pd

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
)
from sklearn.pipeline import Pipeline


from src.prediction.real_data.cic_clean_scenario_split import (
    load_files,
    remove_train_overlap,
    convert_to_binary,
    TRAIN_FILES,
    TEST_FILES,
)

from src.prediction.real_data.cic_preprocessing import (
    clean_invalid_values,
    split_features_and_target,
    build_preprocessor,
)


def prepare_data():
    train = load_files(TRAIN_FILES)
    test = load_files(TEST_FILES)

    train = train.drop_duplicates()
    test = test.drop_duplicates()

    test = remove_train_overlap(
        train=train,
        test=test,
    )

    train = convert_to_binary(train)
    test = convert_to_binary(test)

    train = clean_invalid_values(train)
    test = clean_invalid_values(test)

    X_train, y_train = split_features_and_target(train)
    X_test, y_test = split_features_and_target(test)

    preprocessor = build_preprocessor(
        X_train,
        scale_numeric=True,
    )

    return (
        X_train,
        X_test,
        y_train,
        y_test,
        preprocessor,
    )


def main():
    (
        X_train,
        X_test,
        y_train,
        y_test,
        preprocessor,
    ) = prepare_data()

    print(
        "\n=== CIC-IDS2017 BINARY BENCHMARK ===\n"
    )

    print(
        "Train:",
        X_train.shape,
    )

    print(
        "Test:",
        X_test.shape,
    )

    print(
        "\nTrain labels:"
    )

    print(
        y_train.value_counts()
        .sort_index()
    )

    print(
        "\nTest labels:"
    )

    print(
        y_test.value_counts()
        .sort_index()
    )

    model = Pipeline(
        steps=[
            (
                "preprocessor",
                preprocessor,
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=300,
                    class_weight="balanced",
                    n_jobs=-1,
                    random_state=42,
                ),
            ),
        ]
    )

    print(
        "\nTraining Logistic Regression..."
    )

    model.fit(
        X_train,
        y_train,
    )

    print(
        "Training complete."
    )

    predictions = model.predict(
        X_test
    )

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    macro_f1 = f1_score(
        y_test,
        predictions,
        average="macro",
    )

    weighted_f1 = f1_score(
        y_test,
        predictions,
        average="weighted",
    )

    print(
        f"\nAccuracy: {accuracy:.4f}"
    )

    print(
        f"Macro F1: {macro_f1:.4f}"
    )

    print(
        f"Weighted F1: {weighted_f1:.4f}"
    )

    print(
        "\nClassification report:\n"
    )

    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "normal",
                "attack",
            ],
            digits=4,
        )
    )


if __name__ == "__main__":
    main()
