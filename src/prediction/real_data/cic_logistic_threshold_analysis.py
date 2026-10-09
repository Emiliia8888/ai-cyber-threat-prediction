import numpy as np

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline

from src.prediction.real_data.cic_clean_scenario_split import (
    TRAIN_FILES,
    TEST_FILES,
    convert_to_binary,
    load_files,
    remove_train_overlap,
)

from src.prediction.real_data.cic_feature_engineering import (
    add_cic_features,
)

from src.prediction.real_data.cic_preprocessing import (
    build_preprocessor,
    clean_invalid_values,
    split_features_and_target,
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

    train = add_cic_features(train)
    test = add_cic_features(test)

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
        "\n=== CIC-IDS2017 LOGISTIC REGRESSION "
        "+ FEATURE ENGINEERING + THRESHOLD ===\n"
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
                    max_iter=1000,
                    class_weight="balanced",
                    random_state=42,
                ),
            ),
        ]
    )

    print(
        "Training Logistic Regression..."
    )

    model.fit(
        X_train,
        y_train,
    )

    print(
        "Training complete."
    )

    probabilities = model.predict_proba(
        X_test
    )[:, 1]

    print(
        "\nThreshold analysis:"
    )

    print(
        "\n"
        "Threshold | Accuracy | Precision | Recall | F1"
    )

    print(
        "-" * 55
    )

    for threshold in np.arange(
        0.10,
        0.91,
        0.05,
    ):
        predictions = (
            probabilities >= threshold
        ).astype(int)

        accuracy = accuracy_score(
            y_test,
            predictions,
        )

        precision = precision_score(
            y_test,
            predictions,
            zero_division=0,
        )

        recall = recall_score(
            y_test,
            predictions,
            zero_division=0,
        )

        f1 = f1_score(
            y_test,
            predictions,
            zero_division=0,
        )

        print(
            f"{threshold:9.2f} | "
            f"{accuracy:8.4f} | "
            f"{precision:9.4f} | "
            f"{recall:6.4f} | "
            f"{f1:6.4f}"
        )


if __name__ == "__main__":
    main()
