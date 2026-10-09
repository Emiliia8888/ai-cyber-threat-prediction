from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
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
        "\n=== CIC-IDS2017 LOGISTIC REGRESSION + FEATURE ENGINEERING ===\n"
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
        "\nTraining Logistic Regression..."
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

    print(
        "\nConfusion matrix:"
    )

    print(
        confusion_matrix(
            y_test,
            predictions,
        )
    )


if __name__ == "__main__":
    main()
