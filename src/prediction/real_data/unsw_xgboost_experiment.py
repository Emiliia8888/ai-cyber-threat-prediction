from pathlib import Path

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from xgboost import XGBClassifier

from src.prediction.real_data.unsw_dataset import (
    prepare_unsw_train_test,
)
from src.prediction.real_data.unsw_feature_engineering import (
    add_unsw_features,
)
from src.prediction.real_data.unsw_preprocessing import (
    build_preprocessor,
    split_features_and_target,
)


TRAIN_PATH = Path(
    "/Users/emiliia/Desktop/UNSW-NB15/"
    "UNSW_NB15_training-set.parquet"
)

TEST_PATH = Path(
    "/Users/emiliia/Desktop/UNSW-NB15/"
    "UNSW_NB15_testing-set.parquet"
)


def main():
    print("Loading UNSW-NB15 dataset...")

    train, test = prepare_unsw_train_test(
        train_path=TRAIN_PATH,
        test_path=TEST_PATH,
    )

    print(f"Train shape: {train.shape}")
    print(f"Test shape: {test.shape}")

    print("\nAdding engineered features...")

    train = add_unsw_features(train)
    test = add_unsw_features(test)

    X_train, y_train = split_features_and_target(
        train,
        target="attack_cat",
    )

    X_test, y_test = split_features_and_target(
        test,
        target="attack_cat",
    )

    print(
        f"Original feature count: 34"
    )

    print(
        f"Engineered feature count: "
        f"{X_train.shape[1]}"
    )

    preprocessor = build_preprocessor(
        X_train
    )

    X_train_transformed = (
        preprocessor.fit_transform(X_train)
    )

    X_test_transformed = (
        preprocessor.transform(X_test)
    )

    print(
        "Transformed feature count:",
        X_train_transformed.shape[1],
    )

    labels = sorted(y_train.unique())

    label_to_id = {
        label: index
        for index, label in enumerate(labels)
    }

    y_train_encoded = y_train.map(
        label_to_id
    )

    y_test_encoded = y_test.map(
        label_to_id
    )

    print("\nClasses:")
    print(labels)

    print("\nTraining XGBoost...")

    model = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="multi:softmax",
        num_class=len(labels),
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
        tree_method="hist",
    )

    model.fit(
        X_train_transformed,
        y_train_encoded,
    )

    y_pred_encoded = model.predict(
        X_test_transformed
    )

    y_pred = y_pred_encoded.astype(int)

    accuracy = accuracy_score(
        y_test_encoded,
        y_pred,
    )

    macro_f1 = f1_score(
        y_test_encoded,
        y_pred,
        average="macro",
    )

    weighted_f1 = f1_score(
        y_test_encoded,
        y_pred,
        average="weighted",
    )

    print(
        "\n=== UNSW-NB15 "
        "Multiclass XGBoost + "
        "Feature Engineering ==="
    )

    print(
        f"Accuracy: {accuracy:.4f}"
    )

    print(
        f"Macro F1: {macro_f1:.4f}"
    )

    print(
        f"Weighted F1: {weighted_f1:.4f}"
    )

    print("\nClassification report:")

    print(
        classification_report(
            y_test_encoded,
            y_pred,
            labels=list(range(len(labels))),
            target_names=labels,
            zero_division=0,
        )
    )

    cm = confusion_matrix(
        y_test_encoded,
        y_pred,
        labels=list(range(len(labels))),
    )

    print("\nConfusion Matrix:")
    print("Labels:")
    print(labels)
    print()
    print(cm)


if __name__ == "__main__":
    main()
