from time import perf_counter

import pandas as pd
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)

from src.prediction.real_data.cic_clean_scenario_split import (
    load_files,
    remove_train_overlap,
    convert_to_binary,
)
from src.prediction.real_data.cic_preprocessing import (
    clean_invalid_values,
    split_features_and_target,
    build_preprocessor,
)


TRAIN_FILES = [
    "Benign-Monday-no-metadata.parquet",
    "Bruteforce-Tuesday-no-metadata.parquet",
    "DoS-Wednesday-no-metadata.parquet",
]

VALIDATION_FILES = [
    "Infiltration-Thursday-no-metadata.parquet",
    "WebAttacks-Thursday-no-metadata.parquet",
]

TEST_FILES = [
    "Botnet-Friday-no-metadata.parquet",
    "DDoS-Friday-no-metadata.parquet",
    "Portscan-Friday-no-metadata.parquet",
]

THRESHOLDS = [0.5, 0.3, 0.2, 0.1, 0.05, 0.02, 0.01]

CANDIDATES = [
    {
        "name": "depth3_regularized",
        "max_depth": 3,
        "min_child_weight": 10,
        "reg_lambda": 10.0,
        "reg_alpha": 0.1,
        "gamma": 0.1,
    },
    {
        "name": "depth4_regularized",
        "max_depth": 4,
        "min_child_weight": 10,
        "reg_lambda": 10.0,
        "reg_alpha": 0.1,
        "gamma": 0.1,
    },
    {
        "name": "depth3_strong_regularization",
        "max_depth": 3,
        "min_child_weight": 20,
        "reg_lambda": 20.0,
        "reg_alpha": 1.0,
        "gamma": 0.2,
    },
    {
        "name": "depth4_moderate_regularization",
        "max_depth": 4,
        "min_child_weight": 5,
        "reg_lambda": 5.0,
        "reg_alpha": 0.1,
        "gamma": 0.0,
    },
]


def load_scenarios():
    print("\nLoading training scenarios...")
    train_raw = load_files(TRAIN_FILES).drop_duplicates()

    print("\nLoading validation scenarios...")
    validation_raw = load_files(VALIDATION_FILES).drop_duplicates()

    print("\nLoading final test scenarios...")
    test_raw = load_files(TEST_FILES).drop_duplicates()

    validation_raw = remove_train_overlap(
        train=train_raw,
        test=validation_raw,
    )

    train_and_validation_raw = pd.concat(
        [train_raw, validation_raw],
        ignore_index=True,
    )

    test_raw = remove_train_overlap(
        train=train_and_validation_raw,
        test=test_raw,
    )

    train_df = clean_invalid_values(convert_to_binary(train_raw))
    validation_df = clean_invalid_values(
        convert_to_binary(validation_raw)
    )
    test_df = clean_invalid_values(convert_to_binary(test_raw))

    return train_df, validation_df, test_df


def prepare_features(train_df, other_df):
    X_train, y_train = split_features_and_target(train_df)
    X_other, y_other = split_features_and_target(other_df)

    preprocessor = build_preprocessor(
        X_train,
        scale_numeric=True,
    )

    X_train_processed = preprocessor.fit_transform(X_train)
    X_other_processed = preprocessor.transform(X_other)

    return (
        X_train_processed,
        X_other_processed,
        y_train,
        y_other,
    )


def make_model(params, scale_pos_weight):
    return XGBClassifier(
        n_estimators=200,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="binary:logistic",
        eval_metric="logloss",
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        n_jobs=-1,
        tree_method="hist",
        **params,
    )


def find_best_threshold(y_true, probabilities):
    best = None

    for threshold in THRESHOLDS:
        predictions = (probabilities >= threshold).astype(int)

        result = {
            "threshold": threshold,
            "macro_f1": f1_score(
                y_true,
                predictions,
                average="macro",
                zero_division=0,
            ),
            "attack_recall": recall_score(
                y_true,
                predictions,
                zero_division=0,
            ),
            "attack_precision": precision_score(
                y_true,
                predictions,
                zero_division=0,
            ),
        }

        if best is None or result["macro_f1"] > best["macro_f1"]:
            best = result

    return best


def main():
    train_df, validation_df, test_df = load_scenarios()

    X_train, X_validation, y_train, y_validation = (
        prepare_features(train_df, validation_df)
    )

    print("\n=== SCENARIO SPLIT ===")
    print("Train rows:", len(y_train))
    print("Validation rows:", len(y_validation))
    print("Final test rows:", len(test_df))
    print("Train classes:", y_train.value_counts().to_dict())
    print("Validation classes:", y_validation.value_counts().to_dict())

    scale_pos_weight = (
        (y_train == 0).sum() / (y_train == 1).sum()
    )

    best_candidate = None
    best_validation_score = -1.0

    print("\n=== REGULARIZATION EXPERIMENTS ===")

    for params in CANDIDATES:
        name = params["name"]
        model_params = {
            key: value
            for key, value in params.items()
            if key != "name"
        }

        print(f"\nTraining candidate: {name}")
        start_time = perf_counter()

        model = make_model(model_params, scale_pos_weight)
        model.fit(X_train, y_train)

        elapsed = perf_counter() - start_time
        probabilities = model.predict_proba(X_validation)[:, 1]
        result = find_best_threshold(y_validation, probabilities)

        print(f"Training time: {elapsed:.2f} seconds")
        print(f"Best validation threshold: {result['threshold']:.2f}")
        print(f"Validation Macro F1: {result['macro_f1']:.4f}")
        print(f"Validation attack recall: {result['attack_recall']:.4f}")
        print(f"Validation attack precision: {result['attack_precision']:.4f}")

        if result["macro_f1"] > best_validation_score:
            best_validation_score = result["macro_f1"]
            best_candidate = {
                "name": name,
                "params": model_params,
                "threshold": result["threshold"],
            }

        del model

    print("\n=== SELECTED CONFIGURATION ===")
    print("Candidate:", best_candidate["name"])
    print("Parameters:", best_candidate["params"])
    print("Threshold:", best_candidate["threshold"])
    print(f"Validation Macro F1: {best_validation_score:.4f}")

    full_train_df = pd.concat(
        [train_df, validation_df],
        ignore_index=True,
    )

    X_full, X_test, y_full, y_test = prepare_features(
        full_train_df,
        test_df,
    )

    final_scale_pos_weight = (
        (y_full == 0).sum() / (y_full == 1).sum()
    )

    final_model = make_model(
        best_candidate["params"],
        final_scale_pos_weight,
    )

    print("\n=== FINAL TRAINING: MONDAY–THURSDAY ===")
    start_time = perf_counter()
    final_model.fit(X_full, y_full)
    print(f"Training time: {perf_counter() - start_time:.2f} seconds")

    test_probabilities = final_model.predict_proba(X_test)[:, 1]
    threshold = best_candidate["threshold"]
    predictions = (test_probabilities >= threshold).astype(int)

    print("\n=== FINAL FRIDAY TEST ===")
    print(f"Threshold: {threshold:.2f}")
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print(
        "Macro F1:",
        f"{f1_score(y_test, predictions, average='macro', zero_division=0):.4f}",
    )
    print(
        "Attack recall:",
        f"{recall_score(y_test, predictions, zero_division=0):.4f}",
    )
    print(
        "Attack precision:",
        f"{precision_score(y_test, predictions, zero_division=0):.4f}",
    )

    print("\nClassification report:\n")
    print(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["normal", "attack"],
            digits=4,
            zero_division=0,
        )
    )


if __name__ == "__main__":
    main()