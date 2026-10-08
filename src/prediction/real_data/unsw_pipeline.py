from pathlib import Path

import pandas as pd

from src.prediction.real_data.unsw_dataset import (
    prepare_unsw_train_test,
)
from src.prediction.real_data.unsw_preprocessing import (
    build_preprocessor,
    split_features_and_target,
)


def prepare_binary_data(
    train_path: str | Path,
    test_path: str | Path,
):
    """Prepare UNSW-NB15 data for binary classification."""

    train, test = prepare_unsw_train_test(
        train_path=train_path,
        test_path=test_path,
    )

    X_train, y_train = split_features_and_target(
        train,
        target="label",
    )

    X_test, y_test = split_features_and_target(
        test,
        target="label",
    )

    preprocessor = build_preprocessor(X_train)

    X_train_transformed = preprocessor.fit_transform(
        X_train
    )

    X_test_transformed = preprocessor.transform(
        X_test
    )

    return (
        X_train_transformed,
        X_test_transformed,
        y_train,
        y_test,
        preprocessor,
    )

def prepare_multiclass_data(
    train_path: str | Path,
    test_path: str | Path,
):
    """Prepare UNSW-NB15 data for multiclass classification."""

    train, test = prepare_unsw_train_test(
        train_path=train_path,
        test_path=test_path,
    )

    X_train, y_train = split_features_and_target(
        train,
        target="attack_cat",
    )

    X_test, y_test = split_features_and_target(
        test,
        target="attack_cat",
    )

    preprocessor = build_preprocessor(X_train)

    X_train_transformed = preprocessor.fit_transform(
        X_train
    )

    X_test_transformed = preprocessor.transform(
        X_test
    )

    return (
        X_train_transformed,
        X_test_transformed,
        y_train,
        y_test,
        preprocessor,
    )
