from collections import Counter

from src.prediction.dataset import load_dataset, split_dataset


def test_load_dataset_returns_expected_shape():
    X, y = load_dataset()

    assert len(X) == 1000
    assert len(y) == 1000
    assert all(len(features) == 11 for features in X)


def test_dataset_is_balanced():
    _, y = load_dataset()

    distribution = Counter(y)

    assert distribution == {
        "high": 250,
        "medium": 250,
        "normal": 250,
        "low": 250,
    }


def test_split_dataset_preserves_stratification():
    X_train, X_test, y_train, y_test = split_dataset()

    assert len(X_train) == 800
    assert len(X_test) == 200

    assert Counter(y_train) == {
        "high": 200,
        "medium": 200,
        "normal": 200,
        "low": 200,
    }

    assert Counter(y_test) == {
        "high": 50,
        "medium": 50,
        "normal": 50,
        "low": 50,
    }


def test_split_dataset_is_reproducible():
    first_split = split_dataset()
    second_split = split_dataset()

    assert first_split == second_split
