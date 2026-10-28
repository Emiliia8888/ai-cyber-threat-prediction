import pandas as pd
import pytest

from src.prediction.real_data.cic_clean_scenario_split import (
    TARGET,
    convert_to_binary,
    normalize_labels,
    remove_train_overlap,
)


def test_remove_train_overlap_ignores_label_column():
    train = pd.DataFrame(
        {
            "FeatureA": [1.0, 2.0],
            "FeatureB": [10, 20],
            TARGET: ["Benign", "DoS"],
        }
    )
    test = pd.DataFrame(
        {
            "FeatureA": [1.0, 3.0],
            "FeatureB": [10, 30],
            TARGET: ["Attack", "Benign"],
        }
    )

    result = remove_train_overlap(train, test)

    assert len(result) == 1
    assert result.iloc[0]["FeatureA"] == 3.0


def test_remove_train_overlap_rejects_missing_target():
    train = pd.DataFrame({"FeatureA": [1.0]})
    test = pd.DataFrame({"FeatureA": [2.0]})

    with pytest.raises(KeyError):
        remove_train_overlap(train, test)


def test_remove_train_overlap_rejects_mismatched_features():
    train = pd.DataFrame(
        {"FeatureA": [1.0], TARGET: ["Benign"]}
    )
    test = pd.DataFrame(
        {"FeatureB": [2.0], TARGET: ["Attack"]}
    )

    with pytest.raises(ValueError, match="feature columns"):
        remove_train_overlap(train, test)


def test_normalize_labels_cleans_whitespace_and_replacement_char():
    frame = pd.DataFrame(
        {TARGET: ["  Web Attack\uFFFD   XSS  ", " Benign "]}
    )

    result = normalize_labels(frame)

    assert result[TARGET].tolist() == ["Web Attack XSS", "Benign"]
    assert frame[TARGET].iloc[0] == "  Web Attack\uFFFD   XSS  "


def test_convert_to_binary_maps_benign_and_attacks():
    frame = pd.DataFrame(
        {TARGET: ["Benign", " DoS Hulk ", "PortScan"]}
    )

    result = convert_to_binary(frame)

    assert result[TARGET].tolist() == [0, 1, 1]
