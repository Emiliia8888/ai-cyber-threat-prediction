import json
from pathlib import Path

from sklearn.model_selection import train_test_split


RANDOM_STATE = 42
TEST_SIZE = 0.2

DATASET_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "ml_dataset.json"
)


def load_dataset():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset file not found: {DATASET_PATH}"
        )

    with DATASET_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        dataset = json.load(file)

    X = [sample["features"] for sample in dataset]
    y = [sample["label"] for sample in dataset]

    return X, y


def split_dataset(
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
):
    X, y = load_dataset()

    return train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )
