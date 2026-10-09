from pathlib import Path

import pandas as pd


DATA_DIR = Path(
    "/Users/emiliia/Desktop/CIC-IDS2017"
)

TARGET = "Label"


TRAIN_FILES = [
    "Benign-Monday-no-metadata.parquet",
    "Bruteforce-Tuesday-no-metadata.parquet",
    "DoS-Wednesday-no-metadata.parquet",
    "Infiltration-Thursday-no-metadata.parquet",
    "WebAttacks-Thursday-no-metadata.parquet",
]

TEST_FILES = [
    "Botnet-Friday-no-metadata.parquet",
    "DDoS-Friday-no-metadata.parquet",
    "Portscan-Friday-no-metadata.parquet",
]


def load_files(
    filenames: list[str],
) -> pd.DataFrame:
    frames = []

    for filename in filenames:
        path = DATA_DIR / filename

        print(
            f"Loading: {filename}"
        )

        df = pd.read_parquet(path)
        frames.append(df)

    return pd.concat(
        frames,
        ignore_index=True,
    )


def remove_train_overlap(
    train: pd.DataFrame,
    test: pd.DataFrame,
) -> pd.DataFrame:
    train_hashes = (
        pd.util.hash_pandas_object(
            train,
            index=False,
        )
        .drop_duplicates()
    )

    train_hash_set = set(
        train_hashes
    )

    test_hashes = pd.util.hash_pandas_object(
        test,
        index=False,
    )

    mask = ~test_hashes.isin(
        train_hash_set
    )

    return test.loc[
        mask
    ].reset_index(drop=True)


def convert_to_binary(
    df: pd.DataFrame,
) -> pd.DataFrame:
    result = df.copy()

    result[TARGET] = (
        result[TARGET]
        .ne("Benign")
        .astype("int8")
    )

    return result


def main():
    train = load_files(
        TRAIN_FILES
    )

    test = load_files(
        TEST_FILES
    )

    train = train.drop_duplicates()
    test = test.drop_duplicates()

    print(
        "\nUnique train rows:",
        len(train),
    )

    print(
        "Unique test rows before cleaning:",
        len(test),
    )

    test = remove_train_overlap(
        train=train,
        test=test,
    )

    print(
        "Unique test rows after cleaning:",
        len(test),
    )

    train_hashes = set(
        pd.util.hash_pandas_object(
            train,
            index=False,
        )
    )

    test_hashes = pd.util.hash_pandas_object(
        test,
        index=False,
    )

    remaining_overlap = test_hashes.isin(
        train_hashes
    ).sum()

    print(
        "\nRemaining exact overlap:",
        int(remaining_overlap),
    )

    train = convert_to_binary(train)
    test = convert_to_binary(test)

    print(
        "\n=== CLEAN SCENARIO SPLIT ===\n"
    )

    print(
        "Train shape:",
        train.shape,
    )

    print(
        "Test shape:",
        test.shape,
    )

    print(
        "\nTrain distribution:"
    )

    print(
        train[TARGET]
        .value_counts()
        .sort_index()
    )

    print(
        "\nTest distribution:"
    )

    print(
        test[TARGET]
        .value_counts()
        .sort_index()
    )


if __name__ == "__main__":
    main()
