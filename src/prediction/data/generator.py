import json
import random
from pathlib import Path


RANDOM_SEED = 42


def generate_sample(label):
    if label == "normal":
        port_scan_count = random.randint(0, 5)
        failed_login_count = random.randint(0, 0)
        successful_login_count = random.randint(0, 3)
        sequence = 0

    elif label == "low":
        port_scan_count = random.randint(0, 2)
        failed_login_count = random.randint(1, 6)
        successful_login_count = random.randint(0, 2)
        sequence = 0

    elif label == "medium":
        port_scan_count = random.randint(1, 6)
        failed_login_count = random.randint(1, 6)
        successful_login_count = 0
        sequence = 1

    elif label == "high":
        port_scan_count = random.randint(1, 6)
        failed_login_count = random.randint(1, 6)
        successful_login_count = random.randint(1, 4)
        sequence = 1

    else:
        raise ValueError(f"Unknown label: {label}")

    return {
        "features": [
            port_scan_count,
            failed_login_count,
            successful_login_count,
            sequence,
        ],
        "label": label,
    }


def generate_dataset(samples_per_class=250):
    random.seed(RANDOM_SEED)

    labels = ["normal", "low", "medium", "high"]
    dataset = []

    for label in labels:
        for _ in range(samples_per_class):
            dataset.append(generate_sample(label))

    random.shuffle(dataset)

    return dataset


def save_dataset(dataset, path):
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(dataset, file, indent=2)


def main():
    dataset = generate_dataset(samples_per_class=250)

    save_dataset(
        dataset,
        "data/ml_dataset.json",
    )

    print(f"Generated {len(dataset)} samples")
    print("Saved to data/ml_dataset.json")


if __name__ == "__main__":
    main()
