import json
import random

from datetime import datetime, timedelta
from pathlib import Path

from src.prediction.features import extract_features
from src.preprocessing.normalize import add_time_differences, normalize_events


RANDOM_SEED = 42

SOURCES = [
    "server_01",
    "server_02",
    "server_03",
    "server_04",
]


def create_event(event_type, source, timestamp):
    return {
        "type": event_type,
        "source": source,
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
    }


def generate_event_sequence(label):
    start = datetime(2026, 9, 1, 12, 0, 0)
    source = random.choice(SOURCES)

    other_sources = random.sample(
        [item for item in SOURCES if item != source],
        k=random.randint(0, 2),
    )

    events = []

    if label == "normal":
        # Normal activity.
        # Includes an explicit benign port_scan -> successful_login
        # scenario so the model learns that this combination alone
        # is not a multi-stage attack.

        scenario = random.choice(
            [
                "regular",
                "port_scan_then_success",
            ]
        )

        if scenario == "port_scan_then_success":
            events.append(
                create_event(
                    "port_scan",
                    source,
                    start,
                )
            )

            start += timedelta(seconds=random.randint(90, 180))

            events.append(
                create_event(
                    "successful_login",
                    source,
                    start,
                )
            )

            additional_events = random.randint(1, 4)

            for _ in range(additional_events):
                start += timedelta(seconds=random.randint(90, 300))

                events.append(
                    create_event(
                        "successful_login",
                        random.choice([source, *other_sources]),
                        start,
                    )
                )

        else:
            event_count = random.randint(4, 8)

            for _ in range(event_count):
                event_type = random.choices(
                    [
                        "successful_login",
                        "failed_login",
                        "port_scan",
                    ],
                    weights=[0.85, 0.10, 0.05],
                )[0]

                start += timedelta(seconds=random.randint(90, 300))

                events.append(
                    create_event(
                        event_type,
                        random.choice([source, *other_sources]),
                        start,
                    )
                )

    elif label == "low":
        # Low-risk suspicious activity.
        # Failed logins are isolated by more than 60 seconds.
        # No rapid failed-login pattern and no attack chain.

        event_count = random.randint(3, 7)

        for _ in range(event_count):
            event_type = random.choices(
                [
                    "failed_login",
                    "successful_login",
                ],
                weights=[0.80, 0.20],
            )[0]

            start += timedelta(seconds=random.randint(90, 240))

            events.append(
                create_event(
                    event_type,
                    source,
                    start,
                )
            )

    elif label == "medium":
        # Medium-risk suspicious activity:
        # repeated port scans OR repeated failed logins.
        #
        # Successful logins are deliberately excluded so that
        # port_scan + successful_login remains a benign/normal
        # combination unless a real multi-stage attack chain exists.

        scenario = random.choice(
            [
                "port_scan",
                "failed_logins",
            ]
        )

        if scenario == "port_scan":
            event_count = random.randint(2, 5)

            for _ in range(event_count):
                start += timedelta(seconds=random.randint(20, 120))

                events.append(
                    create_event(
                        "port_scan",
                        random.choice([source, *other_sources]),
                        start,
                    )
                )

        elif scenario == "failed_logins":
            event_count = random.randint(3, 6)

            for _ in range(event_count):
                start += timedelta(seconds=random.randint(15, 45))

                events.append(
                    create_event(
                        "failed_login",
                        source,
                        start,
                    )
                )

    elif label == "high":
        # High-risk multi-stage attack:
        #
        # reconnaissance
        #       ↓
        # port scan
        #       ↓
        # failed login
        #       ↓
        # successful login
        #
        # All events use the same source and happen rapidly.

        events.append(
            create_event(
                "port_scan",
                source,
                start,
            )
        )

        start += timedelta(seconds=random.randint(5, 30))

        events.append(
            create_event(
                "failed_login",
                source,
                start,
            )
        )

        start += timedelta(seconds=random.randint(5, 30))

        events.append(
            create_event(
                "successful_login",
                source,
                start,
            )
        )

        # Add some additional activity around the attack chain.
        additional_events = random.randint(1, 4)

        for _ in range(additional_events):
            start += timedelta(seconds=random.randint(5, 45))

            event_type = random.choice(
                [
                    "failed_login",
                    "successful_login",
                    "port_scan",
                ]
            )

            events.append(
                create_event(
                    event_type,
                    source,
                    start,
                )
            )

    else:
        raise ValueError(f"Unknown label: {label}")

    events.sort(key=lambda event: event["timestamp"])

    return events

def generate_sample(label):
    events = generate_event_sequence(label)

    normalize_events(events)
    add_time_differences(events)

    features = extract_features(events)

    return {
        "features": [
            features["port_scan_count"],
            features["failed_login_count"],
            features["successful_login_count"],
            features["event_count"],
            features["unique_source_count"],
            features["time_span_seconds"],
            features["failed_login_rate"],
            features["successful_login_rate"],
            features["rapid_failed_login_count"],
            features["port_scan_followed_by_failed_login"],
            features["failed_login_followed_by_successful_login"],
        ],
        "label": label,
    }


def generate_dataset(samples_per_class=250):
    random.seed(RANDOM_SEED)

    labels = [
        "normal",
        "low",
        "medium",
        "high",
    ]

    dataset = []

    for label in labels:
        for _ in range(samples_per_class):
            dataset.append(
                generate_sample(label)
            )

    random.shuffle(dataset)

    return dataset


def save_dataset(dataset, path):
    output_path = Path(path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            dataset,
            file,
            indent=2,
        )


def main():
    dataset = generate_dataset(
        samples_per_class=250
    )

    save_dataset(
        dataset,
        "data/ml_dataset.json",
    )

    print(f"Generated {len(dataset)} samples")
    print("Saved to data/ml_dataset.json")


if __name__ == "__main__":
    main()
