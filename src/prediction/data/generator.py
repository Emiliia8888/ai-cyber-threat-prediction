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

    available_sources = [source, *other_sources]
    events = []

    if label == "normal":
        # Benign activity can still contain occasional suspicious-looking
        # events. The important difference is the lack of a coherent attack
        # sequence and generally slower activity.

        scenario = random.choice(
            [
                "regular",
                "failed_logins",
                "port_scan",
                "port_scan_then_success",
            ]
        )

        if scenario == "regular":
            event_count = random.randint(4, 8)

            for _ in range(event_count):
                event_type = random.choices(
                    [
                        "successful_login",
                        "failed_login",
                        "port_scan",
                    ],
                    weights=[0.75, 0.18, 0.07],
                )[0]

                start += timedelta(seconds=random.randint(60, 300))

                events.append(
                    create_event(
                        event_type,
                        random.choice(available_sources),
                        start,
                    )
                )

        elif scenario == "failed_logins":
            event_count = random.randint(2, 4)

            for _ in range(event_count):
                start += timedelta(seconds=random.randint(45, 180))

                events.append(
                    create_event(
                        "failed_login",
                        random.choice(available_sources),
                        start,
                    )
                )

        elif scenario == "port_scan":
            event_count = random.randint(1, 3)

            for _ in range(event_count):
                start += timedelta(seconds=random.randint(60, 240))

                events.append(
                    create_event(
                        "port_scan",
                        random.choice(available_sources),
                        start,
                    )
                )

        elif scenario == "port_scan_then_success":
            events.append(
                create_event(
                    "port_scan",
                    source,
                    start,
                )
            )

            start += timedelta(seconds=random.randint(60, 240))

            events.append(
                create_event(
                    "successful_login",
                    random.choice(available_sources),
                    start,
                )
            )

            additional_events = random.randint(1, 3)

            for _ in range(additional_events):
                start += timedelta(seconds=random.randint(60, 300))

                events.append(
                    create_event(
                        random.choice(
                            [
                                "successful_login",
                                "failed_login",
                            ]
                        ),
                        random.choice(available_sources),
                        start,
                    )
                )

    elif label == "low":
        # Low-risk suspicious activity.
        # Failed logins can sometimes happen relatively quickly,
        # and successful logins are possible, but there is no coherent
        # multi-stage attack chain.

        scenario = random.choice(
            [
                "isolated_failures",
                "repeated_failures",
                "mixed_login_activity",
            ]
        )

        if scenario == "isolated_failures":
            event_count = random.randint(3, 6)

            for _ in range(event_count):
                start += timedelta(seconds=random.randint(60, 240))

                events.append(
                    create_event(
                        random.choice(
                            [
                                "failed_login",
                                "successful_login",
                            ]
                        ),
                        source,
                        start,
                    )
                )

        elif scenario == "repeated_failures":
            event_count = random.randint(3, 6)

            for _ in range(event_count):
                start += timedelta(seconds=random.randint(20, 90))

                events.append(
                    create_event(
                        "failed_login",
                        source,
                        start,
                    )
                )

        elif scenario == "mixed_login_activity":
            event_count = random.randint(4, 7)

            for _ in range(event_count):
                start += timedelta(seconds=random.randint(30, 150))

                events.append(
                    create_event(
                        random.choices(
                            [
                                "failed_login",
                                "successful_login",
                            ],
                            weights=[0.65, 0.35],
                        )[0],
                        random.choice(available_sources),
                        start,
                    )
                )

    elif label == "medium":
        # Medium-risk suspicious activity.
        # This class intentionally overlaps with both low and high:
        # repeated scans, repeated failures, and occasional successful
        # logins can occur, but there is no complete high-risk chain.

        scenario = random.choice(
            [
                "port_scan",
                "failed_logins",
                "scan_then_failed_login",
                "failed_then_success",
            ]
        )

        if scenario == "port_scan":
            event_count = random.randint(2, 5)

            for _ in range(event_count):
                start += timedelta(seconds=random.randint(15, 120))

                events.append(
                    create_event(
                        "port_scan",
                        random.choice(available_sources),
                        start,
                    )
                )

        elif scenario == "failed_logins":
            event_count = random.randint(3, 6)

            for _ in range(event_count):
                start += timedelta(seconds=random.randint(10, 60))

                events.append(
                    create_event(
                        "failed_login",
                        source,
                        start,
                    )
                )

        elif scenario == "scan_then_failed_login":
            events.append(
                create_event(
                    "port_scan",
                    source,
                    start,
                )
            )

            start += timedelta(seconds=random.randint(10, 60))

            events.append(
                create_event(
                    "failed_login",
                    source,
                    start,
                )
            )

            additional_events = random.randint(1, 3)

            for _ in range(additional_events):
                start += timedelta(seconds=random.randint(20, 120))

                events.append(
                    create_event(
                        random.choice(
                            [
                                "port_scan",
                                "failed_login",
                            ]
                        ),
                        source,
                        start,
                    )
                )

        elif scenario == "failed_then_success":
            event_count = random.randint(3, 5)

            for _ in range(event_count):
                start += timedelta(seconds=random.randint(15, 90))

                events.append(
                    create_event(
                        random.choice(
                            [
                                "failed_login",
                                "successful_login",
                            ]
                        ),
                        source,
                        start,
                    )
                )

    elif label == "high":
        # High-risk activity.
        #
        # Most samples contain the full:
        #
        # port_scan -> failed_login -> successful_login
        #
        # chain, but timing and surrounding activity vary.
        # Some high-risk samples contain additional noise so that
        # individual binary chain features are not perfect predictors.

        scenario = random.choice(
            [
                "rapid_attack_chain",
                "slower_attack_chain",
                "noisy_attack_chain",
            ]
        )

        if scenario == "rapid_attack_chain":
            events.append(
                create_event(
                    "port_scan",
                    source,
                    start,
                )
            )

            start += timedelta(seconds=random.randint(5, 25))

            events.append(
                create_event(
                    "failed_login",
                    source,
                    start,
                )
            )

            start += timedelta(seconds=random.randint(5, 25))

            events.append(
                create_event(
                    "successful_login",
                    source,
                    start,
                )
            )

        elif scenario == "slower_attack_chain":
            events.append(
                create_event(
                    "port_scan",
                    source,
                    start,
                )
            )

            start += timedelta(seconds=random.randint(30, 90))

            events.append(
                create_event(
                    "failed_login",
                    source,
                    start,
                )
            )

            start += timedelta(seconds=random.randint(30, 90))

            events.append(
                create_event(
                    "successful_login",
                    source,
                    start,
                )
            )

        elif scenario == "noisy_attack_chain":
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

            additional_events = random.randint(2, 5)

            for _ in range(additional_events):
                start += timedelta(seconds=random.randint(5, 90))

                events.append(
                    create_event(
                        random.choice(
                            [
                                "failed_login",
                                "successful_login",
                                "port_scan",
                            ]
                        ),
                        random.choice(available_sources),
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
