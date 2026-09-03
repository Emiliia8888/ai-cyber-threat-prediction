from datetime import datetime


def normalize_events(events):

    for event in events:

        event["timestamp"] = datetime.strptime(

            event["timestamp"],

            "%Y-%m-%d %H:%M:%S"

        )

    return events


def calculate_time_difference(event1, event2):

    return event2["timestamp"] - event1["timestamp"]

def add_time_differences(events):
    for i in range(1, len(events)):
        events[i]["time_since_previous"] = (
            events[i]["timestamp"] - events[i - 1]["timestamp"]
        )

    return events
