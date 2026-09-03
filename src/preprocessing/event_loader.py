import json
from pathlib import Path


def load_events(path):
    path = Path(path)

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)

