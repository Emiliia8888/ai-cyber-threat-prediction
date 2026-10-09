from pathlib import Path

import joblib


MODEL_PATH = (
    Path(__file__).resolve().parents[3]
    / "models"
    / "cic_multiclass_random_forest.joblib"
)


def save_cic_model(
    model,
    preprocessor,
    encoder,
    path=MODEL_PATH,
):
    output_path = Path(path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    artifact = {
        "model": model,
        "preprocessor": preprocessor,
        "label_encoder": encoder,
    }

    joblib.dump(
        artifact,
        output_path,
    )

    return output_path


def load_cic_model(path=MODEL_PATH):
    model_path = Path(path)

    if not model_path.exists():
        raise FileNotFoundError(
            f"CIC model file not found: {model_path}"
        )

    return joblib.load(model_path)
