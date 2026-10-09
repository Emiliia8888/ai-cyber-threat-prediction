from src.prediction.real_data.cic_clean_scenario_split import (
    load_files,
)
from src.prediction.real_data.cic_prediction_engine import (
    CICPredictionEngine,
)


FILES = [
    "Benign-Monday-no-metadata.parquet",
]


def test_cic_prediction_engine_predicts_benign():
    df = load_files(FILES)

    sample = df.iloc[0].drop(
        labels=["Label"]
    ).to_dict()

    engine = CICPredictionEngine()

    prediction, confidence = engine.predict(
        sample
    )

    assert prediction == "Benign"
    assert 0.0 <= confidence <= 1.0
