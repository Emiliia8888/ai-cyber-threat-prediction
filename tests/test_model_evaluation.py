from unittest.mock import patch

from src.application.model_evaluation import ModelEvaluation


def test_model_evaluation_delegates_to_evaluate_model():
    evaluator = ModelEvaluation()

    with patch(
        "src.application.model_evaluation.evaluate_model"
    ) as mock_evaluate:
        evaluator.evaluate("data/evaluation.json")

    mock_evaluate.assert_called_once_with(
        "data/evaluation.json"
    )
