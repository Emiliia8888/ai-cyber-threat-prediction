from src.prediction.evaluate import evaluate_model


class ModelEvaluation:
    """
    Application use case for evaluating the ML threat prediction model.

    The application layer exposes a stable entry point for model
    evaluation while the prediction implementation remains isolated
    behind this use case.
    """

    def evaluate(self) -> None:
        """
        Evaluate the persisted ML prediction model.
        """
        evaluate_model()
