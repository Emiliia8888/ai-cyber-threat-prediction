from src.prediction.evaluate import evaluate_model


class ModelEvaluation:
    """
    Application use case for evaluating the ML threat prediction model.

    The application layer exposes a stable entry point for model
    evaluation while the existing prediction implementation remains
    isolated behind this use case.
    """

    def evaluate(
        self,
        evaluation_file: str,
    ) -> None:
        """
        Evaluate the prediction model using the provided dataset.
        """
        evaluate_model(evaluation_file)
