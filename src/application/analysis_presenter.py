from src.application.analysis_result import AnalysisResult


class AnalysisPresenter:
    """
    Formats application analysis results for CLI presentation.

    Presentation logic is kept outside the application use case
    and domain logic.
    """

    def present(self, result: AnalysisResult) -> None:
        print(f"ML prediction: {result.prediction}")
        print(f"Confidence: {result.confidence:.2%}")
        print(f"Threat level: {result.threat_level}")
        print(f"Attack type: {result.attack_type}")

        print(
            f"Assessment agreement: "
            f"{'YES' if result.agreement else 'NO'}"
        )

        print("Risk explanation:")

        for explanation in result.explanation:
            print(f"  - {explanation}")

        print("Risk severity:")

        for item in result.severity:
            print(
                f"  - {item['level']}: {item['message']}"
            )
