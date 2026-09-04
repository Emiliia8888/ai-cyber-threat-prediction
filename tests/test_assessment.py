from src.detection.assessment import compare_assessments


def test_assessments_agree():
    assert compare_assessments("high", "high") is True


def test_assessments_disagree():
    assert compare_assessments("low", "high") is False
