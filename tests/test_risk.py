"""Risk scoring boundaries."""

from talonedge.risk import score_findings


def f(severity):
    return {"control": "X", "severity": severity, "message": ""}


def test_no_findings_is_low():
    assert score_findings([]) == {"score": 0, "level": "LOW"}


def test_critical_alone_is_critical_band():
    # Single critical = 35 points → MEDIUM band; two crits = 70 → CRITICAL.
    one = score_findings([f("critical")])
    two = score_findings([f("critical"), f("critical")])
    assert one["level"] == "MEDIUM"
    assert two["level"] == "CRITICAL"


def test_high_band_threshold():
    # Three highs = 60 → HIGH band.
    assert score_findings([f("high"), f("high"), f("high")])["level"] == "HIGH"


def test_score_caps_at_100():
    # Twenty criticals would otherwise be 700 — must cap at 100.
    result = score_findings([f("critical")] * 20)
    assert result["score"] == 100
    assert result["level"] == "CRITICAL"


def test_unknown_severity_treated_as_low_weight():
    # A typo'd severity should not blow up — it becomes weight 3 (low).
    result = score_findings([f("critical-ish"), f("medium")])
    # 3 (unknown) + 10 (medium) = 13 -> LOW band (<15)
    assert result["score"] == 13
    assert result["level"] == "LOW"


def test_band_boundary_at_15():
    # 15 = MEDIUM (>=15 < 40).
    result = score_findings([f("medium"), f("medium")])  # 20
    assert result["level"] == "MEDIUM"


def test_missing_severity_field_defaults_low():
    result = score_findings([{"control": "X", "message": ""}])
    assert result["score"] == 3
    assert result["level"] == "LOW"
