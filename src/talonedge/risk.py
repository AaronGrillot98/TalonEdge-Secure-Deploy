WEIGHTS = {
    "critical": 35,
    "high": 20,
    "medium": 10,
    "low": 3,
}


def score_findings(findings: list[dict]) -> dict:
    score = min(100, sum(WEIGHTS.get(f.get("severity", "low"), 3) for f in findings))
    if score >= 70:
        level = "CRITICAL"
    elif score >= 40:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"
    return {"score": score, "level": level}
