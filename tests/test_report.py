"""Report rendering — verify HTML escaping for every dynamic field."""

from talonedge.report import component_rows, finding_rows, write_html_report


XSS = "<script>alert(1)</script>"
EXPECTED_ESCAPE = "&lt;script&gt;alert(1)&lt;/script&gt;"


def _scaffold_result(*, artifact_overrides=None, findings=None):
    artifact = {
        "name": "edge-agent",
        "version": "1.0",
        "trusted": True,
        "hash_ok": True,
        "expected_sha256": "deadbeef" * 8,
        "actual_sha256": "deadbeef" * 8,
        "signature": {"verified": True, "reason": "ok", "identity": "id", "issuer": "iss"},
        "sbom": {"verified": True, "reason": "ok", "predicate_type": "cdx", "components": []},
        "components": [],
    }
    if artifact_overrides:
        artifact.update(artifact_overrides)
    return {
        "artifact": artifact,
        "telemetry": {"node_id": "edge-01", "network_status": "ok"},
        "findings": findings or [],
        "risk": {"level": "LOW", "score": 0},
    }


def test_finding_message_is_html_escaped():
    rows = finding_rows([{"severity": "high", "control": "X", "message": XSS}])
    assert "<script>" not in rows
    assert EXPECTED_ESCAPE in rows


def test_finding_severity_and_control_are_escaped():
    rows = finding_rows([{"severity": "<crit>", "control": "<ctrl>", "message": "ok"}])
    assert "<crit>" not in rows
    assert "&lt;crit&gt;".upper() in rows.upper()
    assert "&lt;ctrl&gt;" in rows


def test_no_findings_renders_placeholder():
    rows = finding_rows([])
    assert "No findings detected" in rows
    assert "colspan='3'" in rows


def test_component_rows_escape_xss():
    rows = component_rows([{"name": XSS, "version": "1.0"}])
    assert "<script>" not in rows
    assert EXPECTED_ESCAPE in rows


def test_artifact_name_in_hero_is_escaped(tmp_path):
    out = tmp_path / "report.html"
    result = _scaffold_result(artifact_overrides={"name": XSS})
    write_html_report(result, out)
    body = out.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in body
    assert EXPECTED_ESCAPE in body


def test_signature_reason_is_escaped(tmp_path):
    out = tmp_path / "report.html"
    result = _scaffold_result(
        artifact_overrides={
            "trusted": False,
            "signature": {"verified": False, "reason": XSS, "identity": "i", "issuer": "j"},
        }
    )
    write_html_report(result, out)
    body = out.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in body
    assert EXPECTED_ESCAPE in body


def test_telemetry_node_id_is_escaped(tmp_path):
    out = tmp_path / "report.html"
    result = _scaffold_result()
    result["telemetry"]["node_id"] = XSS
    write_html_report(result, out)
    body = out.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in body
    assert EXPECTED_ESCAPE in body


def test_findings_table_renders_each_finding(tmp_path):
    out = tmp_path / "report.html"
    findings = [
        {"severity": "critical", "control": "A", "message": "first"},
        {"severity": "medium", "control": "B", "message": "second"},
    ]
    result = _scaffold_result(findings=findings)
    write_html_report(result, out)
    body = out.read_text(encoding="utf-8")
    assert "first" in body and "second" in body
    assert body.count("<tr>") >= 2
