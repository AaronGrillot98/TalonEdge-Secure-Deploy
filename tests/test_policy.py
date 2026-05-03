"""Tests for the policy loader, parser, and evaluator."""

import pytest

from talonedge.policy import PolicyError, evaluate_policy, load_policy
from talonedge.risk import score_findings


# ---------- evaluate_policy: each control covered, including disabling them ----------


def _trusted_artifact():
    return {
        "trusted": True,
        "sbom_present": True,
        "signature": {"verified": True, "reason": "ok"},
        "sbom": {"verified": True, "reason": "ok"},
        "provenance": {"verified": True, "reason": "ok"},
    }


def _healthy_telemetry():
    return {
        "disk_encrypted": True,
        "last_patch_days": 5,
        "failed_login_count": 0,
        "telemetry_backlog": 0,
        "critical_services": {"a": "running", "b": "running"},
    }


def test_clean_telemetry_and_trusted_artifact_yields_no_findings():
    policy = {
        "controls": {
            "require_trusted_artifacts": True,
            "require_sbom": True,
            "require_signature": True,
            "require_disk_encryption": True,
            "max_patch_age_days": 30,
            "failed_login_limit": 5,
            "telemetry_backlog_limit": 25,
            "required_services": ["a", "b"],
        }
    }
    assert evaluate_policy(policy, _healthy_telemetry(), _trusted_artifact()) == []


def test_untrusted_artifact_yields_critical():
    policy = {"controls": {"require_trusted_artifacts": True}}
    artifact = {**_trusted_artifact(), "trusted": False}
    findings = evaluate_policy(policy, _healthy_telemetry(), artifact)
    assert any(f["control"] == "ARTIFACT_TRUST" and f["severity"] == "critical" for f in findings)


def test_missing_sbom_yields_high():
    policy = {"controls": {"require_trusted_artifacts": False, "require_sbom": True, "require_signature": False}}
    artifact = {**_trusted_artifact(), "sbom_present": False}
    findings = evaluate_policy(policy, _healthy_telemetry(), artifact)
    assert any(f["control"] == "SBOM_REQUIRED" and f["severity"] == "high" for f in findings)


def test_unverified_signature_yields_critical():
    policy = {"controls": {"require_trusted_artifacts": False, "require_sbom": False, "require_signature": True}}
    artifact = {**_trusted_artifact(), "signature": {"verified": False, "reason": "Rekor entry not found"}}
    findings = evaluate_policy(policy, _healthy_telemetry(), artifact)
    sig_findings = [f for f in findings if f["control"] == "SIGNATURE_REQUIRED"]
    assert sig_findings and sig_findings[0]["severity"] == "critical"
    assert "Rekor" in sig_findings[0]["message"]


def test_require_provenance_default_false_is_quiet():
    policy = {"controls": {"require_trusted_artifacts": False, "require_sbom": False, "require_signature": False}}
    artifact = {**_trusted_artifact(), "provenance": {"verified": False, "reason": "missing"}}
    findings = evaluate_policy(policy, _healthy_telemetry(), artifact)
    assert not any(f["control"] == "PROVENANCE_REQUIRED" for f in findings)


def test_require_provenance_true_with_unverified_yields_high():
    policy = {
        "controls": {
            "require_trusted_artifacts": False,
            "require_sbom": False,
            "require_signature": False,
            "require_provenance": True,
        }
    }
    artifact = {**_trusted_artifact(), "provenance": {"verified": False, "reason": "subject digest mismatch"}}
    findings = evaluate_policy(policy, _healthy_telemetry(), artifact)
    prov_findings = [f for f in findings if f["control"] == "PROVENANCE_REQUIRED"]
    assert prov_findings and prov_findings[0]["severity"] == "high"
    assert "subject digest mismatch" in prov_findings[0]["message"]


def test_disk_not_encrypted_yields_high():
    policy = {"controls": {"require_disk_encryption": True}}
    telemetry = {**_healthy_telemetry(), "disk_encrypted": False}
    findings = evaluate_policy(policy, telemetry, _trusted_artifact())
    assert any(f["control"] == "DISK_ENCRYPTION" and f["severity"] == "high" for f in findings)


def test_patch_age_above_threshold():
    policy = {"controls": {"max_patch_age_days": 30}}
    telemetry = {**_healthy_telemetry(), "last_patch_days": 90}
    findings = evaluate_policy(policy, telemetry, _trusted_artifact())
    assert any(f["control"] == "PATCH_AGE" for f in findings)


def test_patch_age_at_threshold_does_not_fire():
    policy = {"controls": {"max_patch_age_days": 30}}
    telemetry = {**_healthy_telemetry(), "last_patch_days": 30}
    findings = evaluate_policy(policy, telemetry, _trusted_artifact())
    assert not any(f["control"] == "PATCH_AGE" for f in findings)


def test_failed_login_above_limit_yields_medium():
    policy = {"controls": {"failed_login_limit": 5}}
    telemetry = {**_healthy_telemetry(), "failed_login_count": 9}
    findings = evaluate_policy(policy, telemetry, _trusted_artifact())
    assert any(f["control"] == "AUTH_ANOMALY" and f["severity"] == "medium" for f in findings)


def test_telemetry_backlog_above_limit_yields_medium():
    policy = {"controls": {"telemetry_backlog_limit": 25}}
    telemetry = {**_healthy_telemetry(), "telemetry_backlog": 100}
    findings = evaluate_policy(policy, telemetry, _trusted_artifact())
    assert any(f["control"] == "OFFLINE_BACKLOG" for f in findings)


def test_missing_required_service_yields_critical_per_service():
    policy = {"controls": {"required_services": ["alpha", "beta", "gamma"]}}
    telemetry = {**_healthy_telemetry(), "critical_services": {"alpha": "running", "beta": "stopped"}}
    findings = evaluate_policy(policy, telemetry, _trusted_artifact())
    service_findings = [f for f in findings if f["control"] == "SERVICE_HEALTH"]
    assert len(service_findings) == 2
    bad = {f["message"].rsplit(": ", 1)[-1] for f in service_findings}
    assert bad == {"beta", "gamma"}


def test_required_services_must_be_list():
    policy = {"controls": {"required_services": "not-a-list"}}
    with pytest.raises(PolicyError):
        evaluate_policy(policy, _healthy_telemetry(), _trusted_artifact())


def test_default_thresholds_when_policy_empty():
    """An empty policy still enforces the secure-by-default checks."""
    policy = {"controls": {}}
    artifact = {**_trusted_artifact(), "trusted": False}
    findings = evaluate_policy(policy, _healthy_telemetry(), artifact)
    assert any(f["control"] == "ARTIFACT_TRUST" for f in findings)


def test_score_aggregates_severity():
    findings = [
        {"control": "X", "severity": "critical", "message": ""},
        {"control": "Y", "severity": "high", "message": ""},
    ]
    result = score_findings(findings)
    assert result["score"] == 55
    assert result["level"] == "HIGH"


# ---------- load_policy: parser correctness for previously-fragile cases ----------


def test_load_policy_handles_quoted_strings_with_colons(tmp_path):
    # The hand-rolled parser silently mis-parsed values like "host:port".
    # safe_load handles them correctly.
    path = tmp_path / "p.yml"
    path.write_text(
        """
        controls:
          motd: "host:8080 — restricted"
          required_services:
            - alpha
        """,
        encoding="utf-8",
    )
    policy = load_policy(path)
    assert policy["controls"]["motd"] == "host:8080 — restricted"
    assert policy["controls"]["required_services"] == ["alpha"]


def test_load_policy_handles_inline_comments(tmp_path):
    path = tmp_path / "p.yml"
    path.write_text(
        """
        # leading comment
        controls:
          max_patch_age_days: 14  # inline comment
          require_disk_encryption: true
        """,
        encoding="utf-8",
    )
    policy = load_policy(path)
    assert policy["controls"]["max_patch_age_days"] == 14
    assert policy["controls"]["require_disk_encryption"] is True


def test_load_policy_handles_nested_mapping(tmp_path):
    path = tmp_path / "p.yml"
    path.write_text(
        """
        controls:
          required_services:
            - artifact_verifier
          thresholds:
            max_patch_age_days: 7
            failed_login_limit: 3
        """,
        encoding="utf-8",
    )
    policy = load_policy(path)
    assert policy["controls"]["thresholds"]["failed_login_limit"] == 3


def test_load_policy_empty_file_returns_empty_controls(tmp_path):
    path = tmp_path / "p.yml"
    path.write_text("", encoding="utf-8")
    assert load_policy(path) == {"controls": {}}


def test_load_policy_invalid_yaml_raises_policy_error(tmp_path):
    path = tmp_path / "p.yml"
    # Tab indentation inside a mapping is a yaml.YAMLError.
    path.write_text("controls:\n\tfoo: 1\n", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(path)


def test_load_policy_root_must_be_mapping(tmp_path):
    path = tmp_path / "p.yml"
    path.write_text("- 1\n- 2\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="must be a mapping"):
        load_policy(path)


def test_load_policy_missing_file_raises_filenotfound(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_policy(tmp_path / "does-not-exist.yml")


def test_load_policy_safe_load_does_not_construct_arbitrary_objects(tmp_path):
    # Tag-based RCE attempt. safe_load must reject this rather than calling out
    # to ``os.system`` or any other arbitrary constructor.
    path = tmp_path / "p.yml"
    path.write_text(
        "controls: !!python/object/apply:os.system [\"echo pwned\"]\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError):
        load_policy(path)
