"""Policy loader and evaluator.

Uses ``yaml.safe_load`` rather than a hand-rolled parser. ``safe_load`` cannot
construct arbitrary Python objects, so a malicious policy file cannot trigger
code execution.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class PolicyError(ValueError):
    """Raised when the policy file is structurally invalid."""


def load_policy(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Missing policy file: {path}")
    raw = path.read_text(encoding="utf-8")
    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise PolicyError(f"Policy file is not valid YAML: {path}: {exc}") from exc

    if parsed is None:
        return {"controls": {}}
    if not isinstance(parsed, dict):
        raise PolicyError(f"Policy file root must be a mapping: {path}")

    controls = parsed.get("controls", {})
    if not isinstance(controls, dict):
        raise PolicyError(f"'controls' must be a mapping in: {path}")

    return {"controls": controls}


def _as_int(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    return default


def evaluate_policy(policy: dict, telemetry: dict, artifact_result: dict) -> list[dict]:
    findings: list[dict] = []
    controls = policy.get("controls", {})

    if _as_bool(controls.get("require_trusted_artifacts", True), True) and not artifact_result.get("trusted"):
        findings.append(
            {
                "control": "ARTIFACT_TRUST",
                "severity": "critical",
                "message": "Deployment artifact failed trust verification.",
            }
        )

    if _as_bool(controls.get("require_sbom", True), True) and not artifact_result.get("sbom_present"):
        findings.append(
            {
                "control": "SBOM_REQUIRED",
                "severity": "high",
                "message": "Artifact SBOM attestation is missing or did not verify.",
            }
        )

    if _as_bool(controls.get("require_signature", True), True):
        signature = artifact_result.get("signature") or {}
        if not signature.get("verified"):
            findings.append(
                {
                    "control": "SIGNATURE_REQUIRED",
                    "severity": "critical",
                    "message": "Sigstore signature did not verify: " + str(signature.get("reason", "unknown")),
                }
            )

    # require_provenance defaults to False here so existing callers and tests
    # that don't supply a SLSA Provenance attestation are not retroactively
    # broken. The deployed edge_policy.yml turns it on.
    if _as_bool(controls.get("require_provenance", False), False):
        provenance = artifact_result.get("provenance") or {}
        if not provenance.get("verified"):
            findings.append(
                {
                    "control": "PROVENANCE_REQUIRED",
                    "severity": "high",
                    "message": "SLSA Provenance attestation did not verify: " + str(provenance.get("reason", "unknown")),
                }
            )

    max_patch_days = _as_int(controls.get("max_patch_age_days", 30), 30)
    if _as_int(telemetry.get("last_patch_days", 999), 999) > max_patch_days:
        findings.append(
            {
                "control": "PATCH_AGE",
                "severity": "high",
                "message": f"Node patch age exceeds {max_patch_days} days.",
            }
        )

    if _as_bool(controls.get("require_disk_encryption", True), True) and not _as_bool(
        telemetry.get("disk_encrypted", False), False
    ):
        findings.append(
            {
                "control": "DISK_ENCRYPTION",
                "severity": "high",
                "message": "Edge node disk encryption is not enabled.",
            }
        )

    failed_login_limit = _as_int(controls.get("failed_login_limit", 5), 5)
    if _as_int(telemetry.get("failed_login_count", 0), 0) > failed_login_limit:
        findings.append(
            {
                "control": "AUTH_ANOMALY",
                "severity": "medium",
                "message": "Failed login count exceeds configured threshold.",
            }
        )

    backlog_limit = _as_int(controls.get("telemetry_backlog_limit", 25), 25)
    if _as_int(telemetry.get("telemetry_backlog", 0), 0) > backlog_limit:
        findings.append(
            {
                "control": "OFFLINE_BACKLOG",
                "severity": "medium",
                "message": "Offline telemetry backlog is above policy limit.",
            }
        )

    required_services = controls.get("required_services") or []
    if not isinstance(required_services, list):
        raise PolicyError("required_services must be a list")
    services = telemetry.get("critical_services") or {}
    if not isinstance(services, dict):
        services = {}
    for service in required_services:
        if services.get(service) != "running":
            findings.append(
                {
                    "control": "SERVICE_HEALTH",
                    "severity": "critical",
                    "message": f"Required service is not running: {service}",
                }
            )
    return findings
