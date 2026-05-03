"""Shared test fixtures.

A fake Sigstore verifier (``FakeVerifier``) lets every test deterministically
control whether a signature/attestation "verifies", what predicate the DSSE
unwraps to, and what subject digest it reports. No test ever talks to the real
Fulcio/Rekor services.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from talonedge.artifact import IN_TOTO_PAYLOAD_TYPE, TrustPolicy, sha256_file


@dataclass
class FakeVerifier:
    """Test double for ``SigstoreVerifier``.

    ``verify_artifact_ok`` controls whether ``verify_artifact`` raises.
    ``dsse_payload`` is the raw bytes returned by a single ``verify_dsse``
    call (for tests that only verify one attestation).
    ``dsse_responses`` is a queue of (payload_type, payload, error) tuples
    for tests that verify multiple attestations in sequence; if both are
    set, ``dsse_responses`` wins.
    """

    verify_artifact_ok: bool = True
    verify_artifact_error: Exception | None = None
    dsse_payload: bytes | None = None
    dsse_payload_type: str = IN_TOTO_PAYLOAD_TYPE
    dsse_error: Exception | None = None
    dsse_responses: list[tuple[str, bytes | None, Exception | None]] = field(default_factory=list)
    artifact_calls: list[dict] = field(default_factory=list)
    dsse_calls: list[dict] = field(default_factory=list)

    def verify_artifact(self, *, payload: bytes, bundle_json: str, policy: TrustPolicy) -> None:
        self.artifact_calls.append({"payload_len": len(payload), "policy": policy})
        if self.verify_artifact_error:
            raise self.verify_artifact_error
        if not self.verify_artifact_ok:
            raise RuntimeError("fake verifier: signature did not verify")

    def verify_dsse(self, *, bundle_json: str, policy: TrustPolicy) -> tuple[str, bytes]:
        self.dsse_calls.append({"policy": policy})
        if self.dsse_responses:
            payload_type, payload, error = self.dsse_responses.pop(0)
            if error:
                raise error
            if payload is None:
                raise RuntimeError("fake verifier: no DSSE payload configured for this call")
            return payload_type, payload
        if self.dsse_error:
            raise self.dsse_error
        if self.dsse_payload is None:
            raise RuntimeError("fake verifier: no DSSE payload configured")
        return self.dsse_payload_type, self.dsse_payload


SAMPLE_PAYLOAD = b"hello talonedge\n"
SAMPLE_PAYLOAD_SHA = "5b1d0aff66dee8e9e3f9a3d8a3a3e0c4e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0"  # placeholder, recomputed in fixture


@pytest.fixture
def workspace(tmp_path: Path):
    """Create a payload file and return a helper bundle of paths.

    The fixture writes a real payload, computes its real SHA, and returns the
    paths and digest so individual tests can build matching or mismatching
    manifests/bundles as needed.
    """
    payload = tmp_path / "payload.bin"
    payload.write_bytes(SAMPLE_PAYLOAD)
    actual_sha = sha256_file(payload)
    return {
        "tmp": tmp_path,
        "payload": payload,
        "sha": actual_sha,
        "manifest": tmp_path / "manifest.json",
        "sig_bundle": tmp_path / "payload.sigstore.bundle.json",
        "att_bundle": tmp_path / "payload.sbom.attest.bundle.json",
        "prov_bundle": tmp_path / "payload.provenance.attest.bundle.json",
    }


def write_manifest(
    path: Path,
    *,
    sha: str,
    sig: str = "payload.sigstore.bundle.json",
    att: str | None = "payload.sbom.attest.bundle.json",
    prov: str | None = None,
    identity: str = "ident",
    issuer: str = "issuer",
) -> None:
    body: dict = {
        "name": "talonedge-test",
        "version": "0.0.1",
        "sha256": sha,
        "sigstore_bundle": sig,
        "expected_identity": identity,
        "expected_issuer": issuer,
    }
    if att is not None:
        body["sbom_attestation"] = att
    if prov is not None:
        body["provenance_attestation"] = prov
    path.write_text(json.dumps(body), encoding="utf-8")


def make_provenance_statement(*, subject_sha: str, builder_id: str = "https://github.com/actions/runner/github-hosted") -> bytes:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": "payload.bin", "digest": {"sha256": subject_sha}}],
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/Aaron/TalonEdge/buildType/v1",
                "externalParameters": {"workflow": {"ref": "refs/heads/main"}},
                "internalParameters": {"runner_environment": "github-hosted"},
                "resolvedDependencies": [
                    {"uri": "git+https://github.com/Aaron/TalonEdge@refs/heads/main", "digest": {"gitCommit": "deadbeef" * 5}},
                ],
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {
                    "invocationId": "https://github.com/Aaron/TalonEdge/actions/runs/1/attempts/1",
                    "startedOn": "2026-05-03T01:00:00Z",
                },
            },
        },
    }
    return json.dumps(statement).encode("utf-8")


def make_in_toto_statement(*, subject_sha: str, predicate_type: str = "https://cyclonedx.org/bom", components: list[dict] | None = None) -> bytes:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": predicate_type,
        "subject": [
            {"name": "payload.bin", "digest": {"sha256": subject_sha}},
        ],
        "predicate": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": components if components is not None else [
                {"name": "python", "version": "3.11"},
                {"name": "pyyaml", "version": "6.0.2"},
            ],
        },
    }
    return json.dumps(statement).encode("utf-8")


@pytest.fixture
def fake_verifier() -> FakeVerifier:
    return FakeVerifier()


@pytest.fixture
def trust_policy() -> TrustPolicy:
    return TrustPolicy(identity="ident", issuer="issuer")
