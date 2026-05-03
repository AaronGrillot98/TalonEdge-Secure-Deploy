"""Negative-path tests for artifact verification.

Every test exercises a failure mode the v1 string-equality check missed:
hash tampering, missing manifest, missing bundles, sigstore exceptions,
unexpected DSSE payload type, in-toto subject digest mismatch, unsupported
predicate types, and so on. The happy path is covered last with the fake
verifier configured to succeed.
"""

import json

import pytest

from talonedge.artifact import IN_TOTO_PAYLOAD_TYPE, TrustPolicy, verify_artifact

from .conftest import make_in_toto_statement, write_manifest


def test_missing_payload_raises(tmp_path):
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        verify_artifact(tmp_path / "does-not-exist.bin", manifest)


def test_missing_manifest_raises(workspace):
    with pytest.raises(FileNotFoundError):
        verify_artifact(workspace["payload"], workspace["tmp"] / "no-manifest.json")


def test_malformed_manifest_raises(workspace):
    workspace["manifest"].write_text("this is not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        verify_artifact(workspace["payload"], workspace["manifest"])


def test_manifest_root_must_be_object(workspace):
    workspace["manifest"].write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(ValueError, match="must be a JSON object"):
        verify_artifact(workspace["payload"], workspace["manifest"])


def test_hash_mismatch_returns_untrusted_and_skips_signature(workspace, fake_verifier):
    write_manifest(workspace["manifest"], sha="0" * 64)
    workspace["sig_bundle"].write_text("{}", encoding="utf-8")
    workspace["att_bundle"].write_text("{}", encoding="utf-8")

    result = verify_artifact(workspace["payload"], workspace["manifest"], verifier=fake_verifier)

    assert result["trusted"] is False
    assert result["hash_ok"] is False
    assert result["signature"]["verified"] is False
    assert "sha256 mismatch" in result["signature"]["reason"]
    # Tamper-evident: we refuse to even attempt signature verification when
    # the hash doesn't match. The fake verifier should never have been called.
    assert fake_verifier.artifact_calls == []
    assert fake_verifier.dsse_calls == []


def test_no_trust_policy_yields_untrusted(workspace, fake_verifier):
    body = {
        "name": "x",
        "version": "y",
        "sha256": workspace["sha"],
        "sigstore_bundle": "payload.sigstore.bundle.json",
        "sbom_attestation": "payload.sbom.attest.bundle.json",
        # expected_identity / expected_issuer intentionally omitted
    }
    workspace["manifest"].write_text(json.dumps(body), encoding="utf-8")

    result = verify_artifact(workspace["payload"], workspace["manifest"], verifier=fake_verifier)

    assert result["trusted"] is False
    assert "no trust policy" in result["signature"]["reason"]


def test_missing_sigstore_bundle_field_returns_untrusted(workspace, fake_verifier):
    body = {
        "sha256": workspace["sha"],
        "expected_identity": "ident",
        "expected_issuer": "issuer",
        "sbom_attestation": "payload.sbom.attest.bundle.json",
    }
    workspace["manifest"].write_text(json.dumps(body), encoding="utf-8")

    result = verify_artifact(workspace["payload"], workspace["manifest"], verifier=fake_verifier)

    assert result["trusted"] is False
    assert result["signature"]["reason"] == "manifest is missing sigstore_bundle"


def test_missing_attestation_field_returns_untrusted_sbom(workspace, fake_verifier):
    write_manifest(workspace["manifest"], sha=workspace["sha"], att=None)
    workspace["sig_bundle"].write_text("{}", encoding="utf-8")
    fake_verifier.verify_artifact_ok = True

    result = verify_artifact(workspace["payload"], workspace["manifest"], verifier=fake_verifier)

    assert result["sbom"]["verified"] is False
    assert result["sbom"]["reason"] == "manifest is missing sbom_attestation"
    assert result["sbom_present"] is False


def test_bundle_file_not_on_disk(workspace, fake_verifier):
    write_manifest(workspace["manifest"], sha=workspace["sha"])
    # No bundle files written on disk.
    result = verify_artifact(workspace["payload"], workspace["manifest"], verifier=fake_verifier)

    assert result["trusted"] is False
    assert "Sigstore bundle not found" in result["signature"]["reason"]


def test_sigstore_verify_artifact_raises_returns_untrusted(workspace, fake_verifier, trust_policy):
    write_manifest(workspace["manifest"], sha=workspace["sha"])
    workspace["sig_bundle"].write_text("{}", encoding="utf-8")
    workspace["att_bundle"].write_text("{}", encoding="utf-8")
    fake_verifier.verify_artifact_error = RuntimeError("Rekor entry not found")
    fake_verifier.dsse_payload = make_in_toto_statement(subject_sha=workspace["sha"])

    result = verify_artifact(workspace["payload"], workspace["manifest"], verifier=fake_verifier)

    assert result["trusted"] is False
    assert result["signature"]["verified"] is False
    assert "Rekor entry not found" in result["signature"]["reason"]


def test_unexpected_dsse_payload_type_rejected(workspace, fake_verifier):
    write_manifest(workspace["manifest"], sha=workspace["sha"])
    workspace["sig_bundle"].write_text("{}", encoding="utf-8")
    workspace["att_bundle"].write_text("{}", encoding="utf-8")
    fake_verifier.verify_artifact_ok = True
    fake_verifier.dsse_payload_type = "application/json"
    fake_verifier.dsse_payload = b"{}"

    result = verify_artifact(workspace["payload"], workspace["manifest"], verifier=fake_verifier)

    assert result["sbom"]["verified"] is False
    assert "unexpected DSSE payloadType" in result["sbom"]["reason"]


def test_dsse_payload_not_json_rejected(workspace, fake_verifier):
    write_manifest(workspace["manifest"], sha=workspace["sha"])
    workspace["sig_bundle"].write_text("{}", encoding="utf-8")
    workspace["att_bundle"].write_text("{}", encoding="utf-8")
    fake_verifier.verify_artifact_ok = True
    fake_verifier.dsse_payload_type = IN_TOTO_PAYLOAD_TYPE
    fake_verifier.dsse_payload = b"\xff\xff not json \xff\xff"

    result = verify_artifact(workspace["payload"], workspace["manifest"], verifier=fake_verifier)

    assert result["sbom"]["verified"] is False
    assert "not valid JSON" in result["sbom"]["reason"]


def test_unsupported_predicate_type_rejected(workspace, fake_verifier):
    write_manifest(workspace["manifest"], sha=workspace["sha"])
    workspace["sig_bundle"].write_text("{}", encoding="utf-8")
    workspace["att_bundle"].write_text("{}", encoding="utf-8")
    fake_verifier.verify_artifact_ok = True
    fake_verifier.dsse_payload = make_in_toto_statement(
        subject_sha=workspace["sha"],
        predicate_type="https://example.org/totally-fake/v1",
    )

    result = verify_artifact(workspace["payload"], workspace["manifest"], verifier=fake_verifier)

    assert result["sbom"]["verified"] is False
    assert "unsupported predicateType" in result["sbom"]["reason"]


def test_in_toto_subject_digest_mismatch_rejected(workspace, fake_verifier):
    write_manifest(workspace["manifest"], sha=workspace["sha"])
    workspace["sig_bundle"].write_text("{}", encoding="utf-8")
    workspace["att_bundle"].write_text("{}", encoding="utf-8")
    fake_verifier.verify_artifact_ok = True
    # Attestation subject points at a different artifact's hash.
    fake_verifier.dsse_payload = make_in_toto_statement(subject_sha="a" * 64)

    result = verify_artifact(workspace["payload"], workspace["manifest"], verifier=fake_verifier)

    assert result["sbom"]["verified"] is False
    assert "subject digest does not match" in result["sbom"]["reason"]


def test_dsse_verify_raises_returns_untrusted_sbom(workspace, fake_verifier):
    write_manifest(workspace["manifest"], sha=workspace["sha"])
    workspace["sig_bundle"].write_text("{}", encoding="utf-8")
    workspace["att_bundle"].write_text("{}", encoding="utf-8")
    fake_verifier.verify_artifact_ok = True
    fake_verifier.dsse_error = RuntimeError("DSSE signature invalid")

    result = verify_artifact(workspace["payload"], workspace["manifest"], verifier=fake_verifier)

    assert result["sbom"]["verified"] is False
    assert "DSSE signature invalid" in result["sbom"]["reason"]


def test_attestation_bundle_file_missing(workspace, fake_verifier):
    write_manifest(workspace["manifest"], sha=workspace["sha"])
    workspace["sig_bundle"].write_text("{}", encoding="utf-8")
    fake_verifier.verify_artifact_ok = True

    result = verify_artifact(workspace["payload"], workspace["manifest"], verifier=fake_verifier)

    assert result["sbom"]["verified"] is False
    assert "Sigstore bundle not found" in result["sbom"]["reason"]


def test_happy_path_with_fake_verifier(workspace, fake_verifier):
    """All signals green: hash match + signature verifies + DSSE verifies + subject matches."""
    write_manifest(workspace["manifest"], sha=workspace["sha"])
    workspace["sig_bundle"].write_text("{}", encoding="utf-8")
    workspace["att_bundle"].write_text("{}", encoding="utf-8")
    fake_verifier.verify_artifact_ok = True
    fake_verifier.dsse_payload = make_in_toto_statement(subject_sha=workspace["sha"])

    result = verify_artifact(workspace["payload"], workspace["manifest"], verifier=fake_verifier)

    assert result["trusted"] is True
    assert result["hash_ok"] is True
    assert result["signature"]["verified"] is True
    assert result["sbom"]["verified"] is True
    assert result["sbom"]["predicate_type"] == "https://cyclonedx.org/bom"
    assert any(c.get("name") == "python" for c in result["components"])


def test_caller_policy_overrides_manifest_policy(workspace, fake_verifier):
    """Explicit policy passed to verify_artifact wins over manifest fields."""
    write_manifest(
        workspace["manifest"],
        sha=workspace["sha"],
        identity="manifest-ident",
        issuer="manifest-issuer",
    )
    workspace["sig_bundle"].write_text("{}", encoding="utf-8")
    workspace["att_bundle"].write_text("{}", encoding="utf-8")
    fake_verifier.verify_artifact_ok = True
    fake_verifier.dsse_payload = make_in_toto_statement(subject_sha=workspace["sha"])
    override = TrustPolicy(identity="cli-ident", issuer="cli-issuer")

    result = verify_artifact(
        workspace["payload"], workspace["manifest"], policy=override, verifier=fake_verifier
    )

    assert result["trusted"] is True
    assert fake_verifier.artifact_calls[0]["policy"] == override
    assert fake_verifier.dsse_calls[0]["policy"] == override


def test_spdx_attestation_extracts_packages_as_components(workspace, fake_verifier):
    write_manifest(workspace["manifest"], sha=workspace["sha"])
    workspace["sig_bundle"].write_text("{}", encoding="utf-8")
    workspace["att_bundle"].write_text("{}", encoding="utf-8")
    fake_verifier.verify_artifact_ok = True
    spdx_statement = json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://spdx.dev/Document",
            "subject": [{"digest": {"sha256": workspace["sha"]}}],
            "predicate": {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {"name": "openssl", "versionInfo": "3.2.0"},
                    {"name": "zlib", "versionInfo": "1.3"},
                ],
            },
        }
    ).encode("utf-8")
    fake_verifier.dsse_payload = spdx_statement

    result = verify_artifact(workspace["payload"], workspace["manifest"], verifier=fake_verifier)

    assert result["trusted"] is True
    names = {c["name"] for c in result["components"]}
    assert names == {"openssl", "zlib"}
