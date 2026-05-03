"""Artifact trust verification.

Replaces the v1 string-equality "trust" check with real Sigstore (Fulcio + Rekor)
keyless verification of:

  1. A signed payload (cosign sign-blob --bundle) — proves who signed the artifact
     and that Rekor logged the signing event.
  2. An in-toto / DSSE SBOM attestation (cosign attest-blob --bundle, predicate
     type CycloneDX or SPDX) — proves the SBOM was issued by the same identity
     and binds it to the artifact via its sha256 digest.

The verifier object is injected (see ``DefaultSigstoreVerifier``) so tests can
substitute a fake without ever calling the real Fulcio/Rekor services.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"
SUPPORTED_PREDICATE_TYPES = (
    "https://cyclonedx.org/bom",
    "https://spdx.dev/Document",
    "https://slsa.dev/provenance/v1",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True)
class TrustPolicy:
    """Identity policy that the signing certificate must satisfy.

    ``identity`` is the Fulcio cert's SAN — for GitHub Actions OIDC this is the
    workflow ref, e.g.
    ``https://github.com/<owner>/<repo>/.github/workflows/deploy-aws.yml@refs/heads/main``.

    ``issuer`` is the OIDC issuer — for GitHub Actions, always
    ``https://token.actions.githubusercontent.com``.
    """

    identity: str
    issuer: str


class SigstoreVerifier(Protocol):
    def verify_artifact(self, *, payload: bytes, bundle_json: str, policy: TrustPolicy) -> None: ...
    def verify_dsse(self, *, bundle_json: str, policy: TrustPolicy) -> tuple[str, bytes]: ...


class DefaultSigstoreVerifier:
    """Thin wrapper over sigstore-python's production Verifier.

    Imported lazily so unit tests can run without the sigstore package installed.
    """

    def __init__(self) -> None:
        from sigstore.verify import Verifier

        self._verifier = Verifier.production()

    def _load_bundle(self, bundle_json: str):
        from sigstore.models import Bundle

        return Bundle.from_json(bundle_json)

    def _identity_policy(self, policy: TrustPolicy):
        from sigstore.verify.policy import Identity

        return Identity(identity=policy.identity, issuer=policy.issuer)

    def verify_artifact(self, *, payload: bytes, bundle_json: str, policy: TrustPolicy) -> None:
        bundle = self._load_bundle(bundle_json)
        self._verifier.verify_artifact(input_=payload, bundle=bundle, policy=self._identity_policy(policy))

    def verify_dsse(self, *, bundle_json: str, policy: TrustPolicy) -> tuple[str, bytes]:
        bundle = self._load_bundle(bundle_json)
        return self._verifier.verify_dsse(bundle=bundle, policy=self._identity_policy(policy))


def _read_bundle(bundle_path: Path) -> str:
    if not bundle_path.exists():
        raise FileNotFoundError(f"Sigstore bundle not found: {bundle_path}")
    return bundle_path.read_text(encoding="utf-8")


def _components_from_predicate(predicate: dict[str, Any]) -> list[dict[str, Any]]:
    if "components" in predicate:
        return list(predicate.get("components") or [])
    if "packages" in predicate:
        return [
            {"name": p.get("name", ""), "version": p.get("versionInfo", "")}
            for p in (predicate.get("packages") or [])
        ]
    return []


def _verify_payload_signature(
    payload_path: Path,
    bundle_path: Path,
    policy: TrustPolicy,
    get_verifier,
) -> dict[str, Any]:
    # Read the bundle first; if it's missing we never construct the real
    # verifier (which would do a TUF fetch and fail on Windows without
    # Developer Mode for symlinks).
    try:
        bundle_json = _read_bundle(bundle_path)
    except FileNotFoundError as exc:
        return {"verified": False, "reason": str(exc)}
    try:
        verifier = get_verifier()
        verifier.verify_artifact(
            payload=payload_path.read_bytes(),
            bundle_json=bundle_json,
            policy=policy,
        )
    except Exception as exc:
        return {"verified": False, "reason": f"signature verification failed: {exc.__class__.__name__}: {exc}"}
    return {"verified": True, "reason": "ok", "identity": policy.identity, "issuer": policy.issuer}


def _verify_sbom_attestation(
    payload_path: Path,
    bundle_path: Path,
    policy: TrustPolicy,
    get_verifier,
) -> dict[str, Any]:
    try:
        bundle_json = _read_bundle(bundle_path)
    except FileNotFoundError as exc:
        return {"verified": False, "reason": str(exc), "components": []}
    try:
        verifier = get_verifier()
        payload_type, payload_bytes = verifier.verify_dsse(bundle_json=bundle_json, policy=policy)
    except Exception as exc:
        return {
            "verified": False,
            "reason": f"attestation verification failed: {exc.__class__.__name__}: {exc}",
            "components": [],
        }

    if payload_type != IN_TOTO_PAYLOAD_TYPE:
        return {"verified": False, "reason": f"unexpected DSSE payloadType: {payload_type}", "components": []}

    try:
        statement = json.loads(payload_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return {"verified": False, "reason": f"in-toto statement is not valid JSON: {exc}", "components": []}

    predicate_type = statement.get("predicateType", "")
    if predicate_type not in SUPPORTED_PREDICATE_TYPES:
        return {"verified": False, "reason": f"unsupported predicateType: {predicate_type}", "components": []}

    actual_sha = sha256_file(payload_path)
    subjects = statement.get("subject") or []
    subject_match = any(
        (subject.get("digest") or {}).get("sha256", "").lower() == actual_sha.lower()
        for subject in subjects
    )
    if not subject_match:
        return {
            "verified": False,
            "reason": "in-toto subject digest does not match payload sha256",
            "components": [],
        }

    components = _components_from_predicate(statement.get("predicate") or {})
    return {
        "verified": True,
        "reason": "ok",
        "predicate_type": predicate_type,
        "components": components,
        "identity": policy.identity,
        "issuer": policy.issuer,
    }


def verify_artifact(
    payload_path: Path,
    manifest_path: Path,
    *,
    policy: TrustPolicy | None = None,
    verifier: SigstoreVerifier | None = None,
) -> dict[str, Any]:
    """Verify an artifact's hash, Sigstore signature, and SBOM attestation.

    ``policy`` defaults to values pulled from the manifest if absent. ``verifier``
    defaults to ``DefaultSigstoreVerifier`` (real Fulcio/Rekor) but can be
    injected for tests.
    """
    if not payload_path.exists():
        raise FileNotFoundError(f"Missing payload: {payload_path}")
    if not manifest_path.exists():
        raise FileNotFoundError(f"Missing manifest: {manifest_path}")

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Manifest is not valid JSON: {manifest_path}: {exc}") from exc
    if not isinstance(manifest, dict):
        raise ValueError(f"Manifest must be a JSON object: {manifest_path}")

    actual_sha = sha256_file(payload_path)
    expected_sha = str(manifest.get("sha256", "")).lower()
    hash_ok = bool(expected_sha) and actual_sha.lower() == expected_sha

    if policy is None:
        identity = manifest.get("expected_identity")
        issuer = manifest.get("expected_issuer")
        if identity and issuer:
            policy = TrustPolicy(identity=identity, issuer=issuer)

    manifest_dir = manifest_path.parent
    bundle_field = manifest.get("sigstore_bundle")
    sbom_field = manifest.get("sbom_attestation")

    if not hash_ok:
        signature = {"verified": False, "reason": "payload sha256 mismatch — refusing to verify signature"}
        sbom = {"verified": False, "reason": "payload sha256 mismatch — refusing to verify SBOM", "components": []}
    elif policy is None:
        signature = {"verified": False, "reason": "no trust policy supplied (set expected_identity/expected_issuer in manifest or pass --identity/--issuer)"}
        sbom = {"verified": False, "reason": "no trust policy supplied", "components": []}
    else:
        # Build the real verifier at most once, and only when a bundle file
        # is actually on disk. This keeps the demo path on Windows from
        # tripping over sigstore-python's TUF symlink requirement.
        cache: list[SigstoreVerifier | None] = [verifier]

        def get_verifier() -> SigstoreVerifier:
            if cache[0] is None:
                cache[0] = DefaultSigstoreVerifier()
            return cache[0]

        signature = (
            _verify_payload_signature(payload_path, manifest_dir / bundle_field, policy, get_verifier)
            if bundle_field
            else {"verified": False, "reason": "manifest is missing sigstore_bundle"}
        )
        sbom = (
            _verify_sbom_attestation(payload_path, manifest_dir / sbom_field, policy, get_verifier)
            if sbom_field
            else {"verified": False, "reason": "manifest is missing sbom_attestation", "components": []}
        )

    trusted = hash_ok and signature["verified"] and sbom["verified"]
    return {
        "name": manifest.get("name", payload_path.name),
        "version": manifest.get("version", "unknown"),
        "expected_sha256": expected_sha,
        "actual_sha256": actual_sha,
        "hash_ok": hash_ok,
        "signature": signature,
        "sbom": sbom,
        "sbom_present": sbom["verified"],
        "components": sbom.get("components", []),
        "trusted": trusted,
    }
