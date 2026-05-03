# Security Posture

This document records the security controls TalonEdge enforces, where each one
lives in the repo, and what it actually defends against.

## Trust model

Trust is **cryptographic**, not declarative.

- Every artifact must carry a Sigstore (Fulcio + Rekor) keyless signature.
- Every artifact must carry an in-toto / DSSE SBOM attestation (CycloneDX or
  SPDX). The attestation's subject digest must match the payload's SHA-256.
- The Fulcio cert SAN must equal the configured `expected_identity`, and the
  OIDC issuer must equal the configured `expected_issuer`. Defaults pull
  from the manifest; CLI flags `--identity` / `--issuer` override.
- A missing bundle, a missing attestation, a wrong identity, a tampered
  payload, or a Rekor mismatch all produce `trusted: false`. There is no
  "warn and continue" path.

Implementation: `src/talonedge/artifact.py`.

## Pipeline guarantees

- All GitHub Actions are pinned by commit SHA. Re-resolve with
  `./scripts/pin-actions.sh`. CI also runs `./scripts/pin-actions.sh --check`
  on every PR (see `.github/workflows/security-ci.yml`).
- The deploy workflow uses GitHub OIDC for both Sigstore and AWS — no
  long-lived AWS keys live anywhere in the repo or in environment secrets.
- Deployments are gated by the `production` environment. Required reviewers
  are configured in the GitHub UI (Environments → production → Required
  reviewers) and cannot be bypassed by a force-push to `main`.
- `concurrency: deploy-aws` serializes deploys; back-to-back pushes cannot
  race the `s3 sync --delete` + invalidation.

## CI scanners (fail-closed)

| Tool        | Scope                                  | Workflow                             |
|-------------|----------------------------------------|--------------------------------------|
| pytest      | unit tests, including negative paths   | `python` job                         |
| Bandit      | Python SAST                            | `python` job                         |
| pip-audit   | Python dependency CVEs                 | `python` job                         |
| Gitleaks    | Secret scanning over full git history  | `secrets` job                        |
| tfsec       | Terraform misconfig                    | `iac` job                            |
| Trivy fs    | Vulns + misconfig + secrets in `.`     | `filesystem` job                     |

Every scanner is configured to fail the build on any CRITICAL or HIGH finding.

## Container

- Multi-stage build, base pinned by digest (`Dockerfile`).
- Final image runs as UID/GID 10001 (`USER 10001:10001`).
- `.dockerignore` excludes `.git`, `tests`, `infra`, docs, screenshots, and
  any local Sigstore artifacts so they cannot leak into a published image.

## Kubernetes

`infra/k8s/deployment.yaml` enforces:

- Namespace labeled `pod-security.kubernetes.io/enforce: restricted`.
- `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`.
- `capabilities: { drop: [ALL] }`, `seccompProfile: RuntimeDefault`.
- Resource requests and limits on CPU, memory, and ephemeral storage.
- Liveness and readiness probes.
- A default-deny `NetworkPolicy` that allows only DNS egress to kube-dns.
- `automountServiceAccountToken: false` on the SA and the pod.

## AWS

`infra/aws/main.tf`:

- Site bucket: `BucketOwnerEnforced` (ACLs disabled), public access fully
  blocked, AES256 SSE, versioning enabled.
- Bucket policy denies anything where `aws:SecureTransport=false`.
- CloudFront uses Origin Access Control (sigv4), `redirect-to-https`, and
  TLS 1.2_2021 minimum.
- CloudFront access logs go to a separate logs bucket with a 90-day
  expiration lifecycle and the same SecureTransport deny.
- Deploy IAM role assumed via GitHub OIDC, scoped to
  `repo:<owner>/<repo>:ref:refs/heads/main`. Permissions limited to
  `s3:Put/Delete/List` on the site bucket and `cloudfront:CreateInvalidation`
  on the one distribution.

## Reporting a vulnerability

Open a private security advisory on the GitHub repo. Please do not file
public issues for security reports.
