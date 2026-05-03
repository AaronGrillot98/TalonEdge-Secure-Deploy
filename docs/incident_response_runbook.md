# TalonEdge Incident Response Runbook

## Purpose

This runbook explains how to respond when TalonEdge detects a suspicious artifact, failed deployment, or degraded edge-node state.

## Severity Levels

### SEV-1
Confirmed compromised artifact or deployment to production environment.

### SEV-2
Suspicious artifact blocked before deployment.

### SEV-3
Failed pipeline, failed sync, or non-critical telemetry issue.

## Response Steps

1. Identify the issue in the TalonEdge report and GitHub Actions logs.
2. Contain by stopping further deployments or protecting the main branch.
3. Validate hashes, trust score, telemetry status, and deployment logs.
4. Recover the last known-good report or artifact.
5. Document root cause, timeline, commands used, and corrective action.

## Evidence to Capture

- GitHub Actions run URL
- Failed job name
- Artifact hash
- Trust score
- S3 object version
- CloudFront invalidation ID
- Screenshot of live report
