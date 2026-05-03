# Operator Failure Scenarios

## Scenario 1: Network Drop

A forward-deployed edge node loses connection during telemetry upload. TalonEdge stores telemetry locally, marks it as unsynced, and retries when connectivity returns. This demonstrates denied, degraded, intermittent, and limited network thinking.

## Scenario 2: Authentication Failure

A deployment token or role assumption fails. The deployment pipeline stops immediately and does not upload partial or untrusted artifacts. This prevents unauthorized deployment from reaching the operational environment.

## Scenario 3: Suspected Compromise

The artifact trust score falls below the accepted threshold. The system blocks deployment, logs the reason, and creates an operator-facing finding.

## Scenario 4: Recovery

A failed deployment needs to be restored. S3 versioning allows earlier report versions to be recovered. GitHub Actions logs show exactly when the failure occurred.
