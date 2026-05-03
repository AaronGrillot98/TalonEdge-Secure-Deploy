# TalonEdge Interview Talk Track

## 30-second version

I built TalonEdge as a secure edge deployment lab aimed at defense-style SecDevOps work. It verifies deployment artifacts, checks a policy-as-code file, handles offline telemetry, scores operational risk, and produces an operator report. I added Docker, GitHub Actions, Terraform scaffolding, and Kubernetes manifests to show I understand the path from code to deployed system.

## Why it matters

Forward-deployed systems often operate with degraded networks and high trust requirements. The project focuses on the questions a real operator cares about: can I trust this artifact, is the node healthy, what is the risk, and what should I fix first?

## What I would improve next

1. Add real artifact signing with Sigstore Cosign.
2. Generate a real SBOM with Syft.
3. Deploy the report to AWS with Terraform.
4. Add OpenTelemetry metrics and a Grafana dashboard.
5. Add STIG-style compliance checks.
