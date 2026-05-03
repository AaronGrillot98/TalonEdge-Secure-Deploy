# TalonEdge Secure Deploy

**Forward-deployed secure edge platform for a defense-style SecDevOps portfolio.**

TalonEdge is a master flagship project that combines three ideas into one recruiter-ready system:

- **AeroSentinel:** edge telemetry, operator risk reports, and security findings.
- **FieldDeploy-Kit:** deployment workflow, runbooks, Docker, Terraform, and degraded-network thinking.
- **Artifact Trust Inspector:** artifact hash verification, manifest validation, SBOM presence, and trust scoring.

## 30-second explanation

TalonEdge simulates how a small forward-deployed team could validate software before it reaches edge systems, inspect telemetry from remote nodes, detect risky conditions, and publish a trusted operator report through a real AWS deployment pipeline.

This is designed for SecDevOps, cloud security, and forward-deployed engineering conversations.

## What it demonstrates

- Python security automation
- Artifact trust inspection
- Edge telemetry analysis
- Policy-based findings
- Offline/degraded-network handling
- Dockerized runtime
- GitHub Actions CI/CD
- Terraform infrastructure as code
- AWS S3 and CloudFront deployment
- Operator runbooks and incident response documentation

## Architecture

```txt
Edge Node Telemetry + Artifact Manifest
        |
        v
TalonEdge Python CLI
        |
        | verifies artifact hash, signature status, SBOM, node policy
        v
Operator HTML Report
        |
        v
GitHub Actions CI/CD
        |
        | OIDC assume role, no long-term AWS keys
        v
Private AWS S3 Bucket
        |
        v
CloudFront HTTPS Demo URL
```

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -e .
python -m pip install -r requirements-dev.txt
python -m pytest tests
python -m talonedge demo
```

Generate the AWS-ready report:

```bash
mkdir -p reports
python -m talonedge simulate --output reports/index.html
```

Open:

```txt
reports/index.html
```

## Docker

```bash
docker build -t talonedge-secure-deploy .
docker run --rm talonedge-secure-deploy
```

## AWS deployment

The real deployment path uses:

- Terraform
- AWS S3
- AWS CloudFront
- AWS IAM OIDC for GitHub Actions
- GitHub Actions repository variables

Start here:

```txt
docs/TalonEdge_AWS_Implementation_Guide.html
```

Terraform files are located here:

```txt
infra/aws/
```

GitHub Actions deployment workflow:

```txt
.github/workflows/deploy-aws.yml
```

## Screenshots to capture

1. Local CLI scan running
2. Docker build/run success
3. Terraform apply outputs
4. GitHub Actions successful deployment
5. Live CloudFront report
6. README architecture section

## Interview talk track

> I built TalonEdge as a forward-deployed secure edge platform simulation. The goal was to show that I understand more than cybersecurity theory. The project demonstrates how an operator could validate telemetry, inspect deployment artifacts, handle limited connectivity, and publish trusted operational reports through a real CI/CD pipeline.

> The deployment uses GitHub Actions, Docker, Terraform, AWS S3, CloudFront, and IAM OIDC. I avoided long-term AWS keys and scoped the GitHub role to the main branch of this specific repo.

> The project is intentionally small but realistic. It proves I can build, document, deploy, and explain a secure system end to end.

## Important note

This is a portfolio simulation. It does not connect to real military systems, classified systems, or production operational technology.
