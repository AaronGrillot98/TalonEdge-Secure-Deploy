# Bug Sweep Report

## Date
April 30, 2026

## Scope
This sweep checked the TalonEdge V2 package after combining the AeroSentinel, FieldDeploy-Kit, and Artifact Trust Inspector concepts into one AWS-ready flagship repo.

## Checks Completed

- Confirmed Python package entry point works with `python -m talonedge`.
- Added `simulate --output` command so GitHub Actions can generate `reports/index.html` cleanly.
- Added `pyproject.toml` so the project can be installed with `python -m pip install -e .`.
- Added `requirements-dev.txt` for pytest in CI.
- Updated Dockerfile to install the package before running it.
- Added AWS Terraform files under `infra/aws/`.
- Added GitHub Actions AWS deployment workflow using OIDC instead of long-term AWS keys.
- Added operator failure scenarios and incident response runbook.
- Added master project map explaining how the smaller project ideas combine.
- Added beginner-friendly AWS HTML guide with screenshot timing.
- Generated a sample `reports/index.html` report successfully.

## Local Test Results

Commands run:

```bash
PYTHONPATH=src /usr/bin/python3 -m unittest discover -s tests -v
PYTHONPATH=src /usr/bin/python3 -m talonedge simulate --output reports/index.html
/usr/bin/python3 -m compileall src tests
```

Result:

```txt
2 unit tests passed.
Report generated successfully at reports/index.html.
Python files compiled successfully.
```

## Not Executed In This Environment

These checks require your machine or cloud account:

- `terraform init`
- `terraform plan`
- `terraform apply`
- Docker build/run
- Real GitHub Actions deployment
- Real AWS CloudFront URL verification

## Notes

The project is ready for you to upload to GitHub and connect to real AWS. The AWS deployment is intentionally small and focused so it demonstrates real SecDevOps skills without overengineering the portfolio project.
