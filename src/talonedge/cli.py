import argparse
from pathlib import Path

from .artifact import TrustPolicy, verify_artifact
from .offline_queue import OfflineQueue
from .policy import evaluate_policy, load_policy
from .report import write_html_report
from .risk import score_findings
from .telemetry import create_sample_telemetry, load_telemetry

ROOT = Path.cwd()


def _build_policy(args) -> TrustPolicy | None:
    if getattr(args, "identity", None) and getattr(args, "issuer", None):
        return TrustPolicy(identity=args.identity, issuer=args.issuer)
    return None


def run_scan(policy: TrustPolicy | None) -> dict:
    edge_policy = load_policy(ROOT / "policies" / "edge_policy.yml")
    telemetry = load_telemetry(ROOT / "telemetry" / "sample_telemetry.json")
    artifact_result = verify_artifact(
        ROOT / "artifacts" / "sample_payload.txt",
        ROOT / "artifacts" / "sample_artifact_manifest.json",
        policy=policy,
    )
    findings = evaluate_policy(edge_policy, telemetry, artifact_result)
    risk = score_findings(findings)
    return {
        "artifact": artifact_result,
        "telemetry": telemetry,
        "findings": findings,
        "risk": risk,
    }


def _print_summary(result: dict) -> None:
    artifact = result["artifact"]
    provenance = artifact.get("provenance", {})
    print(f"Artifact trusted: {artifact['trusted']}  (SLSA L3: {artifact.get('slsa_build_l3', False)})")
    print(f"  hash_ok:    {artifact['hash_ok']}  (expected={artifact['expected_sha256']} actual={artifact['actual_sha256']})")
    print(f"  signature:  {artifact['signature']['verified']}  ({artifact['signature']['reason']})")
    print(f"  sbom:       {artifact['sbom']['verified']}  ({artifact['sbom']['reason']})")
    print(f"  provenance: {provenance.get('verified', False)}  ({provenance.get('reason', 'not configured')})")
    print(f"Risk level: {result['risk']['level']} ({result['risk']['score']}/100)")
    if result["findings"]:
        print("Findings:")
        for finding in result["findings"]:
            print(f"- [{finding['severity']}] {finding['control']}: {finding['message']}")
    else:
        print("No findings")


def cmd_demo(args):
    create_sample_telemetry(ROOT / "telemetry" / "sample_telemetry.json")
    result = run_scan(_build_policy(args))
    out = write_html_report(result, ROOT / "dist" / "talonedge_report.html")
    print("TalonEdge demo complete")
    _print_summary(result)
    print(f"Report written to: {out}")


def cmd_scan(args):
    result = run_scan(_build_policy(args))
    print("TalonEdge scan results")
    _print_summary(result)


def cmd_report(args):
    result = run_scan(_build_policy(args))
    output = Path(args.output) if args.output else ROOT / "dist" / "talonedge_report.html"
    out = write_html_report(result, output)
    print(f"Report written to: {out}")


def cmd_simulate(args):
    create_sample_telemetry(ROOT / "telemetry" / "sample_telemetry.json")
    result = run_scan(_build_policy(args))
    output = Path(args.output) if args.output else ROOT / "reports" / "index.html"
    out = write_html_report(result, output)
    print("TalonEdge forward-deployed simulation complete")
    _print_summary(result)
    print(f"Report written to: {out}")


def cmd_queue_demo(args):
    queue = OfflineQueue(ROOT / "dist" / "offline_queue.jsonl")
    queue.enqueue({"node": "edge-node-01", "event": "link_down", "severity": "medium"})
    queue.enqueue({"node": "edge-node-01", "event": "telemetry_cached", "severity": "low"})
    flushed = queue.flush()
    print(f"Queued and flushed {len(flushed)} offline events")


def cmd_verify(args):
    policy = _build_policy(args)
    result = verify_artifact(Path(args.payload), Path(args.manifest), policy=policy)
    _print_summary({"artifact": result, "risk": {"level": "n/a", "score": 0}, "findings": []})
    raise SystemExit(0 if result["trusted"] else 1)


def _add_trust_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--identity",
        default=None,
        help="Expected signing identity (Fulcio cert SAN). Overrides manifest expected_identity.",
    )
    parser.add_argument(
        "--issuer",
        default=None,
        help="Expected OIDC issuer. Overrides manifest expected_issuer.",
    )


def main():
    parser = argparse.ArgumentParser(description="TalonEdge Secure Deploy Platform")
    sub = parser.add_subparsers(dest="command", required=True)

    demo_parser = sub.add_parser("demo")
    _add_trust_args(demo_parser)

    scan_parser = sub.add_parser("scan")
    _add_trust_args(scan_parser)

    report_parser = sub.add_parser("report")
    report_parser.add_argument("--output", default=None, help="HTML report output path")
    _add_trust_args(report_parser)

    simulate_parser = sub.add_parser("simulate")
    simulate_parser.add_argument(
        "--output",
        default=None,
        help="HTML report output path, normally reports/index.html for AWS",
    )
    _add_trust_args(simulate_parser)

    sub.add_parser("queue-demo")

    verify_parser = sub.add_parser("verify", help="Verify an artifact and exit non-zero if not trusted")
    verify_parser.add_argument("--payload", required=True)
    verify_parser.add_argument("--manifest", required=True)
    _add_trust_args(verify_parser)

    args = parser.parse_args()
    {
        "demo": cmd_demo,
        "scan": cmd_scan,
        "report": cmd_report,
        "simulate": cmd_simulate,
        "queue-demo": cmd_queue_demo,
        "verify": cmd_verify,
    }[args.command](args)


if __name__ == "__main__":
    main()
