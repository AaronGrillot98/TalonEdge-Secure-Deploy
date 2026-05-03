import html
from datetime import datetime, timezone
from pathlib import Path


def finding_rows(findings: list[dict]) -> str:
    if not findings:
        return "<tr><td colspan='3'>No findings detected.</td></tr>"
    rows = []
    for f in findings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(f['severity']).upper())}</td>"
            f"<td>{html.escape(str(f['control']))}</td>"
            f"<td>{html.escape(str(f['message']))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def component_rows(components: list[dict]) -> str:
    if not components:
        return "<tr><td colspan='2'>No components in attested SBOM.</td></tr>"
    rows = []
    for c in components:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(c.get('name', '')))}</td>"
            f"<td>{html.escape(str(c.get('version', '')))}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _verdict(ok: bool) -> str:
    return "<span style='color:#34d399'>VERIFIED</span>" if ok else "<span style='color:#f87171'>NOT VERIFIED</span>"


def write_html_report(result: dict, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    risk = result["risk"]
    artifact = result["artifact"]
    telemetry = result["telemetry"]
    sig = artifact.get("signature", {})
    sbom = artifact.get("sbom", {})
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    html_doc = f"""<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>TalonEdge Operator Report</title>
<style>
body {{ margin:0; font-family: Arial, sans-serif; background:#0d1117; color:#e6edf3; }}
.wrap {{ max-width:1050px; margin:0 auto; padding:28px; }}
.hero {{ border:1px solid #30363d; border-radius:22px; padding:26px; background:linear-gradient(135deg,#111827,#162033); }}
.grid {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(220px,1fr)); gap:16px; margin-top:18px; }}
.card {{ background:#161b22; border:1px solid #30363d; border-radius:18px; padding:18px; margin-top:18px; }}
.big {{ font-size:36px; font-weight:800; }}
.badge {{ display:inline-block; padding:6px 10px; border-radius:999px; border:1px solid #3b82f6; color:#bfdbfe; font-size:12px; letter-spacing:.04em; }}
table {{ width:100%; border-collapse:collapse; margin-top:14px; }}
th,td {{ border-bottom:1px solid #30363d; padding:12px; text-align:left; vertical-align: top; }}
th {{ color:#93c5fd; }}
.code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color:#a7f3d0; word-break:break-all; }}
.small {{ color:#9ca3af; font-size:14px; }}
.reason {{ color:#fca5a5; font-size:13px; }}
</style>
</head>
<body>
<div class='wrap'>
  <section class='hero'>
    <span class='badge'>SECURE EDGE DEPLOYMENT REPORT</span>
    <h1>TalonEdge Operator Report</h1>
    <p class='small'>Generated {generated}. Trust derives from Sigstore (Fulcio + Rekor) verification, not from manifest strings.</p>
    <div class='grid'>
      <div class='card'><div class='small'>Risk Level</div><div class='big'>{html.escape(str(risk['level']))}</div><p>{int(risk['score'])}/100</p></div>
      <div class='card'><div class='small'>Artifact Trusted</div><div class='big'>{str(artifact['trusted']).upper()}</div><p>{html.escape(str(artifact['name']))} v{html.escape(str(artifact['version']))}</p></div>
      <div class='card'><div class='small'>Edge Node</div><div class='big'>{html.escape(str(telemetry['node_id']))}</div><p>{html.escape(str(telemetry['network_status']))}</p></div>
    </div>
  </section>

  <section class='card'>
    <h2>Artifact Verification</h2>
    <p><strong>Hash check:</strong> {_verdict(artifact['hash_ok'])}</p>
    <p><strong>Expected SHA256:</strong> <span class='code'>{html.escape(str(artifact['expected_sha256']))}</span></p>
    <p><strong>Actual SHA256:</strong> <span class='code'>{html.escape(str(artifact['actual_sha256']))}</span></p>
    <p><strong>Sigstore signature:</strong> {_verdict(sig.get('verified', False))}</p>
    <p class='reason'>{html.escape(str(sig.get('reason', '')))}</p>
    <p><strong>SBOM attestation:</strong> {_verdict(sbom.get('verified', False))} <span class='small'>({html.escape(str(sbom.get('predicate_type', 'n/a')))})</span></p>
    <p class='reason'>{html.escape(str(sbom.get('reason', '')))}</p>
    <p><strong>Identity:</strong> <span class='code'>{html.escape(str(sig.get('identity', 'n/a')))}</span></p>
    <p><strong>OIDC issuer:</strong> <span class='code'>{html.escape(str(sig.get('issuer', 'n/a')))}</span></p>
  </section>

  <section class='card'>
    <h2>Attested SBOM Components</h2>
    <table><thead><tr><th>Name</th><th>Version</th></tr></thead><tbody>{component_rows(artifact.get('components', []))}</tbody></table>
  </section>

  <section class='card'>
    <h2>Policy Findings</h2>
    <table><thead><tr><th>Severity</th><th>Control</th><th>Message</th></tr></thead><tbody>{finding_rows(result['findings'])}</tbody></table>
  </section>

  <section class='card'>
    <h2>Operator Notes</h2>
    <p>This project models secure deployment behavior for disconnected or degraded edge environments: verify what you deploy, keep telemetry flowing, enforce policy, and report risk clearly.</p>
  </section>
</div>
</body>
</html>"""
    out_path.write_text(html_doc, encoding="utf-8")
    return out_path
