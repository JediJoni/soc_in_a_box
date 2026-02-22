from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="out/alerts.jsonl")
    ap.add_argument("--outdir", default="reports/cases")
    args = ap.parse_args()

    cases_path = Path(args.cases)
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    if not cases_path.exists():
        print(f"No alerts file found: {cases_path}. Run `make detect` first.")
        return

    alerts = []
    with cases_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                alerts.append(json.loads(line))

    if not alerts:
        print("No alerts to render.")
        return

    for i, a in enumerate(alerts, start=1):
        rule = a.get("rule_id", "rule")
        ts = a.get("timestamp", "unknown").replace(":", "").replace("/", "-")
        fname = f"CASE-{i:04d}_{rule}_{ts}.md"
        path = outdir / fname

        entities = a.get("entities", {})
        evidence = a.get("evidence", {})
        samples = evidence.get("samples", [])

        lines = []
        lines.append(f"# Case {i:04d}: {a.get('title', rule)}")
        lines.append("")
        lines.append("## Alert summary")
        lines.append(f"- **Rule:** `{rule}`")
        lines.append(f"- **Severity:** `{a.get('severity', 'unknown')}`")
        lines.append(f"- **First seen:** `{a.get('timestamp', 'unknown')}`")
        lines.append("")
        lines.append("## Entities")
        for k, v in entities.items():
            lines.append(f"- **{k}**: `{v}`")
        lines.append("")
        lines.append("## Evidence (samples)")
        lines.append("")
        lines.append("```json")
        for s in samples[:10]:
            lines.append(json.dumps(s, ensure_ascii=False))
        lines.append("```")
        lines.append("")
        lines.append("## Triage notes (starter)")
        lines.append("- Does the source process normally access this target on this host?")
        lines.append("- Is the user context expected (SYSTEM/NT AUTHORITY) for this activity?")
        lines.append("- Correlate with adjacent events: process creation (Sysmon 1), registry writes (Sysmon 13), network (5156).")
        lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")

    print(f"✅ Rendered {len(alerts)} case file(s) to {outdir}")


if __name__ == "__main__":
    main()