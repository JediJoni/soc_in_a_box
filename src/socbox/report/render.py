from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def _parse_ts(ts: str) -> Optional[datetime]:
    # Handles strings like "2020-09-20T16:17:03.996000+00:00"
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def _time_window(samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    ts_list: List[datetime] = []
    for s in samples:
        t = s.get("@timestamp")
        if isinstance(t, str):
            dt = _parse_ts(t)
            if dt:
                ts_list.append(dt)

    if not ts_list:
        return {"first_seen": None, "last_seen": None, "duration_seconds": None}

    first = min(ts_list)
    last = max(ts_list)
    return {
        "first_seen": first.isoformat(),
        "last_seen": last.isoformat(),
        "duration_seconds": int((last - first).total_seconds()),
    }


def _markdown_table(rows: List[List[str]], headers: List[str]) -> List[str]:
    lines = []
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
    for r in rows:
        lines.append("| " + " | ".join(r) + " |")
    return lines


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

    alerts: List[Dict[str, Any]] = []
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
        ts = str(a.get("timestamp", "unknown")).replace(":", "").replace("/", "-")
        fname = f"CASE-{i:04d}_{rule}_{ts}.md"
        path = outdir / fname

        entities = a.get("entities", {})
        evidence = a.get("evidence", {})
        samples = evidence.get("samples", []) or []

        # --- New: time window + granted_access distribution ---
        tw = _time_window(samples)

        access_values = []
        for s in samples:
            v = s.get("process.granted_access")
            if v is None:
                v = "null"
            access_values.append(str(v))
        access_counts = Counter(access_values)
        access_rows = [[k, str(access_counts[k])] for k in sorted(access_counts.keys())]

        lines: List[str] = []
        lines.append(f"# Case {i:04d}: {a.get('title', rule)}")
        lines.append("")
        lines.append("## Alert summary")
        lines.append(f"- **Rule:** `{rule}`")
        lines.append(f"- **Severity:** `{a.get('severity', 'unknown')}`")
        lines.append(f"- **First seen (alert):** `{a.get('timestamp', 'unknown')}`")
        lines.append("")

        # --- New: time window section ---
        lines.append("## Time window (from evidence samples)")
        if tw["first_seen"] is None:
            lines.append("- No parsable timestamps found in samples.")
        else:
            lines.append(f"- **First seen (samples):** `{tw['first_seen']}`")
            lines.append(f"- **Last seen (samples):** `{tw['last_seen']}`")
            lines.append(f"- **Duration:** `{tw['duration_seconds']}s`")
        lines.append("")

        lines.append("## Entities")
        for k, v in entities.items():
            lines.append(f"- **{k}**: `{v}`")
        lines.append("")

        # --- New: mini table of granted_access counts ---
        lines.append("## Evidence summary")
        lines.append("")
        lines.append(f"- **Sample count:** `{len(samples)}`")
        lines.append("")
        lines.append("### process.granted_access counts (samples)")
        lines.append("")
        if access_rows:
            lines.extend(_markdown_table(access_rows, headers=["granted_access", "count"]))
        else:
            lines.append("- No `process.granted_access` values found in samples.")
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