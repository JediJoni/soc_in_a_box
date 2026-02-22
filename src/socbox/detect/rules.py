"""
Detection rules (rule-based, explainable).

Each rule takes a pandas DataFrame of normalized events and returns
a list of alerts (dicts) suitable for writing to alerts.jsonl.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Any, Dict, List

import pandas as pd


@dataclass(frozen=True)
class Alert:
    rule_id: str
    severity: str
    title: str
    timestamp: str
    entities: Dict[str, Any]
    evidence: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "timestamp": self.timestamp,
            "entities": self.entities,
            "evidence": self.evidence,
        }


def _win_basename(path: str | None) -> str | None:
    if not path:
        return None
    try:
        return PureWindowsPath(path).name.lower()
    except Exception:
        return path.split("\\")[-1].lower()


def suspicious_process_access(
    df: pd.DataFrame, *, target_processes: List[str], min_events: int = 1
) -> List[Dict[str, Any]]:
    """
    Detect Sysmon Event ID 10 (ProcessAccess) where a source process accesses a sensitive target process.

    Requires (normalized):
      - event.action == "10"
      - process.name (source image)
      - process.target (target image)
      - host.name, user.name
      - @timestamp
    """
    if df.empty:
        return []

    required_cols = {"@timestamp", "event.action", "process.name", "process.target", "host.name", "user.name"}
    missing = required_cols - set(df.columns)
    if missing:
        # If schema isn't there yet, don't crash—return no alerts.
        return []

    d10 = df[df["event.action"].astype(str) == "10"].copy()
    if d10.empty:
        return []

    # Normalize target process comparison: look for endings like "\lsass.exe"
    target_processes_lc = [t.lower() for t in target_processes]

    def matches_sensitive_target(x: Any) -> bool:
        if x is None or (isinstance(x, float) and pd.isna(x)):
            return False
        s = str(x).lower()
        return any(s.endswith(tp) for tp in target_processes_lc)

    hits = d10[d10["process.target"].apply(matches_sensitive_target)]
    if hits.empty:
        return []

    # Group into alert “entities”
    group_cols = ["host.name", "user.name", "process.name", "process.target"]
    alerts: List[Dict[str, Any]] = []
    for keys, g in hits.groupby(group_cols):
        if len(g) < min_events:
            continue

        host, user, source_proc, target_proc = keys
        g_sorted = g.sort_values("@timestamp")
        first_ts = str(g_sorted["@timestamp"].iloc[0])

        sample = g_sorted[["@timestamp", "process.name", "process.target", "process.granted_access"]].head(10).to_dict(
            orient="records"
        )

        alerts.append(
            Alert(
                rule_id="suspicious_process_access",
                severity="high",
                title="Suspicious ProcessAccess to sensitive target process",
                timestamp=first_ts,
                entities={
                    "host": host,
                    "user": user,
                    "source_process": source_proc,
                    "target_process": target_proc,
                },
                evidence={
                    "count": int(len(g_sorted)),
                    "samples": sample,
                },
            ).to_dict()
        )

    return alerts


def powershell_suspicious_keywords(
    df: pd.DataFrame,
    *,
    event_ids: List[str],
    keywords: List[str],
    min_keyword_hits: int = 1,
    max_samples: int = 10,
) -> List[Dict[str, Any]]:
    """
    Detect PowerShell Operational events (e.g., 4103) containing suspicious keywords.
    This is triage-oriented: it flags content worth human review, not 'confirmed malicious'.
    """
    if df.empty:
        return []

    required_cols = {"@timestamp", "event.action", "host.name", "user.name", "message"}
    missing = required_cols - set(df.columns)
    if missing:
        return []

    ids = {str(x) for x in event_ids}
    ps = df[df["event.action"].astype(str).isin(ids)].copy()
    if ps.empty:
        return []

    kw = [k.lower() for k in keywords]

    def count_hits(msg: Any) -> int:
        if msg is None or (isinstance(msg, float) and pd.isna(msg)):
            return 0
        s = str(msg).lower()
        return sum(1 for k in kw if k in s)

    ps["keyword_hits"] = ps["message"].apply(count_hits)
    hits = ps[ps["keyword_hits"] >= int(min_keyword_hits)]
    if hits.empty:
        return []

    alerts: List[Dict[str, Any]] = []
    group_cols = ["host.name", "user.name"]
    for (host, user), g in hits.groupby(group_cols):
        g_sorted = g.sort_values("@timestamp")
        first_ts = str(g_sorted["@timestamp"].iloc[0])

        sample_rows = (
            g_sorted[["@timestamp", "event.action", "keyword_hits", "message"]]
            .head(int(max_samples))
            .to_dict(orient="records")
        )

        top_keywords = []
        joined = " ".join(str(x).lower() for x in g_sorted["message"].dropna().head(50).tolist())
        for k in kw:
            if k in joined:
                top_keywords.append(k)
        top_keywords = top_keywords[:10]

        alerts.append(
            Alert(
                rule_id="powershell_suspicious_keywords",
                severity="medium",
                title="PowerShell event contains suspicious triage keywords",
                timestamp=first_ts,
                entities={"host": host, "user": user},
                evidence={
                    "count": int(len(g_sorted)),
                    "top_keywords": top_keywords,
                    "samples": sample_rows,
                },
            ).to_dict()
        )

    return alerts