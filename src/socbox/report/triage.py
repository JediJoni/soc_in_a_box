"""
Triage helpers.

These utilities will turn alerts into investigation-friendly summaries:
- timelines
- entity pivots (by user/host/ip)
- evidence snippets
"""

from __future__ import annotations

from typing import Dict
import pandas as pd


def basic_context(df: pd.DataFrame, *, user: str | None = None, host: str | None = None, source_ip: str | None = None) -> Dict[str, object]:
    q = df
    if user:
        q = q[q["user.name"] == user]
    if host:
        q = q[q["host.name"] == host]
    if source_ip:
        q = q[q["source.ip"] == source_ip]

    return {
        "events_count": int(len(q)),
        "first_seen": None if q.empty else str(q["@timestamp"].min()),
        "last_seen": None if q.empty else str(q["@timestamp"].max()),
    }