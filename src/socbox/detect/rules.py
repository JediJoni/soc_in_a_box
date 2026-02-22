"""
Detection rules (rule-based, explainable).

Each rule takes a pandas DataFrame of normalized events and returns
a list of alerts (dicts) suitable for writing to alerts.jsonl.
"""

from __future__ import annotations

from dataclasses import dataclass
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


def brute_force_auth(df: pd.DataFrame, *, window_minutes: int, failures_threshold: int) -> List[Dict[str, Any]]:
    """
    Placeholder: implement next.
    Expected fields: @timestamp, event.category, event.action, event.outcome, user.name, source.ip, host.name
    """
    return []