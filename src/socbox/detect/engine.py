"""
Detection engine: loads normalized events + runs enabled rules from configs/detections.yaml.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd
import yaml

from socbox.detect import rules


def load_events_parquet(path: Path) -> pd.DataFrame:
    return pd.read_parquet(path)


def run(df: pd.DataFrame, config: Dict[str, Any]) -> List[Dict[str, Any]]:
    enabled = config.get("enabled", [])
    params = config.get("parameters", {})

    alerts: List[Dict[str, Any]] = []
    for rule_id in enabled:
        if rule_id == "brute_force_auth":
            p = params.get("brute_force_auth", {})
            alerts.extend(
                rules.brute_force_auth(
                    df,
                    window_minutes=int(p.get("window_minutes", 10)),
                    failures_threshold=int(p.get("failures_threshold", 8)),
                )
            )
        else:
            raise ValueError(f"Unknown rule_id: {rule_id}")

    return alerts


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/detections.yaml")
    ap.add_argument("--events", default="data/processed/events.parquet")
    ap.add_argument("--out", default="out/alerts.jsonl")
    args = ap.parse_args()

    config = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    df = load_events_parquet(Path(args.events))

    alerts = run(df, config)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a, ensure_ascii=False) + "\n")

    print(f"✅ Loaded events: {len(df)}")
    print(f"✅ Alerts written: {len(alerts)} -> {out_path}")


if __name__ == "__main__":
    main()