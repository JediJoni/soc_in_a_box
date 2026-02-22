import json
from pathlib import Path

import pandas as pd
import yaml

from socbox.ingest.parse_mordor import load_mordor_records
from socbox.ingest.normalize import normalize_mordor_event


def main() -> None:
    sources = yaml.safe_load(Path("configs/sources.yaml").read_text(encoding="utf-8"))
    mordor = sources.get("mordor", {})
    if not mordor.get("enabled", True):
        print("Mordor source disabled in configs/sources.yaml")
        return

    glob_pattern = mordor.get("path_glob", "data/raw/mordor/**/*.json")
    dataset_name = mordor.get("dataset_name", "mordor")

    records = load_mordor_records(glob_pattern)
    if not records:
        print(f"No records found for glob: {glob_pattern}")
        print("Add a dataset file under data/raw/mordor/ and try again.")
        return

    normalized = []
    for r in records:
        ev = normalize_mordor_event(r, dataset_name=dataset_name)
        if ev is not None:
            normalized.append(ev.to_dict())

    out_dir = Path("data/processed")
    out_dir.mkdir(parents=True, exist_ok=True)

    out_jsonl = out_dir / "events.jsonl"
    with out_jsonl.open("w", encoding="utf-8") as f:
        for row in normalized:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    df = pd.DataFrame(normalized)
    out_parquet = out_dir / "events.parquet"
    df.to_parquet(out_parquet, index=False)

    print(f"✅ Parsed raw records: {len(records)}")
    print(f"✅ Normalized events: {len(normalized)}")
    print(f"✅ Wrote: {out_jsonl}")
    print(f"✅ Wrote: {out_parquet}")


if __name__ == "__main__":
    main()