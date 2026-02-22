import json
from pathlib import Path

import pandas as pd
import yaml

from socbox.ingest.parse_mordor import load_mordor_records
from socbox.ingest.normalize import normalize_mordor_event


def main() -> None:

    cfg = yaml.safe_load(Path("configs/sources.yaml").read_text(encoding="utf-8"))
    active = cfg.get("active_sources", ["mordor"])
    sources = cfg.get("sources", {})

    all_records = []
    for source_id in active:
        src = sources.get(source_id, {})
        glob_pattern = src.get("path_glob")
        dataset_name = src.get("dataset_name", source_id)

        if not glob_pattern:
            print(f"Skipping {source_id}: no path_glob configured")
            continue

        records = load_mordor_records(glob_pattern)
        if records:
            # Tag dataset name into normalization via dataset_name passed later
            all_records.append((dataset_name, records))

    if not all_records:
        print(f"No records found for active_sources={active}")
        print("Add a dataset under data/raw/mordor/ OR enable the sample source.")
        return

    normalized = []
    raw_count = 0
    for dataset_name, records in all_records:
        raw_count += len(records)
        for r in records:
            ev = normalize_mordor_event(r, dataset_name=dataset_name)
            if ev is not None:
                normalized.append(ev.to_dict())

    # Build DataFrame once
    df = pd.DataFrame(normalized)

    # Deterministic ordering for both outputs (only if columns exist)
    if not df.empty and "@timestamp" in df.columns:
        sort_cols = ["@timestamp"]
        for extra in ["event.dataset", "event.action"]:
            if extra in df.columns:
                sort_cols.append(extra)
        df = df.sort_values(sort_cols, kind="mergesort")

    out_dir = Path("data/processed")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Write JSONL from the DataFrame so it matches parquet ordering
    out_jsonl = out_dir / "events.jsonl"
    with out_jsonl.open("w", encoding="utf-8") as f:
        for row in df.to_dict(orient="records"):
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    # Write parquet from the same DataFrame
    out_parquet = out_dir / "events.parquet"
    df.to_parquet(out_parquet, index=False)

    print(f"✅ Parsed raw records: {raw_count}")
    print(f"✅ Normalized events: {len(normalized)}")
    print(f"✅ Wrote: {out_jsonl}")
    print(f"✅ Wrote: {out_parquet}")


if __name__ == "__main__":
    main()