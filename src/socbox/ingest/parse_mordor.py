import json
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List


def iter_json_records(path: Path) -> Iterator[Dict[str, Any]]:
    """
    Yield JSON objects from either:
      - a JSONL file (one JSON object per line), or
      - a JSON file containing a list of objects, or
      - a JSON file containing a single object.
    """
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not text:
        return

    # Try JSONL first (common for logs)
    if "\n" in text:
        ok_jsonl = True
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                ok_jsonl = False
                break
            if isinstance(obj, dict):
                yield obj
        if ok_jsonl:
            return

    # Fallback: standard JSON
    obj = json.loads(text)
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                yield item
    elif isinstance(obj, dict):
        yield obj


def load_mordor_records(glob_pattern: str) -> List[Dict[str, Any]]:
    paths = [p for p in sorted(Path(".").glob(glob_pattern)) if p.suffix in {".json", ".jsonl"}]
    records: List[Dict[str, Any]] = []
    for p in paths:
        records.extend(list(iter_json_records(p)))
    return records