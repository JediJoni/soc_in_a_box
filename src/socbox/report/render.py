"""
Render investigation case reports from alerts.

For now this is a placeholder. Next step: implement a minimal renderer that
turns each alert into a Markdown file under reports/cases/.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="out/alerts.jsonl")
    ap.add_argument("--outdir", default="reports/cases")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # Placeholder: we will implement this after the first real detection exists.
    print(f"✅ Report output folder ready: {outdir}")
    print("Next: implement Markdown report generation once alerts exist.")


if __name__ == "__main__":
    main()