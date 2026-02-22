from pathlib import Path

RAW_DIR = Path("data/raw/mordor")


def main() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    print(f"✅ Created raw data folder: {RAW_DIR}")
    print("Next: download a Mordor dataset JSON/JSONL file and place it in this folder.")
    print("Example path: data/raw/mordor/sample.jsonl")


if __name__ == "__main__":
    main()