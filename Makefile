.PHONY: setup reset fmt lint test ingest detect report clean all verify

setup:
	@test -d .venv || uv venv
	uv pip install -e ".[dev]"

# Use this when you actually want a fresh environment
reset:
	rm -rf .venv
	uv venv
	uv pip install -e ".[dev]"

test: setup
	uv run pytest

ingest: setup
	uv run python -m socbox.ingest.download
	uv run python -m socbox.ingest.normalize_cli

detect: setup
	uv run python -m socbox.detect.engine --config configs/detections.yaml

report: setup
	uv run python -m socbox.report.render --cases out/alerts.jsonl

fmt: setup
	uv run ruff format .

lint: setup
	uv run ruff check .

verify:
	@test -f data/processed/events.parquet
	@test -f out/alerts.jsonl
	@echo "✅ Verified expected outputs exist"

clean:
	rm -rf .pytest_cache .ruff_cache out outputs

all: setup test ingest detect report