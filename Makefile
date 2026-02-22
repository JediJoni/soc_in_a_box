.PHONY: setup fmt lint test ingest detect report clean

PYTHON := .venv/bin/python

setup:
	uv venv --clear
	uv pip install -e ".[dev]"

fmt:
	uv run ruff format .

lint:
	uv run ruff check .

test:
	uv run pytest

ingest:
	uv run python -m socbox.ingest.download
	uv run python -m socbox.ingest.normalize_cli

detect:
	uv run python -m socbox.detect.engine --config configs/detections.yaml

report:
	uv run python -m socbox.report.render --cases out/alerts.jsonl

clean:
	rm -rf .venv .pytest_cache .ruff_cache out outputs