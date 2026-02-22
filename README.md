# SOC Analyst in a Box

A defensive security analytics portfolio project that mirrors SOC work end-to-end:

**logs → normalization → detections → triage writeups**

This repo focuses on *defensive* engineering & investigation. It intentionally avoids offensive tooling or exploit PoCs.

## What this repo will contain (WIP)

- **Ingest + normalize** security logs into a consistent schema (JSONL/Parquet)
- **Detections** (rule-based) for common SOC patterns
- **Case reports**: alert → investigation steps → evidence → conclusion
- **Repeatable workflow** via simple commands:
  - `make setup`
  - `make ingest`
  - `make detect`
  - `make report`
  - `make test`

## Quickstart (will work once deps + scripts are added)

```bash
make setup
make ingest
make detect
make report
````

## MVP detections (planned)

* Brute force authentication
  *N failures from same source IP to same user/host within T minutes*
* Rapid IP change / “impossible travel”-style behaviour
  *(initially without geo; later add ASN/country enrichment)*
* Suspicious PowerShell command patterns
  *(encoded commands, unusual flags, download cradles)*
* Beaconing-ish periodic connections (conservative)
  *(repeated connections at near-regular intervals; not “C2 confirmed”)*

## Repository structure

```text
soc_in_a_box/
  README.md
  pyproject.toml
  Makefile

  data/
    raw/               # ignored (gitignored)
    processed/         # ignored (gitignored)
    samples/           # small committed samples only

  configs/
    sources.yaml       # dataset sources + formats
    schema.yaml        # canonical event schema
    detections.yaml    # which detections are enabled + thresholds

  src/socbox/
    __init__.py
    ingest/
      download.py
      parse_mordor.py
      normalize.py
    detect/
      rules.py
      engine.py
    report/
      triage.py
      render.py

  reports/
    cases/             # human-readable investigations (markdown)

  tests/
    test_normalize.py
    test_rules.py
    test_engine.py

  .github/workflows/
    tests.yml
```

## Design choices (why this looks like real SOC work)

* Use a **canonical schema** so detections aren’t tied to one dataset format
* Prefer **explainable detections** + clear triage steps over “black box” claims
* Produce readable **case reports** that recruiters can skim quickly

## Next milestones

1. Normalize Mordor JSON into the canonical schema + write Parquet
2. Add 2–4 detections + output `alerts.jsonl`
3. Generate 2–3 case reports in `reports/cases/`
4. Add tests + GitHub Actions CI