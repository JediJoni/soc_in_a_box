# SOC Analyst in a Box

A defensive security analytics portfolio project that mirrors SOC work end-to-end:

**logs → normalization → detections → triage writeups**

This repo focuses on *defensive* engineering & investigation. It intentionally avoids offensive tooling or exploit PoCs.

---

## What this repo contains today

* Example investigation: reports/cases/CASE-0001_...md

✅ **Working ingest + normalization pipeline**  
- Parses Mordor-style Security-Datasets JSON/JSONL
- Normalizes into a small canonical schema
- Writes:
  - `data/processed/events.jsonl` (easy to inspect)
  - `data/processed/events.parquet` (fast for analytics/detections)

✅ **Tests + CI foundations**  
- `pytest` smoke + normalization tests
- GitHub Actions runs lint/test

---

## Quickstart

```bash
make setup
make test
make ingest
```

Outputs:

* `data/processed/events.jsonl`
* `data/processed/events.parquet`

---

## Dataset: current run (reproducible)

This repo currently uses an OTRF **Security-Datasets** “Mordor-style” dataset for Windows lateral movement:

* **Scenario:** Empire Invoke PsExec (lateral movement)
* **Notebook:** `SDWIN-190518210652`
* **Host logs zip:**

  * `datasets/atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip`

Reproduce the exact run:

```bash
cd data/raw/mordor
curl -L "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip" -o dataset.zip
unzip -o dataset.zip
rm dataset.zip

cd ../../..
make ingest
```

Attribution: dataset provenance and scenario context are documented by the Threat Hunter Playbook / Security-Datasets notebook.

---

## Sanity checks (recommended)

```bash
# count normalized events
wc -l data/processed/events.jsonl

# show top categories
uv run python - << 'PY'
import pandas as pd
df = pd.read_parquet("data/processed/events.parquet")
print(df["event.category"].value_counts(dropna=False).head(10))
PY
```

---

## Note on normalization coverage (why some fields may be null)

Security-Datasets/Mordor files are not perfectly uniform across scenarios.
The current normalizer is intentionally conservative and maps a small set of common field paths.

For the current dataset, some high-value attributes exist under alternative keys (e.g. `Hostname`, `AccountName`, `SourceImage`) so certain normalized fields may appear as `null` until additional mappings are enabled.

**Next improvement:** expand mappings for Sysmon-style records so `host.name`, `user.name`, and `process.*` populate more consistently.

---

## Planned detections (MVP)

* **Brute force authentication**
  *N failures from same source IP to same user/host within T minutes*
* **Rapid IP change / “impossible travel”-style behaviour**
  *(initially without geo; later add ASN/country enrichment)*
* **Suspicious PowerShell command patterns**
  *(encoded commands, unusual flags, download cradles)*
* **Beaconing-ish periodic connections (conservative)**
  *(repeated connections at near-regular intervals; not “C2 confirmed”)*

---

## Repository structure

```text
soc_in_a_box/
  README.md
  pyproject.toml
  Makefile

  data/
    raw/               # ignored (gitignored)
    processed/         # ignored (gitignored)
    samples/           # tiny committed samples only

  configs/
    sources.yaml       # dataset sources + formats
    schema.yaml        # canonical event schema
    detections.yaml    # enabled detections + thresholds (coming next)

  src/socbox/
    __init__.py
    ingest/
      download.py
      parse_mordor.py
      normalize.py
      normalize_cli.py
    detect/
      rules.py         # TODO
      engine.py        # TODO
    report/
      triage.py        # TODO
      render.py        # TODO

  reports/
    cases/             # TODO: investigation writeups (markdown)

  tests/
    test_smoke.py
    test_normalize.py
    test_rules.py      # TODO
    test_engine.py     # TODO

  .github/workflows/
    tests.yml
```

---

## Design choices (why this looks like real SOC work)

* Use a **canonical schema** so detections aren’t tied to one dataset format
* Prefer **explainable detections** + clear triage steps over “black box” claims
* Produce readable **case reports** that recruiters can skim quickly

---

## Next milestones

1. Improve normalization mappings for Sysmon-style records (host/user/process extraction)
2. Add 2–4 detections + output `alerts.jsonl`
3. Generate 2–3 case reports in `reports/cases/`
4. Expand tests (`rules`, `engine`) + keep CI green