# Px-Adaptive H2 experiment

Executable reconstruction and extension of Namsey et al.'s adaptive hybrid insider-threat experiment. The study tests whether hybrid anomaly/rule ranking adds value over a tuned rules-only comparator.

The authoritative protocol is [docs/experiment-protocol.md](docs/experiment-protocol.md). Reconstruction choices and the preregistration grid are machine-readable in [configs/full.json](configs/full.json).

## Quick start

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/python -m pytest -q
.venv/bin/python -m pxadaptive smoke --config configs/smoke.json --output runs/smoke
```

For a full run, prepare `logon.csv`, `http.csv`, `device.csv`, and a versioned `labels.csv` containing `user,date,scenario`:

```bash
.venv/bin/python -m pxadaptive run \
  --config configs/full.json \
  --data /path/to/cert-r4.2 \
  --output runs/r4.2-s1
```

Every run writes `manifest.json` with configuration provenance and `metrics.csv` in a tidy schema. Full results are not directly comparable with P2 unless the manifest confirms scenario 1, P2's temporal split, exclusions, and model-selected alert pool.
