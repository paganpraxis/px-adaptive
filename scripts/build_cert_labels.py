#!/usr/bin/env python3
"""Build user-day labels from official CERT detailed observable answer files."""
import argparse
import csv
import hashlib
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


DATE_FORMATS = ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M")


def parse_timestamp(value):
    for date_format in DATE_FORMATS:
        try:
            return datetime.strptime(value, date_format)
        except ValueError:
            continue
    raise ValueError(f"unsupported CERT timestamp: {value!r}")


def build_labels(answers: Path, release: str):
    labels = defaultdict(lambda: {"event_types": set(), "source_details": set()})
    for scenario in (1, 2, 3):
        directory = answers / f"r{release}-{scenario}"
        if not directory.is_dir():
            raise ValueError(f"missing detailed answer directory: {directory}")
        for detail in sorted(directory.glob("*.csv")):
            incident_user = detail.stem.rsplit("-", 1)[-1]
            with detail.open(newline="", errors="strict") as handle:
                for line_number, row in enumerate(csv.reader(handle), 1):
                    if len(row) < 4:
                        raise ValueError(f"{detail}:{line_number}: expected at least four fields")
                    event_type, timestamp_text, user = row[0].lower(), row[2], row[3]
                    if user != incident_user:
                        continue
                    timestamp = parse_timestamp(timestamp_text)
                    key = (user, timestamp.date().isoformat(), scenario)
                    labels[key]["event_types"].add(event_type)
                    labels[key]["source_details"].add(detail.name)
    rows = []
    for (user, day, scenario), evidence in sorted(labels.items(), key=lambda item: (item[0][1], item[0][0], item[0][2])):
        rows.append({
            "user": user,
            "date": day,
            "scenario": scenario,
            "event_types": ";".join(sorted(evidence["event_types"])),
            "source_details": ";".join(sorted(evidence["source_details"])),
        })
    return rows


def sha256(path: Path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--answers", required=True, type=Path)
    parser.add_argument("--release", default="4.2")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args(argv)
    rows = build_labels(args.answers, args.release)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=("user", "date", "scenario", "event_types", "source_details"))
        writer.writeheader()
        writer.writerows(rows)
    counts = defaultdict(int)
    users = defaultdict(set)
    for row in rows:
        counts[str(row["scenario"])] += 1
        users[str(row["scenario"])].add(row["user"])
    manifest = {
        "release": args.release,
        "label_unit": "distinct user-day with at least one official malicious observable",
        "source": "CMU CERT answers.tar.bz2 detailed per-incident files",
        "rows_by_scenario": dict(counts),
        "users_by_scenario": {scenario: len(values) for scenario, values in users.items()},
        "labels_sha256": sha256(args.output),
    }
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
