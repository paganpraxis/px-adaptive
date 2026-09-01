import csv
import json
from pathlib import Path

from .ranking import Alert, expected_precision_at_k, hybrid_score


def run_smoke(config: dict, output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    alerts = [
        Alert("u1", "2010-07-01", True, 0.9, 0.0),
        Alert("u2", "2010-07-01", True, 0.4, 1.0),
        Alert("u3", "2010-07-01", False, 0.8, 0.0),
        Alert("u4", "2010-07-01", False, 0.1, 1.0),
    ]
    checks = {
        "w0_is_rules": all(hybrid_score(a, 0.0) == a.rules for a in alerts),
        "w1_is_anomaly": all(hybrid_score(a, 1.0) == a.anomaly for a in alerts),
        "tie_expectation": expected_precision_at_k(alerts, 0.0, 1) == 0.5,
    }
    rows = []
    for weight in config["weights"]:
        rows.append(
            {
                "profile": "smoke",
                "ranker": "hybrid",
                "candidate_pool": "fixture_model_pool",
                "seed": config["random_seed"],
                "weight": weight,
                "ablation": "full",
                "budget": 1,
                "endpoint": "expected_precision_at_k",
                "estimate": expected_precision_at_k(alerts, weight, 1),
                "lower": "",
                "upper": "",
            }
        )
    with (output / "metrics.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    manifest = {
        "schema_version": config["schema_version"],
        "profile": "smoke",
        "status": "passed" if all(checks.values()) else "failed",
        "checks_passed": sum(checks.values()),
        "checks_total": len(checks),
        "checks": checks,
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest
