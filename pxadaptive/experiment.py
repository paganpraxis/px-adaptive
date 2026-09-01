import csv
import hashlib
import json
from pathlib import Path

from .data import add_causal_zscores, build_user_days
from .model import adaptive_scores
from .protocol import blocked_temporal_calibration, budget_from_percent
from .rules import tune_rule_weights


RULE_FLAGS = ("wikileaks_flag", "offhour_usb_flag", "afterhours_usb_connects")


def _expected_precision(frame, score_column, k):
    k = min(k, len(frame))
    if k <= 0:
        return 0.0, 0.0, 0.0
    remaining = k
    expected = worst = best = 0.0
    for score in sorted(frame[score_column].unique(), reverse=True):
        group = frame.loc[frame[score_column] == score]
        take = min(remaining, len(group))
        positives = int(group.malicious.sum())
        negatives = len(group) - positives
        expected += take * positives / len(group)
        worst += max(0, take - negatives)
        best += min(take, positives)
        remaining -= take
        if remaining == 0:
            break
    return expected / k, worst / k, best / k


def _rule_score(frame, weights, ablation):
    flags = [flag for flag in RULE_FLAGS if flag != "wikileaks_flag" or ablation != "no_wikileaks"]
    if ablation == "wikileaks_only":
        flags = ["wikileaks_flag"]
    denominator = sum(weights[flag] for flag in flags)
    if denominator == 0:
        return frame[flags[0]].astype(float) * 0
    return sum(frame[flag].astype(float) * weights[flag] for flag in flags) / denominator


def _write_csv(path, rows):
    if not rows:
        return
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def run_experiment(config, data_root: Path, output: Path):
    import pandas as pd

    output.mkdir(parents=True, exist_ok=True)
    daily = build_user_days(data_root, config)
    raw_features = config["features"]["continuous"]
    featured = add_causal_zscores(daily, raw_features, config["features"]["rolling_days"])
    model_features = [f"{name}__{kind}" for name in raw_features for kind in ("exp_z", "roll7_z")]
    rows = []
    calibration, evaluation, calibration_cutoff = blocked_temporal_calibration(
        featured,
        config["data"]["split_date"],
        config["rules"]["calibration"]["target_malicious_fraction"],
    )
    weights, tuning_ap = tune_rule_weights(calibration, config["rules"]["weight_grid"])
    for seed in config["analysis"]["seeds"]:
        full_scored = adaptive_scores(featured, model_features, config, seed)
        static_scored = adaptive_scores(featured, model_features, config, seed, expand_fp=False)
        full_model_pool = full_scored.loc[full_scored.is_alert].copy()
        scored = full_scored.loc[full_scored.day > calibration_cutoff].copy()
        model_pool = scored.loc[scored.is_alert].copy()
        for ablation in config["ablations"]:
            reproduction_pool = full_model_pool.copy()
            reproduction_pool["rule_norm"] = _rule_score(
                reproduction_pool, config["rules"]["full_period_baseline_weights"], ablation
            )
            for weight in (0.0, 0.7, 1.0):
                reproduction_pool["hybrid_score"] = (
                    weight * reproduction_pool.anomaly_norm + (1 - weight) * reproduction_pool.rule_norm
                )
                for percent in config["analysis"]["percent_budgets"]:
                    k = budget_from_percent(len(reproduction_pool), percent)
                    estimate, lower_tie, upper_tie = _expected_precision(
                        reproduction_pool, "hybrid_score", k
                    )
                    rows.append({
                        "profile": "full", "analysis_scope": "p2_full_post_split_descriptive",
                        "ranker": "hybrid", "candidate_pool": "model_selected", "seed": seed,
                        "weight": weight, "ablation": ablation, "budget": k,
                        "budget_percent": percent, "endpoint": "expected_precision_at_k",
                        "estimate": estimate, "tie_lower": lower_tie, "tie_upper": upper_tie,
                    })
        for ablation in config["ablations"]:
            for pool_name, pool in (("model_selected", model_pool), ("all_test_user_days", scored)):
                working = pool.copy()
                working["rule_norm"] = _rule_score(working, weights, ablation)
                for weight in config["analysis"]["weight_grid"]:
                    if pool_name == "all_test_user_days" and weight != 0.0:
                        continue
                    working["hybrid_score"] = weight * working.anomaly_norm + (1 - weight) * working.rule_norm
                    for percent in config["analysis"]["percent_budgets"]:
                        k = budget_from_percent(len(working), percent)
                        estimate, lower_tie, upper_tie = _expected_precision(working, "hybrid_score", k)
                        rows.append({
                            "profile": "full", "analysis_scope": "confirmatory_late_holdout",
                            "ranker": "hybrid", "candidate_pool": pool_name,
                            "seed": seed, "weight": weight, "ablation": ablation, "budget": k,
                            "budget_percent": percent, "endpoint": "expected_precision_at_k",
                            "estimate": estimate, "tie_lower": lower_tie, "tie_upper": upper_tie,
                        })
                    for k in config["analysis"]["absolute_budgets"]:
                        effective_k = min(k, len(working))
                        expected, lower_tie, upper_tie = _expected_precision(working, "hybrid_score", effective_k)
                        total_positives = max(1, int(scored.malicious.sum()))
                        rows.append({
                            "profile": "full", "analysis_scope": "confirmatory_late_holdout",
                            "ranker": "hybrid" if pool_name == "model_selected" else "standalone_rules",
                            "candidate_pool": pool_name, "seed": seed, "weight": weight if pool_name == "model_selected" else 0.0,
                            "ablation": ablation, "budget": effective_k, "budget_percent": "",
                            "endpoint": "expected_recall_at_budget", "estimate": expected * effective_k / total_positives,
                            "tie_lower": lower_tie * effective_k / total_positives,
                            "tie_upper": upper_tie * effective_k / total_positives,
                        })
        alert_recall = model_pool.malicious.sum() / max(1, scored.malicious.sum())
        rows.append({
            "profile": "full", "analysis_scope": "confirmatory_late_holdout",
            "ranker": "adaptive_if", "candidate_pool": "model_selected",
            "seed": seed, "weight": "", "ablation": "full", "budget": len(model_pool),
            "budget_percent": "", "endpoint": "recall", "estimate": alert_recall,
            "tie_lower": "", "tie_upper": "",
        })
        static_pool = static_scored.loc[static_scored.is_alert]
        for name, evaluated, pool in (("static_if", static_scored, static_pool), ("expand_fp_only", full_scored, full_model_pool)):
            rows.append({
                "profile": "full", "analysis_scope": "p2_full_post_split_reproduction",
                "ranker": name, "candidate_pool": "model_selected", "seed": seed,
                "weight": "", "ablation": "full", "budget": len(pool), "budget_percent": "",
                "endpoint": "false_positives", "estimate": int((~pool.malicious).sum()),
                "tie_lower": "", "tie_upper": "",
            })
            rows.append({
                "profile": "full", "analysis_scope": "p2_full_post_split_reproduction",
                "ranker": name, "candidate_pool": "model_selected", "seed": seed,
                "weight": "", "ablation": "full", "budget": len(pool), "budget_percent": "",
                "endpoint": "recall", "estimate": float(pool.malicious.sum() / max(1, evaluated.malicious.sum())),
                "tie_lower": "", "tie_upper": "",
            })
    _write_csv(output / "metrics.csv", rows)
    config_digest = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
    manifest = {
        "schema_version": config["schema_version"], "profile": "full", "status": "completed",
        "config_sha256": config_digest, "rows": len(rows), "data_rows": len(daily),
        "users": int(daily.user.nunique()), "malicious_user_days": int(daily.malicious.sum()),
        "tuned_rule_weights": weights, "rule_training_average_precision": tuning_ap,
        "rule_calibration_cutoff": calibration_cutoff.date().isoformat(),
        "rule_calibration_rows": len(calibration),
        "rule_calibration_malicious_user_days": int(calibration.malicious.sum()),
        "confirmatory_rows": len(evaluation),
        "confirmatory_malicious_user_days": int(evaluation.malicious.sum()),
        "comparability_warning": "Only model_selected scenario-1 endpoints under the P2 split are directly comparable to P2.",
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest
