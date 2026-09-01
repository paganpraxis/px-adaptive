"""P2 reconstruction of monthly Expand-FP-only scoring."""


def adaptive_scores(frame, feature_columns, config, seed, expand_fp=True):
    try:
        import numpy as np
        import pandas as pd
        from sklearn.ensemble import IsolationForest
    except ImportError as error:
        raise RuntimeError("Full runs require: pip install -e '.[test]'") from error

    split = pd.Timestamp(config["data"]["split_date"])
    train = frame.loc[(frame.day <= split) & ~frame.malicious].copy()
    test = frame.loc[frame.day > split].copy()
    if train.empty or test.empty:
        raise ValueError("temporal split must produce nonempty benign training and test sets")
    working = train.copy()
    outputs = []
    for month, month_rows in test.groupby(test.day.dt.to_period("M"), sort=True):
        detector = IsolationForest(
            n_estimators=config["detector"]["n_estimators"],
            max_samples=config["detector"]["max_samples"],
            contamination="auto",
            random_state=seed,
            n_jobs=config["detector"]["n_jobs"],
        ).fit(working[feature_columns])
        train_anomaly = -detector.score_samples(working[feature_columns])
        thresholds = (
            working.assign(_score=train_anomaly)
            .groupby("user")["_score"]
            .quantile(config["detector"]["per_user_quantile"])
        )
        global_threshold = float(np.quantile(train_anomaly, config["detector"]["per_user_quantile"]))
        scored = month_rows.copy()
        scored["anomaly_raw"] = -detector.score_samples(scored[feature_columns])
        scored["threshold"] = scored["user"].map(thresholds).fillna(global_threshold)
        scored["is_alert"] = scored["anomaly_raw"] > scored["threshold"]
        train_min, train_max = float(train_anomaly.min()), float(train_anomaly.max())
        if train_max == train_min:
            scored["anomaly_norm"] = 0.0
        else:
            scored["anomaly_norm"] = ((scored.anomaly_raw - train_min) / (train_max - train_min)).clip(0, 1)
        outputs.append(scored)
        if expand_fp:
            false_positives = scored.loc[scored.is_alert & ~scored.malicious].copy()
            working = pd.concat([working, false_positives], ignore_index=True)
    return pd.concat(outputs, ignore_index=True)
