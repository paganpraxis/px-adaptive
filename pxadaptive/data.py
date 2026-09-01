"""CERT r4.2 adapter and causal user-day feature construction."""
from pathlib import Path


REQUIRED_EVENT_COLUMNS = {
    "logon.csv": {"date", "user", "pc", "activity"},
    "http.csv": {"date", "user", "pc", "url"},
    "device.csv": {"date", "user", "pc", "activity"},
}


def _dependencies():
    try:
        import numpy as np
        import pandas as pd
    except ImportError as error:
        raise RuntimeError("Full runs require: pip install -e '.[test]'") from error
    return np, pd


def validate_raw_directory(root: Path, labels_file: str) -> None:
    _, pd = _dependencies()
    missing = [name for name in (*REQUIRED_EVENT_COLUMNS, labels_file) if not (root / name).exists()]
    if missing:
        raise ValueError(f"missing required CERT inputs: {', '.join(missing)}")
    for name, expected in REQUIRED_EVENT_COLUMNS.items():
        columns = set(pd.read_csv(root / name, nrows=0).columns.str.lower())
        absent = expected - columns
        if absent:
            raise ValueError(f"{name} missing columns: {sorted(absent)}")
    label_columns = set(pd.read_csv(root / labels_file, nrows=0).columns.str.lower())
    if not {"user", "date", "scenario"}.issubset(label_columns):
        raise ValueError("labels file must contain user,date,scenario")


def build_user_days(root: Path, config: dict):
    """Stream-aggregate raw events with DuckDB, then attach official labels."""
    np, pd = _dependencies()
    try:
        import duckdb
    except ImportError as error:
        raise RuntimeError("Full runs require: pip install -e '.[test]'") from error
    labels_file = config["data"]["labels_file"]
    validate_raw_directory(root, labels_file)
    start = config["features"]["business_hour_start"]
    end = config["features"]["business_hour_end"]
    timestamp = "strptime(date, '%m/%d/%Y %H:%M:%S')"

    def source(name):
        path = str(root / name).replace("'", "''")
        return f"read_csv('{path}', header=true, all_varchar=true, strict_mode=false)"

    temp = root.parent / ".duckdb-tmp"
    temp.mkdir(parents=True, exist_ok=True)
    connection = duckdb.connect()
    connection.execute("SET memory_limit='4GB'")
    connection.execute(f"SET temp_directory='{str(temp).replace(chr(39), chr(39) * 2)}'")
    logon_daily = connection.execute(f"""
        SELECT user, CAST({timestamp} AS DATE) AS day,
          SUM(CASE WHEN lower(activity)='logon' THEN 1 ELSE 0 END) AS logon_count,
          SUM(CASE WHEN lower(activity)='logoff' THEN 1 ELSE 0 END) AS logoff_count,
          COUNT(DISTINCT pc) AS distinct_pcs,
          SUM(CASE WHEN hour({timestamp}) < {start} OR hour({timestamp}) >= {end} THEN 1 ELSE 0 END) AS offhour_logons,
          date_diff('minute', MIN({timestamp}), MAX({timestamp})) AS session_span_minutes
        FROM {source('logon.csv')} GROUP BY user, day
    """).fetchdf()
    http_daily = connection.execute(f"""
        SELECT user, CAST({timestamp} AS DATE) AS day,
          COUNT(*) AS web_requests,
          COUNT(DISTINCT regexp_extract(coalesce(url,''), '^(?:https?://)?([^/]+)', 1)) AS unique_domains,
          SUM(CASE WHEN hour({timestamp}) < {start} OR hour({timestamp}) >= {end} THEN 1 ELSE 0 END) AS offhour_web_requests,
          MAX(CASE WHEN contains(lower(coalesce(url,'')), 'wikileaks') THEN 1 ELSE 0 END) AS wikileaks_flag
        FROM {source('http.csv')} GROUP BY user, day
    """).fetchdf()
    device_daily = connection.execute(f"""
        SELECT user, CAST({timestamp} AS DATE) AS day,
          SUM(CASE WHEN lower(activity)='connect' THEN 1 ELSE 0 END) AS usb_connects,
          SUM(CASE WHEN lower(activity)='connect' AND (hour({timestamp}) < {start} OR hour({timestamp}) >= {end}) THEN 1 ELSE 0 END) AS afterhours_usb_connects
        FROM {source('device.csv')} GROUP BY user, day
    """).fetchdf()
    connection.close()
    device_daily["offhour_usb_flag"] = device_daily["afterhours_usb_connects"].gt(0)
    keys = ["user", "day"]
    daily = logon_daily.merge(http_daily, on=keys, how="outer").merge(device_daily, on=keys, how="outer").fillna(0)
    labels = pd.read_csv(root / labels_file)
    labels.columns = labels.columns.str.lower()
    labels["day"] = pd.to_datetime(labels["date"]).dt.normalize()
    excluded = set(config["data"]["excluded_scenarios"])
    excluded_users = set(labels.loc[labels["scenario"].isin(excluded), "user"])
    daily = daily.loc[~daily["user"].isin(excluded_users)].copy()
    positive = labels.loc[labels["scenario"].eq(config["data"]["scenario"]), ["user", "day"]].drop_duplicates()
    positive["malicious"] = True
    daily = daily.merge(positive, on=keys, how="left")
    daily["malicious"] = daily["malicious"].eq(True)
    daily["wikileaks_flag"] = daily["wikileaks_flag"].astype(bool)
    daily["offhour_usb_flag"] = daily["offhour_usb_flag"].astype(bool)
    return daily.sort_values(["day", "user"]).reset_index(drop=True)


def add_causal_zscores(daily, feature_names, rolling_days: int = 7):
    """Past-only expanding and rolling z-scores; current rows never enter their baselines."""
    np, pd = _dependencies()
    result = daily.sort_values(["user", "day"]).copy()
    for feature in feature_names:
        grouped = result.groupby("user", sort=False)[feature]
        expanding_mean = grouped.transform(lambda s: s.expanding().mean().shift(1))
        expanding_std = grouped.transform(lambda s: s.expanding().std(ddof=0).shift(1))
        rolling_mean = grouped.transform(lambda s: s.rolling(rolling_days, min_periods=2).mean().shift(1))
        rolling_std = grouped.transform(lambda s: s.rolling(rolling_days, min_periods=2).std(ddof=0).shift(1))
        fallback_mean = expanding_mean.fillna(0.0)
        fallback_std = expanding_std.replace(0, np.nan).fillna(1.0)
        result[f"{feature}__exp_z"] = ((result[feature] - fallback_mean) / fallback_std).clip(-20, 20)
        rstd = rolling_std.replace(0, np.nan).fillna(fallback_std)
        result[f"{feature}__roll7_z"] = ((result[feature] - rolling_mean.fillna(fallback_mean)) / rstd).clip(-20, 20)
    return result
