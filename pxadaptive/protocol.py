import math
from datetime import date


def budget_from_percent(pool_size: int, percent: float) -> int:
    if pool_size < 0 or percent <= 0:
        raise ValueError("pool_size must be nonnegative and percent positive")
    return max(1, math.floor(pool_size * percent / 100))


def minmax_apply(values, training_min: float, training_max: float) -> list[float]:
    if training_max < training_min:
        raise ValueError("training_max must be >= training_min")
    if training_max == training_min:
        return [0.0 for _ in values]
    scale = training_max - training_min
    return [min(1.0, max(0.0, (value - training_min) / scale)) for value in values]


def validate_chronology(score_feedback_months) -> None:
    for scored, feedback_available in score_feedback_months:
        scored_date = date.fromisoformat(scored + "-01")
        feedback_date = date.fromisoformat(feedback_available + "-01")
        if feedback_date <= scored_date:
            raise ValueError("feedback must become available after scoring month")


def blocked_temporal_calibration(frame, p2_split_date, malicious_fraction=0.30):
    """Split P2's post-cutoff period into early calibration and later evaluation.

    The boundary is the day containing the requested cumulative fraction of
    malicious user-days. Whole calendar days stay together, so the realized
    fraction can exceed the target when several positives share the boundary.
    """
    import pandas as pd

    if not 0 < malicious_fraction < 1:
        raise ValueError("malicious_fraction must be strictly between zero and one")
    post_split = frame.loc[frame.day > pd.Timestamp(p2_split_date)].sort_values("day").copy()
    positive_days = post_split.loc[post_split.malicious, "day"].sort_values().tolist()
    if len(positive_days) < 2:
        raise ValueError("blocked calibration requires at least two post-split malicious user-days")
    target = max(1, math.ceil(len(positive_days) * malicious_fraction))
    cutoff = pd.Timestamp(positive_days[target - 1])
    calibration = post_split.loc[post_split.day <= cutoff].copy()
    evaluation = post_split.loc[post_split.day > cutoff].copy()
    if calibration.malicious.sum() == 0 or evaluation.malicious.sum() == 0:
        raise ValueError("both calibration and evaluation windows must contain malicious user-days")
    return calibration, evaluation, cutoff
