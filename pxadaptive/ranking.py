from dataclasses import dataclass
from typing import Iterable, Sequence


@dataclass(frozen=True)
class Alert:
    user: str
    day: str
    malicious: bool
    anomaly: float
    rules: float


def hybrid_score(alert: Alert, weight: float) -> float:
    if not 0.0 <= weight <= 1.0:
        raise ValueError("weight must be in [0, 1]")
    return weight * alert.anomaly + (1.0 - weight) * alert.rules


def ranked(alerts: Iterable[Alert], weight: float) -> list[Alert]:
    return sorted(alerts, key=lambda row: (-hybrid_score(row, weight), row.user, row.day))


def expected_precision_at_k(alerts: Sequence[Alert], weight: float, k: int) -> float:
    """Expected precision under uniform random ordering inside score ties."""
    if k <= 0:
        raise ValueError("k must be positive")
    if not alerts:
        return 0.0
    k = min(k, len(alerts))
    groups: dict[float, list[Alert]] = {}
    for alert in alerts:
        groups.setdefault(hybrid_score(alert, weight), []).append(alert)
    remaining = k
    expected_tp = 0.0
    for score in sorted(groups, reverse=True):
        group = groups[score]
        take = min(remaining, len(group))
        expected_tp += take * sum(a.malicious for a in group) / len(group)
        remaining -= take
        if remaining == 0:
            break
    return expected_tp / k


def tie_bounds_at_k(alerts: Sequence[Alert], weight: float, k: int) -> tuple[float, float]:
    """Worst/best precision attainable by ordering alerts inside tied groups."""
    if k <= 0:
        raise ValueError("k must be positive")
    if not alerts:
        return (0.0, 0.0)
    k = min(k, len(alerts))
    groups: dict[float, list[Alert]] = {}
    for alert in alerts:
        groups.setdefault(hybrid_score(alert, weight), []).append(alert)
    remaining = k
    worst_tp = best_tp = 0
    for score in sorted(groups, reverse=True):
        group = groups[score]
        take = min(remaining, len(group))
        positives = sum(a.malicious for a in group)
        negatives = len(group) - positives
        worst_tp += max(0, take - negatives)
        best_tp += min(take, positives)
        remaining -= take
        if remaining == 0:
            break
    return (worst_tp / k, best_tp / k)
