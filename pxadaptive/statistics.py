import math
import random
from statistics import NormalDist


def _quantile(values, probability):
    ordered = sorted(values)
    if not ordered:
        raise ValueError("cannot take a quantile of no values")
    position = (len(ordered) - 1) * min(1.0, max(0.0, probability))
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def cluster_bca(clusters, statistic, replicates, seed, alpha=0.05):
    """BCa interval resampling whole user clusters with replacement."""
    clusters = tuple(clusters)
    if len(clusters) < 3:
        raise ValueError("BCa requires at least three clusters")
    observed = statistic(clusters)
    rng = random.Random(seed)
    boot = [statistic(tuple(rng.choice(clusters) for _ in clusters)) for _ in range(replicates)]
    normal = NormalDist()
    less = (sum(value < observed for value in boot) + 0.5 * sum(value == observed for value in boot)) / replicates
    z0 = normal.inv_cdf(min(1 - 1e-12, max(1e-12, less)))
    jack = [statistic(clusters[:i] + clusters[i + 1 :]) for i in range(len(clusters))]
    mean_jack = sum(jack) / len(jack)
    numerator = sum((mean_jack - value) ** 3 for value in jack)
    denominator = 6 * sum((mean_jack - value) ** 2 for value in jack) ** 1.5
    acceleration = numerator / denominator if denominator else 0.0

    def adjusted(p):
        z = normal.inv_cdf(p)
        denominator = 1 - acceleration * (z0 + z)
        return normal.cdf(z0 + (z0 + z) / denominator) if denominator else p

    return observed, _quantile(boot, adjusted(alpha / 2)), _quantile(boot, adjusted(1 - alpha / 2))


def tost_from_interval(estimate, lower, upper, margin):
    """CI-form TOST decision: the entire interval must lie inside ±margin."""
    return {"estimate": estimate, "equivalent": lower > -margin and upper < margin}
