import itertools


RULE_FLAGS = ("wikileaks_flag", "offhour_usb_flag", "afterhours_usb_connects")


def tune_rule_weights(training, grid_values):
    """Choose weights by validation average precision; predicates remain fixed."""
    from sklearn.metrics import average_precision_score

    if training.malicious.nunique() < 2:
        raise ValueError("rule tuning requires both classes before the temporal cutoff")
    best = None
    for values in itertools.product(grid_values, repeat=len(RULE_FLAGS)):
        if not any(values):
            continue
        weights = dict(zip(RULE_FLAGS, values))
        score = sum(training[flag].astype(float) * weights[flag] for flag in RULE_FLAGS) / sum(values)
        objective = float(average_precision_score(training.malicious, score))
        candidate = (objective, -sum(values), tuple(-value for value in values), weights)
        if best is None or candidate[:3] > best[:3]:
            best = candidate
    return best[3], best[0]
