import unittest

import pandas as pd

from pxadaptive.protocol import (
    blocked_temporal_calibration,
    budget_from_percent,
    minmax_apply,
    validate_chronology,
)
from pxadaptive.ranking import Alert, expected_precision_at_k, hybrid_score, tie_bounds_at_k


class RankingProtocolTest(unittest.TestCase):
    def setUp(self):
        self.alerts = [
            Alert("a", "2010-07-01", True, 0.9, 1.0),
            Alert("b", "2010-07-01", False, 0.8, 1.0),
            Alert("c", "2010-07-01", True, 0.7, 0.0),
        ]

    def test_weight_endpoints_are_exact_ranker_identities(self):
        self.assertEqual([hybrid_score(a, 0) for a in self.alerts], [1.0, 1.0, 0.0])
        self.assertEqual([hybrid_score(a, 1) for a in self.alerts], [0.9, 0.8, 0.7])

    def test_tied_boundary_reports_expectation_and_bounds(self):
        self.assertEqual(expected_precision_at_k(self.alerts, 0, 1), 0.5)
        self.assertEqual(tie_bounds_at_k(self.alerts, 0, 1), (0.0, 1.0))

    def test_p2_percentage_budgets_use_floor(self):
        self.assertEqual([budget_from_percent(1842, p) for p in (1, 2, 5, 10)], [18, 36, 92, 184])

    def test_normalization_uses_training_extrema_and_clips_test_values(self):
        self.assertEqual(minmax_apply([-1, 5, 11], 0, 10), [0.0, 0.5, 1.0])
        self.assertEqual(minmax_apply([4], 2, 2), [0.0])

    def test_feedback_cannot_precede_scoring_month(self):
        validate_chronology([("2010-07", "2010-08"), ("2010-08", "2010-09")])
        with self.assertRaisesRegex(ValueError, "after scoring"):
            validate_chronology([("2010-07", "2010-07")])

    def test_blocked_calibration_never_moves_future_rows_backwards(self):
        frame = pd.DataFrame(
            {
                "day": pd.to_datetime(
                    ["2010-07-01", "2010-07-02", "2010-07-03", "2010-07-04", "2010-07-05"]
                ),
                "malicious": [False, True, True, False, True],
            }
        )
        calibration, evaluation, cutoff = blocked_temporal_calibration(
            frame, "2010-06-30", malicious_fraction=1 / 3
        )
        self.assertEqual(str(cutoff.date()), "2010-07-02")
        self.assertLessEqual(calibration.day.max(), cutoff)
        self.assertGreater(evaluation.day.min(), cutoff)
        self.assertEqual(int(calibration.malicious.sum()), 1)
        self.assertEqual(int(evaluation.malicious.sum()), 2)


if __name__ == "__main__":
    unittest.main()
