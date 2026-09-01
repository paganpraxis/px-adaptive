import json
import tempfile
import unittest
from pathlib import Path

from pxadaptive.experiment import run_experiment


ROOT = Path(__file__).resolve().parents[1]


class FullFixtureTest(unittest.TestCase):
    def test_full_runner_consumes_raw_contract_and_writes_provenance(self):
        config = json.loads((ROOT / "configs" / "full.json").read_text())
        config["analysis"]["seeds"] = [11]
        config["analysis"]["weight_grid"] = [0.0, 0.7, 1.0]
        config["analysis"]["percent_budgets"] = [5]
        config["detector"]["n_estimators"] = 10
        with tempfile.TemporaryDirectory() as output:
            manifest = run_experiment(config, ROOT / "tests/fixtures/cert-mini", Path(output))
            self.assertEqual(manifest["status"], "completed")
            self.assertEqual(manifest["malicious_user_days"], 3)
            self.assertIn("wikileaks_flag", manifest["tuned_rule_weights"])
            self.assertTrue((Path(output) / "metrics.csv").exists())


if __name__ == "__main__":
    unittest.main()
