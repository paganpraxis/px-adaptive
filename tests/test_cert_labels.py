import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_cert_labels", ROOT / "scripts/build_cert_labels.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CertLabelsTest(unittest.TestCase):
    def test_distinct_observable_days_are_labels_not_incident_range(self):
        with tempfile.TemporaryDirectory() as directory:
            answers = Path(directory)
            for scenario in (1, 2, 3):
                target = answers / f"r4.2-{scenario}"
                target.mkdir()
                (target / f"r4.2-{scenario}-U{scenario}.csv").write_text(
                    f"logon,id,07/01/2010 01:00:00,U{scenario},PC,Logon\n"
                    f"http,id,07/01/2010 02:00:00,U{scenario},PC,http://x/\n"
                    f"email,id,07/02/2010 02:00:00,OTHER,U{scenario},subject\n"
                    f"device,id,07/03/2010 02:00:00,U{scenario},PC,Connect\n"
                )
            rows = MODULE.build_labels(answers, "4.2")
            scenario_one = [row for row in rows if row["scenario"] == 1]
            self.assertEqual([row["date"] for row in scenario_one], ["2010-07-01", "2010-07-03"])
            self.assertEqual(scenario_one[0]["event_types"], "http;logon")


if __name__ == "__main__":
    unittest.main()
