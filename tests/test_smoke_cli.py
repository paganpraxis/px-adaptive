import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SmokeCliTest(unittest.TestCase):
    def test_smoke_command_writes_machine_readable_manifest(self):
        with tempfile.TemporaryDirectory() as output_dir:
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pxadaptive",
                    "smoke",
                    "--config",
                    str(ROOT / "configs" / "smoke.json"),
                    "--output",
                    output_dir,
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            manifest = json.loads((Path(output_dir) / "manifest.json").read_text())
            self.assertEqual(manifest["status"], "passed")
            self.assertEqual(manifest["profile"], "smoke")
            self.assertGreater(manifest["checks_passed"], 0)
            self.assertTrue((Path(output_dir) / "metrics.csv").exists())


if __name__ == "__main__":
    unittest.main()
