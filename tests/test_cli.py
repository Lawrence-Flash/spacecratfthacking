"""Entry point: help text and an end-to-end demo."""

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from spacelab.catalog import ANOMALIES

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_help_for_the_tool_and_each_command(self):
        for args in (
            ["--help"],
            ["simulate", "--help"],
            ["detect", "--help"],
            ["checklist", "--help"],
            ["demo", "--help"],
        ):
            completed = _run(args)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("usage", completed.stdout.lower())

    def test_unknown_anomaly_is_rejected(self):
        with TemporaryDirectory() as tmp:
            completed = _run(["simulate", "--out-dir", tmp, "--anomalies", "exploit"])
            self.assertEqual(completed.returncode, 2)
            self.assertIn("unknown anomalies", completed.stderr)

    def test_demo_scores_every_planted_anomaly(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            completed = _run(["demo", "--out-dir", str(out)])
            self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
            self.assertIn("CMD-REPLAY", completed.stdout)
            self.assertIn("SL-01", completed.stdout)
            report = json.loads((out / "report.json").read_text(encoding="utf-8"))
            self.assertTrue(report["scoreboard"]["expected_rules_met"])
            self.assertEqual(report["scoreboard"]["injected"], len(ANOMALIES))
            self.assertIn("Simulated teaching data only", report["disclaimer"])

    def test_package_does_not_import_network_or_radio_modules(self):
        banned = ("socket", "subprocess", "http.server", "flask", "scapy", "urllib", "requests")
        for path in (ROOT / "spacelab").glob("*.py"):
            for line in path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                for name in banned:
                    self.assertNotIn(f"import {name}", stripped)
                    self.assertNotIn(f"from {name}", stripped)


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "spacelab", *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


if __name__ == "__main__":
    unittest.main()
