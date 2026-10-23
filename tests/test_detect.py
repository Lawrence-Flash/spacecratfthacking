"""Detector rules fire on planted records and stay quiet on a clean day."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from spacelab.catalog import ANOMALIES, EXPECTED_RULE
from spacelab.detect import analyze, score_injections
from spacelab.serialize import load_commands, load_telemetry
from tests.helpers import run_sim


class DetectTests(unittest.TestCase):
    def test_clean_day_has_no_findings(self):
        with TemporaryDirectory() as tmp:
            result = run_sim(Path(tmp), [])
            report = _analyze(result)
            self.assertEqual(report.findings, [])

    def test_each_planted_anomaly_produces_only_its_family(self):
        expectations = {
            "replay": {"CMD-REPLAY"},
            "out_of_sequence": {"CMD-SEQ"},
            "bad_mac": {"CMD-MAC"},
            "outside_contact": {"CMD-WINDOW"},
            "out_of_range": {"TM-RANGE"},
            "statistical_outlier": {"TM-ZSCORE"},
        }
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            for anomaly, expected in expectations.items():
                result = run_sim(root / anomaly, [anomaly])
                report = _analyze(result)
                found = {finding.rule_id for finding in report.findings}
                self.assertEqual(found, expected, anomaly)
                self.assertEqual(result.injections[0]["expected_rule"], EXPECTED_RULE[anomaly])

    def test_outside_contact_ignores_the_in_contact_claim(self):
        with TemporaryDirectory() as tmp:
            result = run_sim(Path(tmp), ["outside_contact"])
            claimers = [command for command in result.commands if command["in_contact_claim"]]
            outside = [
                command
                for command in claimers
                if not _covered(command, result.contacts)
            ]
            self.assertEqual(len(outside), 1)
            self.assertTrue(outside[0]["in_contact_claim"])
            report = _analyze(result)
            self.assertTrue(all(finding.evidence["in_contact_claim"] for finding in report.findings))

    def test_combined_scoreboard_matches_every_plant(self):
        with TemporaryDirectory() as tmp:
            result = run_sim(Path(tmp), list(ANOMALIES))
            report = _analyze(result)
            board = score_injections(report.findings, result.injections)
            self.assertTrue(board["expected_rules_met"])
            self.assertEqual(board["matched"], len(ANOMALIES))
            self.assertEqual(board["injected"], len(ANOMALIES))

    def test_csv_inputs_match_jsonl_rules(self):
        with TemporaryDirectory() as tmp:
            result = run_sim(Path(tmp), list(ANOMALIES))
            from_jsonl = _analyze(result)
            telemetry = load_telemetry(Path(tmp) / "telemetry.csv")
            commands = load_commands(Path(tmp) / "commands.csv")
            from_csv = analyze(telemetry, commands, result.contacts)
            self.assertEqual(
                [finding.rule_id for finding in from_jsonl.findings],
                [finding.rule_id for finding in from_csv.findings],
            )

    def test_range_finding_names_the_channel(self):
        with TemporaryDirectory() as tmp:
            result = run_sim(Path(tmp), ["out_of_range"])
            report = _analyze(result)
            finding = report.findings[0]
            self.assertEqual(finding.severity, "high")
            self.assertEqual(finding.evidence["channel"], "battery_temp_c")
            self.assertEqual(finding.evidence["value"], 95.0)

    def test_bad_mac_is_critical_and_replay_is_critical(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            mac = _analyze(run_sim(root / "mac", ["bad_mac"]))
            replay = _analyze(run_sim(root / "replay", ["replay"]))
            self.assertEqual(mac.findings[0].severity, "critical")
            self.assertEqual(replay.findings[0].severity, "critical")


def _analyze(result):
    return analyze(result.telemetry, result.commands, result.contacts, sources={"kind": "memory"})


def _covered(command: dict, contacts: list[dict]) -> bool:
    from spacelab.timeutil import parse_utc

    moment = parse_utc(command["received_at"])
    for contact in contacts:
        if contact["station_id"] != command["station_id"]:
            continue
        if parse_utc(contact["aos"]) <= moment <= parse_utc(contact["los"]):
            return True
    return False


if __name__ == "__main__":
    unittest.main()
