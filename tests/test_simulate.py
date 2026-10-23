"""Simulator: fictional logs, stable bytes, and planted anomalies."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from spacelab.auth import compute_mac, verify_mac
from spacelab.catalog import ANOMALIES, CHANNELS
from spacelab.ccsds import parse_primary_header
from spacelab.serialize import load_commands, load_telemetry
from spacelab.timeutil import parse_utc
from tests.helpers import run_sim


class SimulateTests(unittest.TestCase):
    def test_clean_logs_stay_inside_limits_and_contacts(self):
        with TemporaryDirectory() as tmp:
            result = run_sim(Path(tmp), [])
            self.assertGreaterEqual(len(result.telemetry), 20)
            self.assertGreaterEqual(len(result.commands), 4)
            self.assertEqual(result.injections, [])
            self.assertEqual(len(result.contacts), 2)
            for frame in result.telemetry:
                for name, channel in CHANNELS.items():
                    value = frame["sensors"][name]
                    self.assertGreaterEqual(value, channel.minimum)
                    self.assertLessEqual(value, channel.maximum)
                header = parse_primary_header(frame["ccsds_primary_header_hex"])
                self.assertEqual(header["version"], 0)
                self.assertEqual(header["packet_type"], "TM")
                self.assertEqual(header["sequence_flags"], 3)
                self.assertEqual(header["apid"], frame["apid"])
                self.assertEqual(header["sequence_count"], frame["sequence_count"])
            sequences = [frame["sequence_count"] for frame in result.telemetry]
            self.assertEqual(sequences, list(range(len(sequences))))
            previous = None
            for command in result.commands:
                self.assertTrue(verify_mac(command))
                self.assertTrue(_in_contact(command, result.contacts))
                header = parse_primary_header(command["ccsds_primary_header_hex"])
                self.assertEqual(header["packet_type"], "TC")
                self.assertEqual(header["sequence_count"], command["sequence_count"])
                if previous is not None:
                    self.assertEqual(command["sequence_count"], previous + 1)
                previous = command["sequence_count"]

    def test_same_seed_matches_and_a_new_seed_changes_telemetry(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_sim(root / "a", [])
            run_sim(root / "b", [])
            run_sim(root / "c", [], seed=99)
            self.assertEqual((root / "a" / "telemetry.jsonl").read_bytes(), (root / "b" / "telemetry.jsonl").read_bytes())
            self.assertNotEqual(
                (root / "a" / "telemetry.jsonl").read_bytes(),
                (root / "c" / "telemetry.jsonl").read_bytes(),
            )

    def test_receipt_time_is_outside_the_mac(self):
        with TemporaryDirectory() as tmp:
            result = run_sim(Path(tmp), [])
            command = result.commands[0]
            original = command["mac_hex"]
            command["received_at"] = "2026-06-21T12:00:00Z"
            self.assertEqual(compute_mac(command), original)
            self.assertTrue(verify_mac(command))

    def test_each_anomaly_is_recorded_once(self):
        with TemporaryDirectory() as tmp:
            result = run_sim(Path(tmp), list(ANOMALIES))
            planted = [item["anomaly"] for item in result.injections]
            self.assertEqual(planted, list(ANOMALIES))
            self.assertTrue((Path(tmp) / "telemetry.csv").is_file())
            self.assertTrue((Path(tmp) / "commands.csv").is_file())
            self.assertEqual(len(load_telemetry(Path(tmp) / "telemetry.jsonl")), len(result.telemetry))
            self.assertEqual(len(load_commands(Path(tmp) / "commands.csv")), len(result.commands))

    def test_replay_copy_keeps_a_valid_tag(self):
        with TemporaryDirectory() as tmp:
            result = run_sim(Path(tmp), ["replay"])
            copies = [command for command in result.commands if command["frame_id"].endswith("-R")]
            self.assertEqual(len(copies), 1)
            self.assertTrue(verify_mac(copies[0]))
            originals = [
                command
                for command in result.commands
                if command["sequence_count"] == copies[0]["sequence_count"] and command["frame_id"] != copies[0]["frame_id"]
            ]
            self.assertEqual(len(originals), 1)
            self.assertEqual(originals[0]["mac_hex"], copies[0]["mac_hex"])
            self.assertEqual(originals[0]["timestamp"], copies[0]["timestamp"])
            self.assertNotEqual(originals[0]["received_at"], copies[0]["received_at"])

    def test_bad_mac_does_not_verify_and_sequence_jump_does(self):
        with TemporaryDirectory() as tmp:
            bad = run_sim(Path(tmp) / "bad", ["bad_mac"])
            failed = [command for command in bad.commands if not verify_mac(command)]
            self.assertEqual(len(failed), 1)
            jumped = run_sim(Path(tmp) / "seq", ["out_of_sequence"])
            self.assertTrue(all(verify_mac(command) for command in jumped.commands))
            sequences = [command["sequence_count"] for command in jumped.commands]
            steps = [b - a for a, b in zip(sequences, sequences[1:])]
            self.assertTrue(any(step != 1 for step in steps))


def _in_contact(command: dict, contacts: list[dict]) -> bool:
    moment = parse_utc(command["received_at"])
    for contact in contacts:
        if contact["station_id"] != command["station_id"]:
            continue
        if parse_utc(contact["aos"]) <= moment <= parse_utc(contact["los"]):
            return True
    return False


if __name__ == "__main__":
    unittest.main()
