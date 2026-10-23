# spacecratfthacking

SpaceLab is a personal command-line learning lab for spacecraft cybersecurity. It generates fictional telemetry and command logs, flags problems in those logs with defensive rules, and prints a hardening checklist.

The vehicle, the ground stations, and the traffic are simulated on this machine. The tool does not transmit radio, open a network connection, or provide access to any real satellite or ground station. It is not an attack tool and it does not reproduce offensive procedures.

FS-1-LAB is a fictional cubesat. CPT-LAB and JHB-LAB are fictional stations placed at Cape Town and Johannesburg coordinates so the contact schedule is easy to picture. They are not real stations, and this project is not affiliated with any space agency or ground-station operator.

## Quick start

WSL Ubuntu with Python 3.10 or newer is enough. There is nothing to `pip install`.

```bash
python3 -m spacelab --help
python3 -m spacelab demo --out-dir ./spacelab-out
python3 -m spacelab checklist
```

`demo` writes a one-hour scenario, plants six local anomalies, prints a detection report, and lists the checklist. It exits 0 when every planted anomaly is flagged by the rule named in `scenario.json`.

Other entry points:

```bash
python3 -m spacelab simulate --out-dir ./spacelab-out --anomalies none
python3 -m spacelab detect --scenario ./spacelab-out/scenario.json --json-out ./spacelab-out/report.json
python3 -m spacelab detect --scenario ./spacelab-out/scenario.json --score
python3 -m spacelab checklist --format md --out checklist.md
python3 -m spacelab checklist --segment ground
```

`--anomalies` accepts `all`, `none`, or a comma-separated list:

`replay`, `out_of_sequence`, `bad_mac`, `outside_contact`, `out_of_range`, `statistical_outlier`

## Example

This is the report from `python3 -m spacelab demo` (default seed, one simulated hour starting 2026-06-21T06:00:00Z). A forward sequence jump is reported twice: once on the jumped command, and once on the next command, which is no longer the expected successor. That second line is a consequence of the first, not a seventh planted anomaly. The scoreboard still counts one sequence anomaly.

```text
SpaceLab detection report
Simulated teaching data only. SpaceLab does not transmit radio, connect to ground stations, or provide access to any real spacecraft.
Mission: FS-1-LAB    Spacecraft: FS-1
Telemetry frames: 120    Commands: 32    Findings: 7
Severity: info 0, low 0, medium 1, high 4, critical 2

CRITICAL  CMD-REPLAY  2026-06-21T06:07:37Z  Authenticated command repeated
          TC-000000-R repeats TC-000000 (NOOP sequence 0). First receipt 2026-06-21T06:07:22Z, later receipt 2026-06-21T06:07:37Z. The tag matches the first copy because receipt time is outside the MAC.
CRITICAL  CMD-MAC     2026-06-21T06:13:22Z  Command authentication tag failed
          TC-000009 SET_ADCS_MODE sequence 9 tag does not verify with LAB-TEACHING-KEY.
HIGH      TM-RANGE    2026-06-21T06:15:00Z  battery_temp_c outside engineering limits
          TM-000030 battery_temp_c=95 C is outside [0, 40].
HIGH      CMD-WINDOW  2026-06-21T06:25:06Z  Command outside the planned contact
          TC-000015 received at 2026-06-21T06:25:06Z on CPT-LAB is outside that station's AOS/LOS schedule. The log's in-contact claim is not used.
HIGH      CMD-SEQ     2026-06-21T06:33:10Z  Command sequence break
          TC-000016 sequence 41, expected 16 (gap). The lab MAC still verifies over the logged counter.
HIGH      CMD-SEQ     2026-06-21T06:33:50Z  Command sequence break
          TC-000017 sequence 17, expected 42 (backwards or duplicate). The lab MAC still verifies over the logged counter.
MEDIUM    TM-ZSCORE   2026-06-21T06:45:00Z  battery_temp_c is a statistical outlier
          TM-000090 battery_temp_c=39 C is 10.5 standard deviations from the in-range mean 17.704.

Counts by rule: CMD-MAC 1, CMD-REPLAY 1, CMD-SEQ 2, CMD-WINDOW 1, TM-RANGE 1, TM-ZSCORE 1

Scoreboard: 6/6 injected anomalies were flagged by the expected rule.
```

A quiet housekeeping frame looks like this (fields trimmed):

```json
{
  "frame_id": "TM-000040",
  "timestamp": "2026-06-21T06:20:00Z",
  "sequence_count": 40,
  "apid": 1,
  "sensors": {
    "battery_voltage_v": 8.1166,
    "battery_temp_c": 17.9761,
    "payload_temp_c": 21.2225,
    "radio_temp_c": 30.1055,
    "solar_array_current_a": 1.0244
  },
  "orbit": {
    "altitude_km": 522.909,
    "latitude_deg": 74.0968,
    "longitude_deg": 89.308,
    "in_eclipse": false
  },
  "contact": {"in_contact": false, "station_id": null, "elevation_deg": 0.0}
}
```

Commands are ordinary ops traffic only: `NOOP`, `SET_ADCS_MODE`, `SET_HEATER`, `REQUEST_HOUSEKEEPING`, `SET_PAYLOAD_POWER`, and `COMM_CHECK`. Each one carries a lab HMAC-SHA256 tag truncated to 128 bits. The tag covers the command fields, including the sequence counter and the command timestamp. It does not cover `received_at`, which is how a copied frame still verifies. The key id is `LAB-TEACHING-KEY`. It is in this repository on purpose so the detector can recompute tags. A real mission key does not belong in source control. Checklist item SL-04 says that plainly.

The 6-byte `ccsds_primary_header_hex` uses the public space-packet field widths (version, type, APID, sequence flags, sequence count, packet data length). It is a teaching header, not a CCSDS conformance claim and not an SDLS security header.

## What the detector checks

| Rule | Severity | What it means |
| --- | --- | --- |
| `CMD-MAC` | critical | Tag or key id does not match the teaching key |
| `CMD-REPLAY` | critical | The same authenticated bytes were logged again |
| `CMD-SEQ` | high | Command counter is not the next expected value |
| `CMD-WINDOW` | high | Receipt time is outside that station's planned AOS/LOS |
| `TM-RANGE` | high | A sensor left its engineering limit |
| `TM-ZSCORE` | medium | A value is still inside limits but far from the rest of the series |
| `TM-SEQ` | medium or high | Telemetry counter broke |

Z-scores use the population mean and standard deviation of samples that are still inside limits, and only on channels marked for it. Solar-array current is range-checked only, because eclipse legitimately drops it. A z-score also has to clear a noise floor, so the small eclipse step on temperature does not page anyone. Fewer than 20 in-range samples skips the z-score.

`detect` does not read the injection list while it is deciding. `--score` compares the finished findings with `scenario.json` afterwards. Extra findings are allowed. The demo's second `CMD-SEQ` line is one of those.

Contact windows are a planned schedule written by the simulator, not a geometric visibility product. Latitude, longitude, and the eclipse flag come from a simplified Kepler teaching model (about 520 km, period printed in `scenario.json`). Do not use them for flight dynamics.

## Checklist

`python3 -m spacelab checklist` prints twelve defensive practices for the space segment, the ground segment, and the development environment: command authentication, anti-replay, link confidentiality, key management, monitoring, audit logs, segmentation, safe mode, protection of command databases, flight-software integrity, the build environment, and contact-plan release plus incident response.

References are limited to public identifiers checked while writing the lab:

- SPARTA countermeasures, by the id and name in the Aerospace catalog (for example CM0031 Authentication, CM0030 Crypto Key Management, CM0038 Segmentation)
- NIST SP 800-53 Rev. 5 controls (for example SC-8, SC-12, SC-13, AU-2, SI-4)
- NIST CSF 1.1 categories (for example PR.AC, DE.CM, RS.RP), which is the CSF generation used by the two NIST reports below
- NIST IR 8270 (July 2023), *Introduction to Cybersecurity for Commercial Satellite Operations*
- NIST IR 8401 (December 2022), *Satellite Ground Segment: Applying the Cybersecurity Framework to Satellite Command and Control*
- CCSDS 355.0-B-2 (Space Data Link Security Protocol), CCSDS 352.0-B-2 (CCSDS Cryptographic Algorithms), and CCSDS 232.0-B-4 (TC Space Data Link Protocol)

The grouping is this lab's study aid. It is not an official mapping from NIST or The Aerospace Corporation, and it is not a certification.

## Project layout

```text
spacelab/
  __main__.py     python3 -m spacelab
  cli.py          simulate | detect | checklist | demo
  simulate.py     fictional telemetry, commands, and planted anomalies
  detect.py       defensive rules and the scoreboard
  checklist.py    hardening checklist and the reference catalog
  auth.py         teaching HMAC
  ccsds.py        6-byte primary-header helper
  catalog.py      mission limits, stations, and benign command list
tests/            unittest modules
.github/workflows/tests.yml
```

`simulate` writes `telemetry.jsonl`, `telemetry.csv`, `commands.jsonl`, `commands.csv`, `contacts.jsonl`, and `scenario.json`. Detection reads the JSONL files (CSV is accepted too) plus the scenario. `spacelab-out/` is gitignored.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

GitHub Actions runs that command, then `python3 -m spacelab demo`, on Python 3.10, 3.11, and 3.12 for pushes and pull requests.

## Roadmap

- Treat the follow-on sequence finding as part of the original jump when scoring, so the report can say "one break, two lines".
- Add a key-id rollover exercise where yesterday's tag fails closed.
- Shape a simulated security header more like SDLS (still no radio, still not a flight stack).
- Mark each checklist item with whether the detector currently exercises it.
- Let a benign heater or payload command show up later in the housekeeping stream.
- Replace the planned contact table with a clearly labelled geometric pass model, still fictional.

## Honesty note

This repository is a study project for learning defensive review of spacecraft command and telemetry logs. Running it does not operate a satellite, and the sample anomalies are records written to local files. The orbit numbers, the authentication tag, and the checklist are here to practice reading, testing, and explaining security controls.
