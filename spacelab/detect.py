"""Rule-based checks over simulated telemetry and command logs.

Statistical checks are a z-score backstop for values that are still inside
engineering limits. Channels with a normal eclipse swing are range-checked
only; that choice is recorded on each channel as ``zscore``.
"""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

from spacelab.auth import canonical_material, verify_mac
from spacelab.catalog import CHANNELS, channel_from_mapping
from spacelab.ccsds import SEQUENCE_MODULUS
from spacelab.report import Finding, Report, sort_findings
from spacelab.timeutil import parse_utc

SENSOR_NAMES = (
    "battery_voltage_v",
    "battery_temp_c",
    "payload_temp_c",
    "radio_temp_c",
    "solar_array_current_a",
)


def limits_from_scenario(scenario: dict) -> dict:
    raw = scenario.get("limits") or {}
    if not raw:
        return CHANNELS
    return {name: channel_from_mapping(name, payload) for name, payload in raw.items()}


def analyze(
    telemetry: list[dict],
    commands: list[dict],
    contacts: list[dict],
    limits: dict | None = None,
    *,
    z_threshold: float = 4.0,
    min_z_samples: int = 20,
    sources: dict | None = None,
) -> Report:
    """Return findings. This function does not read injection labels."""
    if z_threshold <= 0:
        raise ValueError("z_threshold must be positive")
    if min_z_samples < 2:
        raise ValueError("min_z_samples must be at least 2")
    channel_limits = limits if limits is not None else CHANNELS
    mission_id = _mission_id(telemetry, commands)
    spacecraft_id = _spacecraft_id(telemetry, commands)
    findings: list[Finding] = []
    findings.extend(_telemetry_sequence(telemetry))
    findings.extend(_range_checks(telemetry, channel_limits))
    findings.extend(
        _zscore_checks(
            telemetry,
            channel_limits,
            z_threshold=z_threshold,
            min_z_samples=min_z_samples,
        )
    )
    findings.extend(_command_checks(commands, contacts))
    return Report(
        mission_id=mission_id,
        spacecraft_id=spacecraft_id,
        telemetry_count=len(telemetry),
        command_count=len(commands),
        findings=sort_findings(findings),
        sources=sources or {},
    )


def score_injections(findings: list[Finding], injections: list[dict]) -> dict:
    """Count whether each planted anomaly produced its expected rule.

    Extra findings are allowed. A rule matches when it fired at least as many
    times as it was planted. Labels are not an input to :func:`analyze`.
    """
    expected = Counter(item["expected_rule"] for item in injections)
    found = Counter(finding.rule_id for finding in findings)
    missing = []
    for rule_id, count in sorted(expected.items()):
        if found[rule_id] < count:
            missing.append(
                {"rule_id": rule_id, "expected": count, "found": found[rule_id]}
            )
    return {
        "injected": len(injections),
        "matched": _matched_count(injections, found),
        "expected_rules_met": not missing,
        "missing": missing,
        "by_expected_rule": dict(sorted(expected.items())),
        "by_found_rule": dict(sorted(found.items())),
    }


def _matched_count(injections: list[dict], found: Counter) -> int:
    remaining = Counter(found)
    matched = 0
    for item in injections:
        rule_id = item["expected_rule"]
        if remaining[rule_id] > 0:
            remaining[rule_id] -= 1
            matched += 1
    return matched


def load_inputs(scenario_path: Path) -> tuple[dict, list[dict], list[dict], dict]:
    scenario = json_object(scenario_path)
    base = scenario_path.parent
    from spacelab.serialize import load_commands, load_telemetry

    telemetry_path = _existing(base, ("telemetry.jsonl", "telemetry.csv"))
    command_path = _existing(base, ("commands.jsonl", "commands.csv"))
    telemetry = load_telemetry(telemetry_path)
    commands = load_commands(command_path)
    contacts = scenario.get("contacts") or []
    if not isinstance(contacts, list):
        raise ValueError("scenario contacts must be a list")
    return scenario, telemetry, commands, {
        "scenario": str(scenario_path),
        "telemetry": str(telemetry_path),
        "commands": str(command_path),
    }


def json_object(path: Path) -> dict:
    import json

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain an object")
    return payload


def _existing(base: Path, names: tuple[str, ...]) -> Path:
    for name in names:
        candidate = base / name
        if candidate.is_file():
            return candidate
    raise ValueError(f"none of {', '.join(names)} found in {base}")


def _mission_id(telemetry: list[dict], commands: list[dict]) -> str:
    for record in telemetry + commands:
        if record.get("mission_id"):
            return str(record["mission_id"])
    return "UNKNOWN"


def _spacecraft_id(telemetry: list[dict], commands: list[dict]) -> str:
    for record in telemetry + commands:
        if record.get("spacecraft_id"):
            return str(record["spacecraft_id"])
    return "UNKNOWN"


def _telemetry_sequence(frames: list[dict]) -> list[Finding]:
    findings = []
    ordered = sorted(frames, key=lambda item: (item["timestamp"], item.get("frame_id", "")))
    previous = None
    for frame in ordered:
        sequence = int(frame["sequence_count"])
        if previous is None:
            if sequence != 0:
                findings.append(
                    _finding(
                        "TM-SEQ",
                        "medium",
                        "Telemetry sequence did not start at 0",
                        f"{frame['frame_id']} begins at sequence {sequence}.",
                        frame["timestamp"],
                        "telemetry",
                        {"frame_id": frame["frame_id"], "sequence_count": sequence},
                    )
                )
        else:
            expected = (previous + 1) % SEQUENCE_MODULUS
            if sequence != expected:
                gap = (sequence - expected) % SEQUENCE_MODULUS
                findings.append(
                    _finding(
                        "TM-SEQ",
                        "high" if gap != 1 else "medium",
                        "Telemetry sequence break",
                        f"{frame['frame_id']} sequence {sequence}, expected {expected}.",
                        frame["timestamp"],
                        "telemetry",
                        {"frame_id": frame["frame_id"], "sequence_count": sequence, "expected": expected},
                    )
                )
        previous = sequence
    return findings


def _range_checks(frames: list[dict], limits: dict) -> list[Finding]:
    findings = []
    for frame in frames:
        sensors = frame.get("sensors") or {}
        for name in SENSOR_NAMES:
            if name not in sensors or name not in limits:
                continue
            value = float(sensors[name])
            channel = limits[name]
            if channel.minimum <= value <= channel.maximum:
                continue
            findings.append(
                _finding(
                    "TM-RANGE",
                    "high",
                    f"{name} outside engineering limits",
                    (
                        f"{frame['frame_id']} {name}={value:g} {channel.unit} "
                        f"is outside [{channel.minimum:g}, {channel.maximum:g}]."
                    ),
                    frame["timestamp"],
                    "telemetry",
                    {
                        "frame_id": frame["frame_id"],
                        "channel": name,
                        "value": value,
                        "minimum": channel.minimum,
                        "maximum": channel.maximum,
                    },
                )
            )
    return findings


def _zscore_checks(
    frames: list[dict],
    limits: dict,
    *,
    z_threshold: float,
    min_z_samples: int,
) -> list[Finding]:
    findings = []
    ordered = sorted(frames, key=lambda item: item["timestamp"])
    for name in SENSOR_NAMES:
        channel = limits.get(name)
        if channel is None or not channel.zscore:
            continue
        samples = []
        for frame in ordered:
            sensors = frame.get("sensors") or {}
            if name not in sensors:
                continue
            value = float(sensors[name])
            if channel.minimum <= value <= channel.maximum:
                samples.append((frame, value))
        if len(samples) < min_z_samples:
            continue
        values = [value for _, value in samples]
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / len(values)
        std = math.sqrt(variance)
        if std < 1e-12:
            continue
        for frame, value in samples:
            delta = abs(value - mean)
            score = delta / std
            if score < z_threshold or delta < channel.noise_floor:
                continue
            findings.append(
                _finding(
                    "TM-ZSCORE",
                    "medium",
                    f"{name} is a statistical outlier",
                    (
                        f"{frame['frame_id']} {name}={value:g} {channel.unit} "
                        f"is {score:.1f} standard deviations from the in-range mean {mean:.3f}."
                    ),
                    frame["timestamp"],
                    "telemetry",
                    {
                        "frame_id": frame["frame_id"],
                        "channel": name,
                        "value": value,
                        "mean": round(mean, 4),
                        "std": round(std, 4),
                        "z": round(score, 3),
                    },
                )
            )
    return findings


def _command_checks(commands: list[dict], contacts: list[dict]) -> list[Finding]:
    findings = []
    ordered = sorted(commands, key=lambda item: (item["received_at"], item.get("frame_id", "")))
    seen: dict[bytes, dict] = {}
    previous = None
    for command in ordered:
        mac_ok = verify_mac(command)
        if not mac_ok:
            findings.append(
                _finding(
                    "CMD-MAC",
                    "critical",
                    "Command authentication tag failed",
                    (
                        f"{command['frame_id']} {command['mnemonic']} sequence "
                        f"{command['sequence_count']} tag does not verify with {command.get('key_id')}."
                    ),
                    command["received_at"],
                    "command",
                    {
                        "frame_id": command["frame_id"],
                        "mnemonic": command["mnemonic"],
                        "sequence_count": command["sequence_count"],
                        "key_id": command.get("key_id"),
                    },
                )
            )
        if not _inside_station_window(command, contacts):
            findings.append(
                _finding(
                    "CMD-WINDOW",
                    "high",
                    "Command outside the planned contact",
                    (
                        f"{command['frame_id']} received at {command['received_at']} "
                        f"on {command['station_id']} is outside that station's AOS/LOS schedule. "
                        "The log's in-contact claim is not used."
                    ),
                    command["received_at"],
                    "command",
                    {
                        "frame_id": command["frame_id"],
                        "station_id": command["station_id"],
                        "received_at": command["received_at"],
                        "in_contact_claim": command.get("in_contact_claim"),
                    },
                )
            )
        identity = canonical_material(command) + str(command.get("mac_hex", "")).lower().encode("ascii")
        if identity in seen:
            first = seen[identity]
            tag_note = (
                "The tag matches the first copy because receipt time is outside the MAC."
                if mac_ok
                else "The repeated copy also fails the lab MAC."
            )
            findings.append(
                _finding(
                    "CMD-REPLAY",
                    "critical",
                    "Authenticated command repeated",
                    (
                        f"{command['frame_id']} repeats {first['frame_id']} "
                        f"({command['mnemonic']} sequence {command['sequence_count']}). "
                        f"First receipt {first['received_at']}, later receipt {command['received_at']}. "
                        f"{tag_note}"
                    ),
                    command["received_at"],
                    "command",
                    {
                        "frame_id": command["frame_id"],
                        "first_frame_id": first["frame_id"],
                        "first_received_at": first["received_at"],
                        "sequence_count": command["sequence_count"],
                        "mnemonic": command["mnemonic"],
                    },
                )
            )
            continue
        seen[identity] = command
        sequence = int(command["sequence_count"])
        if previous is None:
            if sequence != 0:
                findings.append(_sequence_finding(command, expected=0))
        else:
            expected = (previous + 1) % SEQUENCE_MODULUS
            if sequence != expected:
                findings.append(_sequence_finding(command, expected=expected))
        previous = sequence
    return findings


def _sequence_finding(command: dict, *, expected: int) -> Finding:
    sequence = int(command["sequence_count"])
    delta = (sequence - expected) % SEQUENCE_MODULUS
    direction = "gap" if 0 < delta < SEQUENCE_MODULUS // 2 else "backwards or duplicate"
    mac_note = "The lab MAC still verifies over the logged counter." if verify_mac(command) else (
        "The lab MAC does not verify either."
    )
    return _finding(
        "CMD-SEQ",
        "high",
        "Command sequence break",
        (
            f"{command['frame_id']} sequence {sequence}, expected {expected} ({direction}). {mac_note}"
        ),
        command["received_at"],
        "command",
        {
            "frame_id": command["frame_id"],
            "sequence_count": sequence,
            "expected": expected,
        },
    )


def _inside_station_window(command: dict, contacts: list[dict]) -> bool:
    moment = parse_utc(command["received_at"])
    station = command.get("station_id")
    for contact in contacts:
        if contact.get("station_id") != station:
            continue
        if parse_utc(contact["aos"]) <= moment <= parse_utc(contact["los"]):
            return True
    return False


def _finding(
    rule_id: str,
    severity: str,
    title: str,
    detail: str,
    timestamp: str,
    record_type: str,
    evidence: dict,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        detail=detail,
        timestamp=timestamp,
        record_type=record_type,
        evidence=evidence,
    )
