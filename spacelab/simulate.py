"""Generate fictional telemetry frames and ground-command logs.

Anomaly options edit those local records so the detector has something to
find. Nothing is transmitted.
"""

from __future__ import annotations

import copy
import json
import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from spacelab import __version__
from spacelab.auth import canonical_material, compute_mac, mac_metadata
from spacelab.catalog import (
    ALTITUDE_KM,
    ANOMALIES,
    CHANNELS,
    COMMAND_CATALOG,
    DEFAULT_START,
    EXPECTED_RULE,
    INCLINATION_DEG,
    MISSION_ID,
    SPACECRAFT_ID,
    STATIONS,
    TC_APID,
    TC_APID_NAME,
    TM_APID,
    TM_APID_NAME,
    Channel,
    channels_as_dict,
)
from spacelab.ccsds import SEQUENCE_MODULUS, build_primary_header
from spacelab.disclaimer import DISCLAIMER
from spacelab.serialize import (
    COMMAND_COLUMNS,
    TELEMETRY_COLUMNS,
    flatten_command,
    flatten_telemetry,
    write_csv,
    write_jsonl,
)
from spacelab.timeutil import add_seconds, format_utc, parse_utc

MU_KM3_S2 = 398600.4418
EARTH_RADIUS_KM = 6371.0
EARTH_ROTATION_DEG_S = 360.0 / 86400.0


@dataclass
class SimConfig:
    out_dir: Path
    seed: int = 20260621
    start: str = DEFAULT_START
    duration_s: int = 3600
    telemetry_interval_s: int = 30
    command_interval_s: int = 40
    anomalies: list[str] = field(default_factory=lambda: list(ANOMALIES))
    mission_id: str = MISSION_ID
    spacecraft_id: str = SPACECRAFT_ID

    def validate(self) -> None:
        if self.duration_s < self.telemetry_interval_s:
            raise ValueError("duration must cover at least one telemetry interval")
        if self.telemetry_interval_s < 1 or self.command_interval_s < 1:
            raise ValueError("intervals must be positive")
        unknown = [name for name in self.anomalies if name not in ANOMALIES]
        if unknown:
            raise ValueError(f"unknown anomalies: {', '.join(unknown)}")


@dataclass
class SimResult:
    out_dir: Path
    telemetry: list[dict]
    commands: list[dict]
    contacts: list[dict]
    injections: list[dict]
    scenario: dict


def orbital_period_s(altitude_km: float = ALTITUDE_KM) -> float:
    semi_major = EARTH_RADIUS_KM + altitude_km
    return 2.0 * math.pi * math.sqrt(semi_major**3 / MU_KM3_S2)


def plan_contacts(start: datetime, duration_s: int) -> list[dict]:
    """Place one or two fictional passes inside the scenario window.

    Pass times are a planned schedule, not a geometric visibility product.
    Elevation during a pass is a cosine profile so logs look like a contact.
    """
    pass_len = int(min(600, max(120, round(duration_s * 0.2))))
    fractions = (0.12, 0.55)
    contacts = []
    for index, fraction in enumerate(fractions):
        aos_offset = int(duration_s * fraction)
        los_offset = aos_offset + pass_len
        if los_offset > duration_s - 5:
            continue
        station = STATIONS[index]
        aos = start + timedelta(seconds=aos_offset)
        los = start + timedelta(seconds=los_offset)
        contacts.append(
            {
                "station_id": station["station_id"],
                "station_name": station["station_name"],
                "latitude_deg": station["latitude_deg"],
                "longitude_deg": station["longitude_deg"],
                "aos": format_utc(aos),
                "los": format_utc(los),
                "fictional": True,
            }
        )
    if contacts:
        return contacts
    if duration_s < 40:
        return []
    station = STATIONS[0]
    aos = start + timedelta(seconds=5)
    los = start + timedelta(seconds=duration_s - 5)
    return [
        {
            "station_id": station["station_id"],
            "station_name": station["station_name"],
            "latitude_deg": station["latitude_deg"],
            "longitude_deg": station["longitude_deg"],
            "aos": format_utc(aos),
            "los": format_utc(los),
            "fictional": True,
        }
    ]


def _pass_elevation(moment: datetime, aos: str, los: str) -> float:
    start = parse_utc(aos)
    end = parse_utc(los)
    if moment < start or moment > end or start == end:
        return 0.0
    half = (end - start).total_seconds() / 2.0
    mid = start + timedelta(seconds=half)
    fraction = (moment - mid).total_seconds() / half
    shape = math.cos(fraction * math.pi / 2.0)
    return round(10.0 + 45.0 * shape, 2)


def contact_at(moment: datetime, contacts: list[dict]) -> dict:
    for contact in contacts:
        aos = parse_utc(contact["aos"])
        los = parse_utc(contact["los"])
        if aos <= moment <= los:
            return {
                "in_contact": True,
                "station_id": contact["station_id"],
                "elevation_deg": _pass_elevation(moment, contact["aos"], contact["los"]),
            }
    return {"in_contact": False, "station_id": None, "elevation_deg": 0.0}


def _in_eclipse(offset_s: float, period_s: float) -> bool:
    phase = (offset_s % period_s) / period_s
    return 0.325 <= phase <= 0.675


def _lat_lon(offset_s: float, period_s: float) -> tuple[float, float]:
    theta = 2.0 * math.pi * (offset_s / period_s)
    sine = math.sin(math.radians(INCLINATION_DEG)) * math.sin(theta)
    sine = max(-1.0, min(1.0, sine))
    latitude = math.degrees(math.asin(sine))
    longitude = 18.4241 + math.degrees(theta) - offset_s * EARTH_ROTATION_DEG_S
    longitude = ((longitude + 180.0) % 360.0) - 180.0
    return round(latitude, 4), round(longitude, 4)


def _sample_channel(rng: random.Random, channel: Channel, eclipse: bool) -> float:
    center = channel.nominal + (channel.eclipse_delta if eclipse else 0.0)
    value = center + rng.uniform(-channel.noise, channel.noise)
    return round(value, 4)


def _telemetry_payload(frame: dict) -> bytes:
    body = {
        "mission_id": frame["mission_id"],
        "spacecraft_id": frame["spacecraft_id"],
        "timestamp": frame["timestamp"],
        "sequence_count": frame["sequence_count"],
        "sensors": frame["sensors"],
        "orbit": frame["orbit"],
        "contact": frame["contact"],
    }
    from spacelab.serialize import dumps

    return dumps(body).encode("utf-8")


def _apply_header(record: dict, *, telemetry: bool, payload: bytes) -> None:
    record["ccsds_primary_header_hex"] = build_primary_header(
        telemetry=telemetry,
        apid=record["apid"],
        sequence_count=record["sequence_count"],
        data_length=len(payload),
    )


def _seal_command(command: dict) -> None:
    meta = mac_metadata()
    command["key_id"] = meta["key_id"]
    command["mac_algorithm"] = meta["mac_algorithm"]
    command["mac_hex"] = compute_mac(command)
    payload = canonical_material(command) + bytes.fromhex(command["mac_hex"])
    _apply_header(command, telemetry=False, payload=payload)


def _corrupt_mac(command: dict) -> None:
    chars = list(command["mac_hex"])
    chars[-1] = "1" if chars[-1] != "1" else "0"
    command["mac_hex"] = "".join(chars)


def build_telemetry(config: SimConfig, contacts: list[dict], rng: random.Random) -> list[dict]:
    start = parse_utc(config.start)
    period = orbital_period_s()
    frames = []
    count = config.duration_s // config.telemetry_interval_s
    for index in range(count):
        offset = index * config.telemetry_interval_s
        moment = start + timedelta(seconds=offset)
        eclipse = _in_eclipse(offset, period)
        latitude, longitude = _lat_lon(offset, period)
        yaw = round((offset * 0.05) % 360.0, 4)
        if yaw > 180:
            yaw = round(yaw - 360.0, 4)
        frame = {
            "record_type": "telemetry",
            "simulated": True,
            "frame_id": f"TM-{index:06d}",
            "mission_id": config.mission_id,
            "spacecraft_id": config.spacecraft_id,
            "timestamp": format_utc(moment),
            "sequence_count": index % SEQUENCE_MODULUS,
            "apid": TM_APID,
            "apid_name": TM_APID_NAME,
            "sensors": {
                name: _sample_channel(rng, channel, eclipse)
                for name, channel in CHANNELS.items()
            },
            "orbit": {
                "altitude_km": round(ALTITUDE_KM + 3.0 * math.sin(offset / period * 2 * math.pi), 3),
                "latitude_deg": latitude,
                "longitude_deg": longitude,
                "in_eclipse": eclipse,
                "roll_deg": round(0.4 * math.sin(offset / 120.0), 3),
                "pitch_deg": round(0.3 * math.cos(offset / 150.0), 3),
                "yaw_deg": yaw,
            },
            "contact": contact_at(moment, contacts),
        }
        _apply_header(frame, telemetry=True, payload=_telemetry_payload(frame))
        frames.append(frame)
    return frames


def build_commands(config: SimConfig, contacts: list[dict]) -> list[dict]:
    commands = []
    sequence = 0
    for contact in contacts:
        cursor = parse_utc(contact["aos"]) + timedelta(seconds=10)
        end = parse_utc(contact["los"])
        while cursor <= end:
            spec = COMMAND_CATALOG[sequence % len(COMMAND_CATALOG)]
            stamp = format_utc(cursor)
            command = {
                "record_type": "command",
                "simulated": True,
                "frame_id": f"TC-{sequence:06d}",
                "mission_id": config.mission_id,
                "spacecraft_id": config.spacecraft_id,
                "station_id": contact["station_id"],
                "timestamp": stamp,
                "received_at": stamp,
                "apid": TC_APID,
                "apid_name": TC_APID_NAME,
                "sequence_count": sequence % SEQUENCE_MODULUS,
                "opcode": spec["opcode"],
                "mnemonic": spec["mnemonic"],
                "parameters": copy.deepcopy(spec["parameters"]),
                "in_contact_claim": True,
            }
            _seal_command(command)
            commands.append(command)
            sequence += 1
            cursor += timedelta(seconds=config.command_interval_s)
    return commands


def _gap_timestamp(contacts: list[dict], start: datetime, duration_s: int) -> str | None:
    if len(contacts) >= 2:
        first_los = parse_utc(contacts[0]["los"])
        second_aos = parse_utc(contacts[1]["aos"])
        gap = (second_aos - first_los).total_seconds()
        if gap >= 30:
            return format_utc(first_los + timedelta(seconds=gap / 2))
    if contacts:
        first_aos = parse_utc(contacts[0]["aos"])
        if (first_aos - start).total_seconds() >= 20:
            return format_utc(start + timedelta(seconds=5))
        last_los = parse_utc(contacts[-1]["los"])
        scenario_end = start + timedelta(seconds=duration_s)
        if (scenario_end - last_los).total_seconds() >= 20:
            return format_utc(last_los + timedelta(seconds=10))
    return None


def _renumber(commands: list[dict]) -> None:
    commands.sort(key=lambda item: (item["received_at"], item["frame_id"]))
    for index, command in enumerate(commands):
        command["sequence_count"] = index % SEQUENCE_MODULUS
        command["frame_id"] = f"TC-{index:06d}"
        _seal_command(command)


def apply_anomalies(
    config: SimConfig,
    telemetry: list[dict],
    commands: list[dict],
    contacts: list[dict],
) -> list[dict]:
    requested = list(dict.fromkeys(config.anomalies))
    if not requested:
        return []
    start = parse_utc(config.start)
    injections: list[dict] = []
    outside_stamp: str | None = None

    if "outside_contact" in requested:
        if not commands:
            raise ValueError("duration is too short to place command anomalies")
        stamp = _gap_timestamp(contacts, start, config.duration_s)
        if stamp is None:
            raise ValueError("could not place a command outside a contact window")
        outside_stamp = stamp
        spec = COMMAND_CATALOG[0]
        extra = {
            "record_type": "command",
            "simulated": True,
            "frame_id": "TC-OUTSIDE",
            "mission_id": config.mission_id,
            "spacecraft_id": config.spacecraft_id,
            "station_id": contacts[0]["station_id"],
            "timestamp": stamp,
            "received_at": stamp,
            "apid": TC_APID,
            "apid_name": TC_APID_NAME,
            "sequence_count": 0,
            "opcode": spec["opcode"],
            "mnemonic": spec["mnemonic"],
            "parameters": copy.deepcopy(spec["parameters"]),
            # The log claims the pass is open. The detector must use the schedule.
            "in_contact_claim": True,
        }
        commands.append(extra)
        _renumber(commands)
        injections.append(
            {
                "anomaly": "outside_contact",
                "expected_rule": EXPECTED_RULE["outside_contact"],
                "record_type": "command",
                "timestamp": stamp,
                "note": "Command time falls outside every planned contact. The in-contact claim is still true.",
            }
        )

    if any(name in requested for name in ("out_of_sequence", "bad_mac", "replay")) and len(commands) < 4:
        raise ValueError("need at least four commands to plant sequence, MAC, or replay anomalies")

    def eligible_indexes() -> list[int]:
        return [
            item
            for item, command in enumerate(commands)
            if command["received_at"] != outside_stamp
        ]

    if "out_of_sequence" in requested:
        eligible = eligible_indexes()
        if len(eligible) < 3:
            raise ValueError("need at least three in-contact commands to plant a sequence anomaly")
        index = eligible[len(eligible) // 2]
        command = commands[index]
        command["sequence_count"] = (command["sequence_count"] + 25) % SEQUENCE_MODULUS
        _seal_command(command)
        injections.append(
            {
                "anomaly": "out_of_sequence",
                "expected_rule": EXPECTED_RULE["out_of_sequence"],
                "record_type": "command",
                "timestamp": command["received_at"],
                "frame_id": command["frame_id"],
                "note": "Sequence counter jumps by 25 and the lab MAC is recomputed over the new counter.",
            }
        )
    else:
        index = None

    if "bad_mac" in requested:
        eligible = [item for item in eligible_indexes() if item != index]
        if not eligible:
            raise ValueError("need a separate in-contact command to plant a bad MAC")
        mac_index = eligible[len(eligible) // 3]
        command = commands[mac_index]
        _corrupt_mac(command)
        injections.append(
            {
                "anomaly": "bad_mac",
                "expected_rule": EXPECTED_RULE["bad_mac"],
                "record_type": "command",
                "timestamp": command["received_at"],
                "frame_id": command["frame_id"],
                "note": "Authentication tag was altered after sealing. The command bytes otherwise stay as logged.",
            }
        )
    else:
        mac_index = None

    if "replay" in requested:
        candidates = [item for item in eligible_indexes() if item not in {index, mac_index}]
        replay_index = candidates[0]
        source = commands[replay_index]
        duplicate = copy.deepcopy(source)
        duplicate["frame_id"] = source["frame_id"] + "-R"
        duplicate["received_at"] = add_seconds(source["received_at"], 15)
        duplicate["in_contact_claim"] = True
        commands.append(duplicate)
        commands.sort(key=lambda item: (item["received_at"], item["frame_id"]))
        injections.append(
            {
                "anomaly": "replay",
                "expected_rule": EXPECTED_RULE["replay"],
                "record_type": "command",
                "timestamp": duplicate["received_at"],
                "frame_id": duplicate["frame_id"],
                "note": "Same authenticated fields and tag logged again 15 seconds later. Receipt time is not inside the tag.",
            }
        )

    if "out_of_range" in requested:
        if not telemetry:
            raise ValueError("no telemetry frame is available for an out-of-range value")
        oor_index = len(telemetry) // 4
        frame = telemetry[oor_index]
        frame["sensors"]["battery_temp_c"] = 95.0
        _apply_header(frame, telemetry=True, payload=_telemetry_payload(frame))
        injections.append(
            {
                "anomaly": "out_of_range",
                "expected_rule": EXPECTED_RULE["out_of_range"],
                "record_type": "telemetry",
                "timestamp": frame["timestamp"],
                "frame_id": frame["frame_id"],
                "channel": "battery_temp_c",
                "value": 95.0,
                "note": "Battery temperature set outside the engineering limit.",
            }
        )
    else:
        oor_index = None

    if "statistical_outlier" in requested:
        if not telemetry:
            raise ValueError("no telemetry frame is available for a statistical outlier")
        stat_index = (3 * len(telemetry)) // 4
        if stat_index == oor_index:
            stat_index = len(telemetry) - 1 if oor_index != len(telemetry) - 1 else 0
        frame = telemetry[stat_index]
        # Inside the 0..40 C limit, far from the nominal cluster.
        frame["sensors"]["battery_temp_c"] = 39.0
        _apply_header(frame, telemetry=True, payload=_telemetry_payload(frame))
        injections.append(
            {
                "anomaly": "statistical_outlier",
                "expected_rule": EXPECTED_RULE["statistical_outlier"],
                "record_type": "telemetry",
                "timestamp": frame["timestamp"],
                "frame_id": frame["frame_id"],
                "channel": "battery_temp_c",
                "value": 39.0,
                "note": "Battery temperature kept inside the hard limit but far from the rest of the pass.",
            }
        )

    order = {name: index for index, name in enumerate(ANOMALIES)}
    injections.sort(key=lambda item: order[item["anomaly"]])
    return injections


def simulate(config: SimConfig) -> SimResult:
    config.validate()
    start = parse_utc(config.start)
    contacts = plan_contacts(start, config.duration_s)
    rng = random.Random(config.seed)
    telemetry = build_telemetry(config, contacts, rng)
    commands = build_commands(config, contacts)
    injections = apply_anomalies(config, telemetry, commands, contacts)
    period = round(orbital_period_s(), 3)
    scenario = {
        "lab": "spacelab",
        "version": __version__,
        "disclaimer": DISCLAIMER,
        "seed": config.seed,
        "mission_id": config.mission_id,
        "spacecraft_id": config.spacecraft_id,
        "start": format_utc(start),
        "duration_s": config.duration_s,
        "telemetry_interval_s": config.telemetry_interval_s,
        "command_interval_s": config.command_interval_s,
        "anomalies_requested": list(config.anomalies),
        "orbit_model": {
            "kind": "simplified-kepler-teaching",
            "altitude_km": ALTITUDE_KM,
            "inclination_deg": INCLINATION_DEG,
            "period_s": period,
            "note": "Latitude, longitude, and eclipse are a classroom model, not a flight propagator.",
        },
        "contacts": contacts,
        "limits": channels_as_dict(),
        "injections": injections,
        "counts": {
            "telemetry_frames": len(telemetry),
            "commands": len(commands),
            "contacts": len(contacts),
        },
    }
    out = config.out_dir
    out.mkdir(parents=True, exist_ok=True)
    write_jsonl(out / "telemetry.jsonl", telemetry)
    write_jsonl(out / "commands.jsonl", commands)
    write_jsonl(out / "contacts.jsonl", contacts)
    write_csv(out / "telemetry.csv", TELEMETRY_COLUMNS, [flatten_telemetry(item) for item in telemetry])
    write_csv(out / "commands.csv", COMMAND_COLUMNS, [flatten_command(item) for item in commands])
    (out / "scenario.json").write_text(
        json.dumps(scenario, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return SimResult(
        out_dir=out,
        telemetry=telemetry,
        commands=commands,
        contacts=contacts,
        injections=injections,
        scenario=scenario,
    )


def parse_anomaly_argument(text: str) -> list[str]:
    cleaned = text.strip().lower()
    if cleaned == "all":
        return list(ANOMALIES)
    if cleaned == "none":
        return []
    parts = [part.strip() for part in cleaned.split(",") if part.strip()]
    if not parts:
        raise ValueError("anomaly list is empty; use 'all', 'none', or a comma-separated list")
    unknown = [part for part in parts if part not in ANOMALIES]
    if unknown:
        known = ", ".join(ANOMALIES)
        raise ValueError(f"unknown anomalies: {', '.join(unknown)}. Choose from {known}, all, none.")
    unique: list[str] = []
    for part in parts:
        if part not in unique:
            unique.append(part)
    return unique
