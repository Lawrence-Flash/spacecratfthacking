"""JSONL and CSV readers and writers for lab records."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path

TELEMETRY_COLUMNS = (
    "frame_id",
    "mission_id",
    "spacecraft_id",
    "timestamp",
    "sequence_count",
    "apid",
    "battery_voltage_v",
    "battery_temp_c",
    "payload_temp_c",
    "radio_temp_c",
    "solar_array_current_a",
    "roll_deg",
    "pitch_deg",
    "yaw_deg",
    "altitude_km",
    "latitude_deg",
    "longitude_deg",
    "in_eclipse",
    "in_contact",
    "station_id",
    "elevation_deg",
    "ccsds_primary_header_hex",
)

COMMAND_COLUMNS = (
    "frame_id",
    "mission_id",
    "spacecraft_id",
    "station_id",
    "timestamp",
    "received_at",
    "apid",
    "sequence_count",
    "opcode",
    "mnemonic",
    "parameters_json",
    "key_id",
    "mac_algorithm",
    "mac_hex",
    "in_contact_claim",
    "ccsds_primary_header_hex",
)

SENSOR_FIELDS = (
    "battery_voltage_v",
    "battery_temp_c",
    "payload_temp_c",
    "radio_temp_c",
    "solar_array_current_a",
)


def dumps(obj: dict) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [dumps(record) for record in records]
    text = "\n".join(lines)
    if text:
        text += "\n"
    path.write_text(text, encoding="utf-8")


def read_jsonl(path: Path) -> list[dict]:
    records = []
    raw = path.read_text(encoding="utf-8")
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number}: invalid JSON") from exc
        if not isinstance(item, dict):
            raise ValueError(f"{path}:{line_number}: expected an object")
        records.append(item)
    return records


def _as_int(value, field: str) -> int:
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError(f"{field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        return int(value.strip())
    raise ValueError(f"{field} must be an integer")


def _as_float(value, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError(f"{field} must be a number")
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be a number") from exc


def _as_bool(value, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in {"true", "false"}:
        return value.strip().lower() == "true"
    raise ValueError(f"{field} must be true or false")


def flatten_telemetry(frame: dict) -> dict:
    sensors = frame["sensors"]
    orbit = frame["orbit"]
    contact = frame["contact"]
    row = {
        "frame_id": frame["frame_id"],
        "mission_id": frame["mission_id"],
        "spacecraft_id": frame["spacecraft_id"],
        "timestamp": frame["timestamp"],
        "sequence_count": frame["sequence_count"],
        "apid": frame["apid"],
        "roll_deg": orbit["roll_deg"],
        "pitch_deg": orbit["pitch_deg"],
        "yaw_deg": orbit["yaw_deg"],
        "altitude_km": orbit["altitude_km"],
        "latitude_deg": orbit["latitude_deg"],
        "longitude_deg": orbit["longitude_deg"],
        "in_eclipse": "true" if orbit["in_eclipse"] else "false",
        "in_contact": "true" if contact["in_contact"] else "false",
        "station_id": contact["station_id"] or "",
        "elevation_deg": contact["elevation_deg"],
        "ccsds_primary_header_hex": frame["ccsds_primary_header_hex"],
    }
    for name in SENSOR_FIELDS:
        row[name] = sensors[name]
    return row


def flatten_command(command: dict) -> dict:
    return {
        "frame_id": command["frame_id"],
        "mission_id": command["mission_id"],
        "spacecraft_id": command["spacecraft_id"],
        "station_id": command["station_id"],
        "timestamp": command["timestamp"],
        "received_at": command["received_at"],
        "apid": command["apid"],
        "sequence_count": command["sequence_count"],
        "opcode": command["opcode"],
        "mnemonic": command["mnemonic"],
        "parameters_json": dumps(command["parameters"]),
        "key_id": command["key_id"],
        "mac_algorithm": command["mac_algorithm"],
        "mac_hex": command["mac_hex"],
        "in_contact_claim": "true" if command["in_contact_claim"] else "false",
        "ccsds_primary_header_hex": command["ccsds_primary_header_hex"],
    }


def write_csv(path: Path, columns: tuple[str, ...], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row[column] for column in columns})


def _read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def telemetry_from_flat(row: dict) -> dict:
    sensors = {name: _as_float(row[name], name) for name in SENSOR_FIELDS}
    station = row.get("station_id") or None
    return {
        "record_type": "telemetry",
        "simulated": True,
        "frame_id": row["frame_id"],
        "mission_id": row["mission_id"],
        "spacecraft_id": row["spacecraft_id"],
        "timestamp": row["timestamp"],
        "sequence_count": _as_int(row["sequence_count"], "sequence_count"),
        "apid": _as_int(row["apid"], "apid"),
        "sensors": sensors,
        "orbit": {
            "roll_deg": _as_float(row["roll_deg"], "roll_deg"),
            "pitch_deg": _as_float(row["pitch_deg"], "pitch_deg"),
            "yaw_deg": _as_float(row["yaw_deg"], "yaw_deg"),
            "altitude_km": _as_float(row["altitude_km"], "altitude_km"),
            "latitude_deg": _as_float(row["latitude_deg"], "latitude_deg"),
            "longitude_deg": _as_float(row["longitude_deg"], "longitude_deg"),
            "in_eclipse": _as_bool(row["in_eclipse"], "in_eclipse"),
        },
        "contact": {
            "in_contact": _as_bool(row["in_contact"], "in_contact"),
            "station_id": station,
            "elevation_deg": _as_float(row["elevation_deg"], "elevation_deg"),
        },
        "ccsds_primary_header_hex": row["ccsds_primary_header_hex"],
    }


def command_from_flat(row: dict) -> dict:
    parameters = json.loads(row["parameters_json"])
    if not isinstance(parameters, dict):
        raise ValueError("parameters_json must be an object")
    return {
        "record_type": "command",
        "simulated": True,
        "frame_id": row["frame_id"],
        "mission_id": row["mission_id"],
        "spacecraft_id": row["spacecraft_id"],
        "station_id": row["station_id"],
        "timestamp": row["timestamp"],
        "received_at": row["received_at"],
        "apid": _as_int(row["apid"], "apid"),
        "sequence_count": _as_int(row["sequence_count"], "sequence_count"),
        "opcode": _as_int(row["opcode"], "opcode"),
        "mnemonic": row["mnemonic"],
        "parameters": parameters,
        "key_id": row["key_id"],
        "mac_algorithm": row["mac_algorithm"],
        "mac_hex": row["mac_hex"],
        "in_contact_claim": _as_bool(row["in_contact_claim"], "in_contact_claim"),
        "ccsds_primary_header_hex": row["ccsds_primary_header_hex"],
    }


def load_telemetry(path: Path) -> list[dict]:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        return read_jsonl(path)
    if suffix == ".csv":
        return [telemetry_from_flat(row) for row in _read_csv(path)]
    raise ValueError(f"unsupported telemetry file type: {path.suffix}")


def load_commands(path: Path) -> list[dict]:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        return read_jsonl(path)
    if suffix == ".csv":
        return [command_from_flat(row) for row in _read_csv(path)]
    raise ValueError(f"unsupported command file type: {path.suffix}")
