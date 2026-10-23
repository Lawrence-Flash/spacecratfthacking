"""Fictional mission constants and engineering limits.

FS-1-LAB, CPT-LAB, and JHB-LAB are not real spacecraft or ground stations.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

MISSION_ID = "FS-1-LAB"
SPACECRAFT_ID = "FS-1"
DEFAULT_START = "2026-06-21T06:00:00Z"
ALTITUDE_KM = 520.0
INCLINATION_DEG = 97.4

TM_APID = 1
TM_APID_NAME = "HOUSEKEEPING"
TC_APID = 100
TC_APID_NAME = "TELECOMMAND"

# Ordinary housekeeping and payload-power commands. No contingency bypass,
# no memory dump, and no command that would change a security mode.
COMMAND_CATALOG = (
    {"opcode": 0x01, "mnemonic": "NOOP", "parameters": {}},
    {"opcode": 0x10, "mnemonic": "SET_ADCS_MODE", "parameters": {"mode": "NADIR"}},
    {"opcode": 0x11, "mnemonic": "SET_HEATER", "parameters": {"zone": "BATTERY", "state": "ON"}},
    {"opcode": 0x11, "mnemonic": "SET_HEATER", "parameters": {"zone": "BATTERY", "state": "OFF"}},
    {"opcode": 0x20, "mnemonic": "REQUEST_HOUSEKEEPING", "parameters": {"subset": "EPS"}},
    {"opcode": 0x30, "mnemonic": "SET_PAYLOAD_POWER", "parameters": {"state": "ON"}},
    {"opcode": 0x30, "mnemonic": "SET_PAYLOAD_POWER", "parameters": {"state": "OFF"}},
    {"opcode": 0x40, "mnemonic": "COMM_CHECK", "parameters": {"check_id": 1}},
)

STATIONS = (
    {
        "station_id": "CPT-LAB",
        "station_name": "Cape Town lab (fictional)",
        "latitude_deg": -33.9249,
        "longitude_deg": 18.4241,
    },
    {
        "station_id": "JHB-LAB",
        "station_name": "Johannesburg lab (fictional)",
        "latitude_deg": -26.2041,
        "longitude_deg": 28.0473,
    },
)

ANOMALIES = (
    "replay",
    "out_of_sequence",
    "bad_mac",
    "outside_contact",
    "out_of_range",
    "statistical_outlier",
)

EXPECTED_RULE = {
    "replay": "CMD-REPLAY",
    "out_of_sequence": "CMD-SEQ",
    "bad_mac": "CMD-MAC",
    "outside_contact": "CMD-WINDOW",
    "out_of_range": "TM-RANGE",
    "statistical_outlier": "TM-ZSCORE",
}


@dataclass(frozen=True)
class Channel:
    minimum: float
    maximum: float
    nominal: float
    noise: float
    unit: str
    zscore: bool = False
    noise_floor: float = 0.0
    eclipse_delta: float = 0.0

    def as_dict(self) -> dict:
        return asdict(self)


# noise is the half-width of the uniform teaching noise. noise_floor is the
# smallest absolute deviation a z-score finding will report, set above the
# eclipse step so a normal day/night change is not paged as an anomaly.
CHANNELS = {
    "battery_voltage_v": Channel(7.2, 8.4, 8.12, 0.02, "V", True, 0.15, -0.07),
    "battery_temp_c": Channel(0.0, 40.0, 18.0, 0.3, "C", True, 2.0, -1.0),
    "payload_temp_c": Channel(-10.0, 45.0, 21.0, 0.3, "C", True, 2.0, -0.5),
    "radio_temp_c": Channel(0.0, 50.0, 30.0, 0.4, "C", True, 2.0, -0.5),
    "solar_array_current_a": Channel(0.0, 2.5, 1.05, 0.03, "A", False, 0.0, -1.0),
}


def channels_as_dict() -> dict:
    return {name: channel.as_dict() for name, channel in CHANNELS.items()}


def channel_from_mapping(name: str, payload: dict) -> Channel:
    try:
        return Channel(
            minimum=float(payload["minimum"]),
            maximum=float(payload["maximum"]),
            nominal=float(payload.get("nominal", 0.0)),
            noise=float(payload.get("noise", 0.0)),
            unit=str(payload.get("unit", "")),
            zscore=bool(payload.get("zscore", False)),
            noise_floor=float(payload.get("noise_floor", 0.0)),
            eclipse_delta=float(payload.get("eclipse_delta", 0.0)),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"channel {name} limits are incomplete") from exc
