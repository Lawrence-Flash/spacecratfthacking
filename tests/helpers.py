"""Shared setup for SpaceLab unit tests."""

from __future__ import annotations

from pathlib import Path

from spacelab.simulate import SimConfig, simulate


def run_sim(out_dir: Path, anomalies: list[str], **overrides):
    config = SimConfig(
        out_dir=out_dir,
        anomalies=list(anomalies),
        duration_s=overrides.pop("duration_s", 900),
        telemetry_interval_s=overrides.pop("telemetry_interval_s", 30),
        seed=overrides.pop("seed", 7),
        **overrides,
    )
    return simulate(config)
