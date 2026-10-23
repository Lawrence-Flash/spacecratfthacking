"""Command-line entry for simulate, detect, checklist, and demo."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from spacelab import __version__
from spacelab.catalog import ANOMALIES, DEFAULT_START
from spacelab.checklist import SEGMENTS, render, render_index
from spacelab.detect import analyze, limits_from_scenario, load_inputs, score_injections
from spacelab.disclaimer import DISCLAIMER
from spacelab.report import render_json, render_text
from spacelab.serialize import load_commands, load_telemetry
from spacelab.simulate import SimConfig, parse_anomaly_argument, simulate

EPILOG = f"""
examples:
  python3 -m spacelab demo
  python3 -m spacelab simulate --out-dir ./spacelab-out --anomalies none
  python3 -m spacelab detect --scenario ./spacelab-out/scenario.json
  python3 -m spacelab checklist --format md --out checklist.md

{DISCLAIMER}
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spacelab",
        description=(
            "Simulated spacecraft security lab. Generate fictional telemetry and "
            "command logs, flag anomalies with defensive rules, and print a "
            "hardening checklist."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
    )
    parser.add_argument("--version", action="version", version=f"spacelab {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    simulate_parser = commands.add_parser(
        "simulate",
        help="Write simulated telemetry, commands, and a scenario manifest",
        description=(
            "Write JSONL and CSV logs for a fictional LEO cubesat. "
            "Anomaly names edit those local files. Nothing is transmitted."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_sim_args(simulate_parser)

    detect_parser = commands.add_parser(
        "detect",
        help="Check logs and write a terminal report plus JSON",
        description=(
            "Apply engineering limits, a z-score backstop, MAC checks, replay "
            "checks, sequence checks, and the contact schedule from --scenario. "
            "Injection labels are not an input to the rules. Add --score to "
            "compare findings with the anomalies the simulator planted."
        ),
    )
    detect_parser.add_argument("--scenario", type=Path, help="scenario.json from simulate")
    detect_parser.add_argument("--telemetry", type=Path, help="telemetry .jsonl or .csv")
    detect_parser.add_argument("--commands", type=Path, help="commands .jsonl or .csv")
    detect_parser.add_argument("--json-out", type=Path, help="where to write report.json")
    detect_parser.add_argument("--z-threshold", type=float, default=4.0)
    detect_parser.add_argument("--min-z-samples", type=int, default=20)
    detect_parser.add_argument(
        "--score",
        action="store_true",
        help="compare findings with scenario injections (labels are not shown to the rules)",
    )

    checklist_parser = commands.add_parser(
        "checklist",
        help="Print the defensive hardening checklist",
        description="Print or export the study checklist. Framework ids are limited to public entries.",
    )
    checklist_parser.add_argument("--format", choices=("text", "md", "json"), default="text")
    checklist_parser.add_argument("--segment", choices=("all",) + SEGMENTS, default="all")
    checklist_parser.add_argument("--out", type=Path, help="also write the checklist to this path")

    demo_parser = commands.add_parser(
        "demo",
        help="Simulate a pass with planted anomalies, then detect them",
        description="End-to-end lab run. Prints the detection report, the scoreboard, and checklist titles.",
    )
    _add_sim_args(demo_parser, default_anomalies="all")
    return parser


def _add_sim_args(parser: argparse.ArgumentParser, default_anomalies: str = "all") -> None:
    parser.add_argument("--out-dir", type=Path, default=Path("spacelab-out"))
    parser.add_argument("--seed", type=int, default=20260621)
    parser.add_argument("--start", default=DEFAULT_START, help="UTC start, for example 2026-06-21T06:00:00Z")
    parser.add_argument("--duration-s", type=int, default=3600)
    parser.add_argument("--telemetry-interval-s", type=int, default=30)
    parser.add_argument("--command-interval-s", type=int, default=40)
    parser.add_argument(
        "--anomalies",
        default=default_anomalies,
        help=f"all, none, or a comma-separated list: {', '.join(ANOMALIES)}",
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "simulate":
            return _cmd_simulate(args)
        if args.command == "detect":
            return _cmd_detect(args)
        if args.command == "checklist":
            return _cmd_checklist(args)
        if args.command == "demo":
            return _cmd_demo(args)
    except (ValueError, OSError) as exc:
        print(f"spacelab: {exc}", file=sys.stderr)
        return 2
    parser.error(f"unknown command {args.command}")
    return 2


def _config_from_args(args: argparse.Namespace) -> SimConfig:
    return SimConfig(
        out_dir=args.out_dir,
        seed=args.seed,
        start=args.start,
        duration_s=args.duration_s,
        telemetry_interval_s=args.telemetry_interval_s,
        command_interval_s=args.command_interval_s,
        anomalies=parse_anomaly_argument(args.anomalies),
    )


def _cmd_simulate(args: argparse.Namespace) -> int:
    result = simulate(_config_from_args(args))
    counts = result.scenario["counts"]
    print(DISCLAIMER)
    print(
        f"Wrote {counts['telemetry_frames']} telemetry frames, "
        f"{counts['commands']} commands, and {counts['contacts']} contacts to {result.out_dir}"
    )
    planted = ", ".join(item["anomaly"] for item in result.injections) or "none"
    print(f"Planted anomalies: {planted}")
    return 0


def _cmd_detect(args: argparse.Namespace) -> int:
    report = _run_detect(args)
    text = render_text(report)
    print(text, end="")
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(render_json(report), encoding="utf-8")
        print(f"Wrote {args.json_out}")
    return 0


def _run_detect(args: argparse.Namespace):
    if args.scenario is None:
        raise ValueError(
            "detect needs --scenario so contact times and engineering limits are known"
        )
    scenario, telemetry, commands, sources = load_inputs(args.scenario)
    contacts = scenario.get("contacts") or []
    limits = limits_from_scenario(scenario)
    if args.telemetry is not None:
        telemetry = load_telemetry(args.telemetry)
        sources["telemetry"] = str(args.telemetry)
    if args.commands is not None:
        commands = load_commands(args.commands)
        sources["commands"] = str(args.commands)
    if not telemetry and not commands:
        raise ValueError("no telemetry or commands were loaded")
    report = analyze(
        telemetry,
        commands,
        contacts,
        limits,
        z_threshold=args.z_threshold,
        min_z_samples=args.min_z_samples,
        sources=sources,
    )
    if args.score or args.command == "demo":
        report.scoreboard = score_injections(report.findings, scenario.get("injections") or [])
    return report


def _cmd_checklist(args: argparse.Namespace) -> int:
    text = render(args.format, args.segment)
    print(text, end="")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
        print(f"Wrote {args.out}", file=sys.stderr)
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    print("SpaceLab demo")
    print(DISCLAIMER)
    print("Mission FS-1-LAB and stations CPT-LAB and JHB-LAB are fictional.")
    print()
    result = simulate(_config_from_args(args))
    counts = result.scenario["counts"]
    print(
        f"Wrote {counts['telemetry_frames']} telemetry frames and "
        f"{counts['commands']} commands to {result.out_dir}"
    )
    planted = ", ".join(item["anomaly"] for item in result.injections) or "none"
    print(f"Planted anomalies: {planted}")
    print()
    detect_args = argparse.Namespace(
        command="demo",
        scenario=result.out_dir / "scenario.json",
        telemetry=None,
        commands=None,
        json_out=result.out_dir / "report.json",
        z_threshold=4.0,
        min_z_samples=20,
        score=True,
    )
    report = _run_detect(detect_args)
    print(render_text(report), end="")
    detect_args.json_out.write_text(render_json(report), encoding="utf-8")
    print(f"Wrote {detect_args.json_out}")
    print()
    print(render_index(), end="")
    if report.scoreboard and not report.scoreboard["expected_rules_met"]:
        return 1
    return 0
