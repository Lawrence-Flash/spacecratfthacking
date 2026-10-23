"""Terminal and JSON rendering for detection reports."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from spacelab import __version__
from spacelab.disclaimer import DISCLAIMER

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}

RULES = {
    "TM-RANGE": "Sensor value outside its engineering limit.",
    "TM-ZSCORE": "Sensor value inside its limit but far from the rest of the series.",
    "TM-SEQ": "Telemetry sequence counter is not the next expected value.",
    "CMD-MAC": "Command authentication tag does not match the lab teaching key.",
    "CMD-REPLAY": "The same authenticated command was logged more than once.",
    "CMD-SEQ": "Command sequence counter is not the next expected value.",
    "CMD-WINDOW": "Command receipt time is outside that station's planned contact.",
}


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    detail: str
    timestamp: str
    record_type: str
    evidence: dict

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "timestamp": self.timestamp,
            "record_type": self.record_type,
            "evidence": self.evidence,
        }


@dataclass
class Report:
    mission_id: str
    spacecraft_id: str
    telemetry_count: int
    command_count: int
    findings: list[Finding] = field(default_factory=list)
    scoreboard: dict | None = None
    sources: dict = field(default_factory=dict)

    def counts_by_severity(self) -> dict[str, int]:
        counts = {name: 0 for name in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def counts_by_rule(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
        return counts

    def to_dict(self) -> dict:
        payload = {
            "lab": "spacelab",
            "version": __version__,
            "disclaimer": DISCLAIMER,
            "mission_id": self.mission_id,
            "spacecraft_id": self.spacecraft_id,
            "telemetry_frames": self.telemetry_count,
            "commands": self.command_count,
            "sources": self.sources,
            "summary": {
                "findings": len(self.findings),
                "by_severity": self.counts_by_severity(),
                "by_rule": self.counts_by_rule(),
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "rules": RULES,
        }
        if self.scoreboard is not None:
            payload["scoreboard"] = self.scoreboard
        return payload


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY_RANK.get(item.severity, 0),
            item.timestamp,
            item.rule_id,
            item.title,
        ),
    )


def render_text(report: Report) -> str:
    severity_counts = report.counts_by_severity()
    parts = [
        "SpaceLab detection report",
        DISCLAIMER,
        f"Mission: {report.mission_id}    Spacecraft: {report.spacecraft_id}",
        (
            f"Telemetry frames: {report.telemetry_count}    "
            f"Commands: {report.command_count}    "
            f"Findings: {len(report.findings)}"
        ),
        (
            "Severity: "
            + ", ".join(f"{name} {severity_counts[name]}" for name in SEVERITIES)
        ),
        "",
    ]
    if not report.findings:
        parts.append(
            "No findings. Checked engineering limits, z-scores on quiet channels, "
            "telemetry sequence, command MAC, replay, command sequence, and contact windows."
        )
    else:
        for finding in report.findings:
            parts.append(
                f"{finding.severity.upper():8}  {finding.rule_id:10}  {finding.timestamp}  {finding.title}"
            )
            parts.append(f"          {finding.detail}")
        parts.append("")
        parts.append("Counts by rule: " + ", ".join(
            f"{rule} {count}" for rule, count in sorted(report.counts_by_rule().items())
        ))
    if report.scoreboard is not None:
        injected = report.scoreboard["injected"]
        matched = report.scoreboard["matched"]
        parts.extend(
            [
                "",
                f"Scoreboard: {matched}/{injected} injected anomalies were flagged by the expected rule.",
            ]
        )
        if report.scoreboard["missing"]:
            missing = ", ".join(item["rule_id"] for item in report.scoreboard["missing"])
            parts.append(f"Missing expected rules: {missing}")
    parts.append("")
    return "\n".join(parts)


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"
