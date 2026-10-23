"""Defensive hardening checklist for a fictional spacecraft and ground segment.

Framework identifiers here are limited to public entries checked while writing
this lab. SPARTA countermeasure numbers and names come from the Aerospace
SPARTA catalog. NIST SP 800-53 identifiers are Rev. 5. NIST CSF identifiers
are version 1.1 categories, which is the CSF generation used by NIST IR 8270
(July 2023) and NIST IR 8401 (December 2022). This file is a study aid, not
an official control allocation or a certification claim.
"""

from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass

from spacelab.disclaimer import DISCLAIMER

NOTE = (
    "Study checklist only. Identifiers are real public entries; the grouping "
    "is this lab's, not an official mapping published by NIST or The Aerospace "
    "Corporation. No certification is implied."
)


@dataclass(frozen=True)
class Reference:
    framework: str
    identifier: str
    title: str
    url: str

    def label(self) -> str:
        return f"{self.framework} {self.identifier} — {self.title}"


@dataclass(frozen=True)
class CheckItem:
    check_id: str
    title: str
    segments: tuple[str, ...]
    summary: str
    practices: tuple[str, ...]
    reference_ids: tuple[str, ...]


REFERENCES: dict[str, Reference] = {
    "CM0001": Reference(
        "SPARTA",
        "CM0001",
        "Protect Sensitive Information",
        "https://sparta.aerospace.org/countermeasures/CM0001",
    ),
    "CM0002": Reference(
        "SPARTA",
        "CM0002",
        "COMSEC",
        "https://sparta.aerospace.org/countermeasures/CM0002",
    ),
    "CM0004": Reference(
        "SPARTA",
        "CM0004",
        "Development Environment Security",
        "https://sparta.aerospace.org/countermeasures/CM0004",
    ),
    "CM0005": Reference(
        "SPARTA",
        "CM0005",
        "Ground-based Countermeasures",
        "https://sparta.aerospace.org/countermeasures/CM0005",
    ),
    "CM0006": Reference(
        "SPARTA",
        "CM0006",
        "Cloaking Safe-mode",
        "https://sparta.aerospace.org/countermeasures/CM0006",
    ),
    "CM0008": Reference(
        "SPARTA",
        "CM0008",
        "Security Testing Results",
        "https://sparta.aerospace.org/countermeasures/CM0008",
    ),
    "CM0012": Reference(
        "SPARTA",
        "CM0012",
        "Software Bill of Materials",
        "https://sparta.aerospace.org/countermeasures/CM0012",
    ),
    "CM0014": Reference(
        "SPARTA",
        "CM0014",
        "Secure boot",
        "https://sparta.aerospace.org/countermeasures/CM0014",
    ),
    "CM0021": Reference(
        "SPARTA",
        "CM0021",
        "Software Digital Signature",
        "https://sparta.aerospace.org/countermeasures/CM0021",
    ),
    "CM0023": Reference(
        "SPARTA",
        "CM0023",
        "Configuration Management",
        "https://sparta.aerospace.org/countermeasures/CM0023",
    ),
    "CM0025": Reference(
        "SPARTA",
        "CM0025",
        "Supplier Review",
        "https://sparta.aerospace.org/countermeasures/CM0025",
    ),
    "CM0030": Reference(
        "SPARTA",
        "CM0030",
        "Crypto Key Management",
        "https://sparta.aerospace.org/countermeasures/CM0030",
    ),
    "CM0031": Reference(
        "SPARTA",
        "CM0031",
        "Authentication",
        "https://sparta.aerospace.org/countermeasures/CM0031",
    ),
    "CM0032": Reference(
        "SPARTA",
        "CM0032",
        "On-board Intrusion Detection & Prevention",
        "https://sparta.aerospace.org/countermeasures/CM0032",
    ),
    "CM0034": Reference(
        "SPARTA",
        "CM0034",
        "Monitor Critical Telemetry Points",
        "https://sparta.aerospace.org/countermeasures/CM0034",
    ),
    "CM0035": Reference(
        "SPARTA",
        "CM0035",
        "Protect Authenticators",
        "https://sparta.aerospace.org/countermeasures/CM0035",
    ),
    "CM0038": Reference(
        "SPARTA",
        "CM0038",
        "Segmentation",
        "https://sparta.aerospace.org/countermeasures/CM0038",
    ),
    "CM0039": Reference(
        "SPARTA",
        "CM0039",
        "Least Privilege",
        "https://sparta.aerospace.org/countermeasures/CM0039",
    ),
    "CM0050": Reference(
        "SPARTA",
        "CM0050",
        "On-board Message Encryption",
        "https://sparta.aerospace.org/countermeasures/CM0050",
    ),
    "CM0054": Reference(
        "SPARTA",
        "CM0054",
        "Two-Person Rule",
        "https://sparta.aerospace.org/countermeasures/CM0054",
    ),
    "CM0055": Reference(
        "SPARTA",
        "CM0055",
        "Secure Command Mode(s)",
        "https://sparta.aerospace.org/countermeasures/CM0055",
    ),
    "CM0056": Reference(
        "SPARTA",
        "CM0056",
        "Data Backup",
        "https://sparta.aerospace.org/countermeasures/CM0056",
    ),
    "CM0090": Reference(
        "SPARTA",
        "CM0090",
        "Continuous Monitoring",
        "https://sparta.aerospace.org/countermeasures/CM0090",
    ),
    "AC-3": Reference(
        "NIST SP 800-53 Rev. 5",
        "AC-3",
        "Access Enforcement",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "AC-4": Reference(
        "NIST SP 800-53 Rev. 5",
        "AC-4",
        "Information Flow Enforcement",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "AC-6": Reference(
        "NIST SP 800-53 Rev. 5",
        "AC-6",
        "Least Privilege",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "AC-17(10)": Reference(
        "NIST SP 800-53 Rev. 5",
        "AC-17(10)",
        "Authenticate Remote Commands",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "AU-2": Reference(
        "NIST SP 800-53 Rev. 5",
        "AU-2",
        "Event Logging",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "AU-3": Reference(
        "NIST SP 800-53 Rev. 5",
        "AU-3",
        "Content of Audit Records",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "AU-6": Reference(
        "NIST SP 800-53 Rev. 5",
        "AU-6",
        "Audit Record Review, Analysis, and Reporting",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "AU-12": Reference(
        "NIST SP 800-53 Rev. 5",
        "AU-12",
        "Audit Record Generation",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "CM-2": Reference(
        "NIST SP 800-53 Rev. 5",
        "CM-2",
        "Baseline Configuration",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "CM-6": Reference(
        "NIST SP 800-53 Rev. 5",
        "CM-6",
        "Configuration Settings",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "IA-2": Reference(
        "NIST SP 800-53 Rev. 5",
        "IA-2",
        "Identification and Authentication (Organizational Users)",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "IA-5": Reference(
        "NIST SP 800-53 Rev. 5",
        "IA-5",
        "Authenticator Management",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "IR-4": Reference(
        "NIST SP 800-53 Rev. 5",
        "IR-4",
        "Incident Handling",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "IR-8": Reference(
        "NIST SP 800-53 Rev. 5",
        "IR-8",
        "Incident Response Plan",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "SC-7": Reference(
        "NIST SP 800-53 Rev. 5",
        "SC-7",
        "Boundary Protection",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "SC-8": Reference(
        "NIST SP 800-53 Rev. 5",
        "SC-8",
        "Transmission Confidentiality and Integrity",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "SC-12": Reference(
        "NIST SP 800-53 Rev. 5",
        "SC-12",
        "Cryptographic Key Establishment and Management",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "SC-13": Reference(
        "NIST SP 800-53 Rev. 5",
        "SC-13",
        "Cryptographic Protection",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "SC-23": Reference(
        "NIST SP 800-53 Rev. 5",
        "SC-23",
        "Session Authenticity",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "SI-4": Reference(
        "NIST SP 800-53 Rev. 5",
        "SI-4",
        "System Monitoring",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "SI-7": Reference(
        "NIST SP 800-53 Rev. 5",
        "SI-7",
        "Software, Firmware, and Information Integrity",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    ),
    "ID.AM": Reference(
        "NIST CSF 1.1",
        "ID.AM",
        "Asset Management",
        "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf",
    ),
    "PR.AC": Reference(
        "NIST CSF 1.1",
        "PR.AC",
        "Identity Management, Authentication and Access Control",
        "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf",
    ),
    "PR.DS": Reference(
        "NIST CSF 1.1",
        "PR.DS",
        "Data Security",
        "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf",
    ),
    "DE.AE": Reference(
        "NIST CSF 1.1",
        "DE.AE",
        "Anomalies and Events",
        "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf",
    ),
    "DE.CM": Reference(
        "NIST CSF 1.1",
        "DE.CM",
        "Security Continuous Monitoring",
        "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf",
    ),
    "RS.AN": Reference(
        "NIST CSF 1.1",
        "RS.AN",
        "Analysis",
        "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf",
    ),
    "RS.RP": Reference(
        "NIST CSF 1.1",
        "RS.RP",
        "Response Planning",
        "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf",
    ),
    "RC.RP": Reference(
        "NIST CSF 1.1",
        "RC.RP",
        "Recovery Planning",
        "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.04162018.pdf",
    ),
    "IR8270": Reference(
        "NIST IR",
        "8270",
        "Introduction to Cybersecurity for Commercial Satellite Operations (July 2023)",
        "https://csrc.nist.gov/pubs/ir/8270/final",
    ),
    "IR8401": Reference(
        "NIST IR",
        "8401",
        "Satellite Ground Segment: Applying the Cybersecurity Framework to Satellite Command and Control (December 2022)",
        "https://csrc.nist.gov/pubs/ir/8401/final",
    ),
    "CCSDS-352": Reference(
        "CCSDS",
        "352.0-B-2",
        "CCSDS Cryptographic Algorithms",
        "https://ccsds.org/Pubs/352x0b2.pdf",
    ),
    "CCSDS-355": Reference(
        "CCSDS",
        "355.0-B-2",
        "Space Data Link Security Protocol",
        "https://ccsds.org/Pubs/355x0b2.pdf",
    ),
    "CCSDS-232": Reference(
        "CCSDS",
        "232.0-B-4",
        "TC Space Data Link Protocol",
        "https://ccsds.org/",
    ),
}


ITEMS: tuple[CheckItem, ...] = (
    CheckItem(
        "SL-01",
        "Authenticate every command before it is accepted",
        ("space", "ground"),
        "Command links should prove origin and integrity before a command is queued or executed. Authentication is not the same thing as authorization.",
        (
            "Require a cryptographic tag or authenticated encryption on command frames, and reject failures closed.",
            "Authenticate the ground endpoint and the spacecraft, including relay paths, where the protocol can support it.",
            "Keep an explicit allow-list of who may send which command. A valid tag alone should not authorize every opcode.",
            "This lab recomputes an HMAC over the command fields and reports CMD-MAC when the tag does not match. That is a classroom stand-in, not SDLS.",
        ),
        ("CM0031", "CM0055", "AC-17(10)", "IA-2", "PR.AC", "CCSDS-355"),
    ),
    CheckItem(
        "SL-02",
        "Reject replays and enforce the sequence counter",
        ("space", "ground"),
        "A tag that does not cover a unique counter and time can be copied and accepted later. Anti-replay state has to survive contact gaps.",
        (
            "Put the sequence counter inside the authenticated data, and accept only the next expected value or a documented window.",
            "Treat an exact repeat of authenticated bytes as a replay even when the tag still verifies.",
            "Log gaps separately from backwards counters. A gap can be a lost frame; a backwards or reused counter is more serious.",
            "Do not authenticate the ground receipt time in place of the counter. Receipt time is a log field an attacker does not have to forge if the original frame is copied.",
            "CMD-REPLAY and CMD-SEQ in this lab are the monitoring half of that practice.",
        ),
        ("CM0031", "SC-23", "CCSDS-355", "CCSDS-232"),
    ),
    CheckItem(
        "SL-03",
        "Encrypt command and telemetry links, with no crypto bypass",
        ("space", "ground"),
        "Authentication shows who sent a frame. Encryption limits what a passive listener learns from telecommand and telemetry.",
        (
            "Protect TT&C and payload traffic in transit, and state which links are covered.",
            "Do not provide an operational mode that turns link cryptography off, including contingency and test modes that can be reached in flight.",
            "Choose algorithms from a published catalog and record the choice. CCSDS 352.0-B-2 recommends AES-256 for encryption and pairs it with authentication.",
            "This lab does not encrypt its sample files. They are local teaching logs, and the checklist item is here so that omission stays visible.",
        ),
        ("CM0002", "CM0050", "SC-8", "SC-13", "PR.DS", "CCSDS-352"),
    ),
    CheckItem(
        "SL-04",
        "Manage keys and authenticators outside the software image",
        ("space", "ground", "development"),
        "The teaching HMAC key in this repository exists so the detector can recompute tags. A mission key must not live in source control or in the same tool that prints telemetry.",
        (
            "Separate key generation, storage, distribution, and destruction from flight-software builds and from operator laptops.",
            "Protect private and secret keys against export over telecommand, telemetry, debug, and diagnostics.",
            "Rotate keys on a written schedule and after any suspected exposure, and rehearse the rollover during a contact.",
            "Treat the lab key id LAB-TEACHING-KEY as a bad example that the detector is allowed to know.",
        ),
        ("CM0030", "CM0035", "SC-12", "IA-5"),
    ),
    CheckItem(
        "SL-05",
        "Monitor critical telemetry and the command path",
        ("space", "ground"),
        "Engineering limits catch broken sensors. A second check catches values that are still legal but unlike the rest of the pass. Command monitoring belongs in the same review.",
        (
            "Define limits for the points that indicate power, thermal, and link health, and alarm when a sample leaves them.",
            "Review authentication failures, repeated frames, sequence gaps, and commands at unexpected times.",
            "Keep eclipse and other mode changes out of naive statistical alarms, or the operator will learn to ignore them.",
            "TM-RANGE, TM-ZSCORE, and the command rules are a ground-side study version of that monitoring. They are not an onboard IDS.",
        ),
        ("CM0034", "CM0032", "CM0090", "SI-4", "AU-6", "DE.AE", "DE.CM", "IR8270"),
    ),
    CheckItem(
        "SL-06",
        "Generate and review ground audit records",
        ("ground",),
        "The ground segment should be able to reconstruct who released a command, when it was radiated, and what the spacecraft acknowledged.",
        (
            "Log command build, approval, release, and the returned telemetry in one timeline.",
            "Include operator identity, station, sequence counter, opcode, and success or failure of the authentication check.",
            "Protect the logs from edit and deletion by the same accounts that send commands.",
            "Review the logs after each contact, not only after an incident. NIST IR 8401 applies the Cybersecurity Framework to satellite command and control on the ground.",
        ),
        ("CM0005", "CM0090", "AU-2", "AU-3", "AU-12", "DE.CM", "IR8401"),
    ),
    CheckItem(
        "SL-07",
        "Segment ground systems and keep least privilege",
        ("ground",),
        "Mission operations, the RF chain, corporate IT, and supplier remote access should not be one flat network.",
        (
            "Separate command workstations, telemetry storage, key management, and general business systems.",
            "Default-deny the flows between those zones and allow only the documented protocols.",
            "Give operators the smallest command set their role needs. Payload engineers should not hold bus-safety commands.",
            "Inventory the ground assets those rules apply to before writing more policy.",
        ),
        ("CM0038", "CM0039", "CM0005", "AC-3", "AC-4", "AC-6", "SC-7", "ID.AM", "IR8401"),
    ),
    CheckItem(
        "SL-08",
        "Leave security enabled in safe mode",
        ("space",),
        "A safe mode that drops authentication or encryption turns a recovery path into an open command path.",
        (
            "Require the same command authentication in safe mode, contingency mode, and the nominal mode.",
            "Keep link encryption on while the vehicle is in safe mode.",
            "Test the recovery procedure against a command that has a bad tag and against a replayed command.",
            "Record the result of that test as sensitive data. Do not publish the procedure beside the keys.",
        ),
        ("CM0006", "CM0002", "CM0055", "SC-8", "SC-13"),
    ),
    CheckItem(
        "SL-09",
        "Protect command databases, procedures, and test reports",
        ("ground", "development"),
        "Command dictionaries, contact scripts, and security-test writeups tell a reader how the vehicle is operated. Treat them as sensitive operations data.",
        (
            "Restrict command and telemetry databases to people with a current need to operate or test.",
            "Track changes to procedures and to critical database fields, and test those changes before a contact.",
            "Store security assessment reports away from general file shares.",
            "The scenario files in this repository are fictional and are safe to publish. A real command database is not.",
        ),
        ("CM0001", "CM0008", "CM0023", "AC-3", "CM-2", "PR.DS"),
    ),
    CheckItem(
        "SL-10",
        "Keep flight software integrity through boot and update",
        ("space", "development"),
        "Command authentication does not help if the flight image will run unsigned code.",
        (
            "Verify a chain from a hardware root of trust through the bootloader to the flight image.",
            "Sign software and firmware updates and verify the signature onboard before activation.",
            "Keep a known baseline and review changes against it.",
            "Regression-test updates on a flat-sat or simulator before they are uplinked. This lab is not that simulator.",
        ),
        ("CM0014", "CM0021", "CM0023", "SI-7", "CM-2", "CM-6"),
    ),
    CheckItem(
        "SL-11",
        "Control the development environment and the suppliers",
        ("development",),
        "Flight software is only as controlled as the machines and people that build it.",
        (
            "Inventory who and what can change the build, and require strong authentication on repositories.",
            "Protect the main branch from direct pushes and review changes.",
            "Produce a software bill of materials and compare it with known vulnerable versions.",
            "Review suppliers of flight software, radios, and ground software before depending on them.",
        ),
        ("CM0004", "CM0012", "CM0025", "ID.AM"),
    ),
    CheckItem(
        "SL-12",
        "Release commands on the contact plan, with a rehearsed response",
        ("ground", "operations"),
        "Radiating outside the published pass is an operations failure even when the tag is mathematically valid. The response to a bad contact should already be written down.",
        (
            "Compare every command release with that station's AOS and LOS. CMD-WINDOW does this on the lab logs and ignores a frame that merely claims to be in contact.",
            "Use two people for command release where the mission class calls for it.",
            "Keep backups of procedures and of the last known configuration so a bad pass can be recovered.",
            "Write the incident path: who is called, how commanding is paused, and how the link is brought back after a key or ground-system compromise.",
        ),
        ("CM0054", "CM0056", "CM0031", "IR-4", "IR-8", "RS.AN", "RS.RP", "RC.RP", "IR8401"),
    ),
)

SEGMENTS = ("space", "ground", "development", "operations")


def select_items(segment: str = "all") -> list[CheckItem]:
    if segment == "all":
        return list(ITEMS)
    if segment not in SEGMENTS:
        known = ", ".join(("all",) + SEGMENTS)
        raise ValueError(f"unknown segment {segment!r}. Choose from {known}.")
    return [item for item in ITEMS if segment in item.segments]


def item_references(item: CheckItem) -> list[Reference]:
    return [REFERENCES[reference_id] for reference_id in item.reference_ids]


def render_index(segment: str = "all") -> str:
    lines = ["SpaceLab hardening checklist", DISCLAIMER, ""]
    for item in select_items(segment):
        where = ", ".join(item.segments)
        lines.append(f"{item.check_id}  {item.title}  [{where}]")
    lines.extend(["", "Full checklist: python3 -m spacelab checklist", ""])
    return "\n".join(lines)


def render_text(segment: str = "all") -> str:
    lines = [
        "SpaceLab spacecraft and ground-segment hardening checklist",
        DISCLAIMER,
        "",
        _wrap(NOTE),
        "",
    ]
    for item in select_items(segment):
        lines.append(f"{item.check_id}  {item.title}")
        lines.append(f"Segment: {', '.join(item.segments)}")
        lines.append(_wrap(item.summary))
        for practice in item.practices:
            lines.append(_wrap(practice, initial="  - ", subsequent="    "))
        lines.append("  References:")
        for reference in item_references(item):
            lines.append(_wrap(reference.label(), initial="  - ", subsequent="    "))
            lines.append(f"    {reference.url}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(segment: str = "all") -> str:
    lines = [
        "# SpaceLab hardening checklist",
        "",
        f"> {DISCLAIMER}",
        "",
        NOTE,
        "",
    ]
    for item in select_items(segment):
        lines.append(f"## {item.check_id} {item.title}")
        lines.append("")
        lines.append(f"Segment: {', '.join(item.segments)}")
        lines.append("")
        lines.append(item.summary)
        lines.append("")
        for practice in item.practices:
            lines.append(f"- {practice}")
        lines.append("")
        lines.append("References:")
        lines.append("")
        for reference in item_references(item):
            lines.append(f"- [{reference.label()}]({reference.url})")
        lines.append("")
    return "\n".join(lines)


def render_json(segment: str = "all") -> str:
    payload = {
        "title": "SpaceLab spacecraft and ground-segment hardening checklist",
        "disclaimer": DISCLAIMER,
        "note": NOTE,
        "segment": segment,
        "items": [
            {
                "check_id": item.check_id,
                "title": item.title,
                "segments": list(item.segments),
                "summary": item.summary,
                "practices": list(item.practices),
                "references": [
                    {
                        "framework": reference.framework,
                        "identifier": reference.identifier,
                        "title": reference.title,
                        "url": reference.url,
                    }
                    for reference in item_references(item)
                ],
            }
            for item in select_items(segment)
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render(fmt: str, segment: str = "all") -> str:
    if fmt == "text":
        return render_text(segment)
    if fmt == "md":
        return render_markdown(segment)
    if fmt == "json":
        return render_json(segment)
    raise ValueError("format must be text, md, or json")


def _wrap(text: str, initial: str = "", subsequent: str | None = None) -> str:
    follow = initial if subsequent is None else subsequent
    return textwrap.fill(text, width=78, initial_indent=initial, subsequent_indent=follow)
