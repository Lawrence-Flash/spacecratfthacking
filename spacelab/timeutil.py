"""UTC timestamps with second resolution."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

def parse_utc(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp {value!r} must include a timezone")
    return parsed.astimezone(timezone.utc)


def format_utc(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("refusing to format a naive datetime")
    return moment.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def add_seconds(value: str, seconds: int) -> str:
    return format_utc(parse_utc(value) + timedelta(seconds=seconds))
