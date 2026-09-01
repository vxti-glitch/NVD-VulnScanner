"""Validation helpers for explicitly recorded API fixtures."""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path
from typing import Any


class RecordedFixtureError(ValueError):
    """Raised when fixture provenance or payload structure is unusable."""


def load_recorded_fixture(
    path: Path,
    *,
    today: date | None = None,
    max_age_days: int = 365,
) -> dict[str, Any]:
    """Load a fixture wrapper and reject malformed or stale recordings."""
    try:
        wrapper = json.loads(path.read_text(encoding="utf-8"))
        recorded_at = datetime.strptime(wrapper["recorded_at"], "%Y-%m-%d").date()
        source_url = wrapper["source_url"]
        payload = wrapper["payload"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise RecordedFixtureError(f"malformed recorded fixture: {path.name}") from exc
    if not isinstance(source_url, str) or not source_url.startswith("https://"):
        raise RecordedFixtureError("fixture source_url must be HTTPS")
    if not isinstance(payload, dict):
        raise RecordedFixtureError("fixture payload must be an object")
    age = (today or date.today()) - recorded_at
    if age.days < 0 or age.days > max_age_days:
        raise RecordedFixtureError(f"stale recorded fixture: {path.name} is {age.days} days old")
    return payload
