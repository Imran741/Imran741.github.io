"""Brute-force crack time estimation.

The model assumes an offline attack against a fast hash:

    total_guesses   = pool_size ** length
    average_guesses = total_guesses / 2      (attacker finds it halfway, on average)
    seconds         = average_guesses / guesses_per_second

``guesses_per_second`` defaults to 1e10 (10 billion/s), a realistic figure
for a single modern GPU rig attacking MD5/SHA-1 style hashes.  Online
attacks are orders of magnitude slower; we report the pessimistic case
because that is what password storage must withstand.
"""

from __future__ import annotations

from . import entropy as entropy_mod

DEFAULT_GUESSES_PER_SECOND = 1e10

_UNITS = (
    ("second", 60),
    ("minute", 60),
    ("hour", 24),
    ("day", 365),
    ("year", 100),
    ("century", None),
)

_SECONDS_PER = {
    "second": 1,
    "minute": 60,
    "hour": 3600,
    "day": 86400,
    "year": 86400 * 365,
    "century": 86400 * 365 * 100,
}


def estimate_seconds(
    password: str, guesses_per_second: float = DEFAULT_GUESSES_PER_SECOND
) -> float:
    """Average seconds to brute-force ``password`` at the given guess rate."""
    if not password or guesses_per_second <= 0:
        return 0.0
    pool = entropy_mod.charset_pool_size(password)
    if pool <= 1:
        return 0.0
    average_guesses = (pool ** len(password)) / 2
    return average_guesses / guesses_per_second


def humanize_seconds(seconds: float) -> str:
    """Render a duration as a human-friendly string.

    Examples: "instantly", "3 minutes", "12 years", "5 thousand centuries".
    """
    if seconds < 1:
        return "instantly"
    if seconds >= _SECONDS_PER["century"]:
        centuries = seconds / _SECONDS_PER["century"]
        return f"{_humanize_big_number(centuries)} centuries"
    for unit, _ in _UNITS:
        per = _SECONDS_PER[unit]
        nxt = _next_unit(unit)
        if nxt is None or seconds < _SECONDS_PER[nxt]:
            value = int(seconds / per)
            plural = "s" if value != 1 else ""
            return f"{value} {unit}{plural}"
    return "centuries"  # pragma: no cover - unreachable


def _next_unit(unit: str) -> str | None:
    names = [name for name, _ in _UNITS]
    idx = names.index(unit)
    return names[idx + 1] if idx + 1 < len(names) else None


def _humanize_big_number(value: float) -> str:
    """Format huge magnitudes readably instead of in raw scientific notation."""
    for threshold, suffix in (
        (1e18, "quintillion"),
        (1e15, "quadrillion"),
        (1e12, "trillion"),
        (1e9, "billion"),
        (1e6, "million"),
        (1e3, "thousand"),
    ):
        if value >= threshold:
            return f"{value / threshold:.1f} {suffix}"
    return f"{value:.0f}"


def crack_time_report(
    password: str, guesses_per_second: float = DEFAULT_GUESSES_PER_SECOND
) -> dict:
    """Crack-time analysis used by the API layer."""
    seconds = estimate_seconds(password, guesses_per_second)
    return {
        "seconds": seconds,
        "display": humanize_seconds(seconds),
        "guesses_per_second": guesses_per_second,
        "attack_model": "offline brute-force, fast hash, single GPU rig",
    }
