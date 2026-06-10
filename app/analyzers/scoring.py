"""Composite password strength scoring (0-100).

The score blends three signals:

1. Length (up to 40 points) -- length is the single strongest defence
   against brute force, so it carries the most weight.
2. Character variety (up to 30 points) -- each character class widens the
   attacker's search pool.
3. Entropy (up to 30 points) -- rewards the combination of the two above.

Structural weaknesses then subtract penalty points, because a long,
varied password built from "Password123!" patterns is far weaker than
its raw entropy suggests.
"""

from __future__ import annotations

from . import entropy as entropy_mod
from . import patterns as patterns_mod

# --- weights -----------------------------------------------------------
MAX_LENGTH_POINTS = 40
MAX_VARIETY_POINTS = 30
MAX_ENTROPY_POINTS = 30

# Length at which the length component maxes out.
_FULL_CREDIT_LENGTH = 16
# Entropy (bits) at which the entropy component maxes out.
_FULL_CREDIT_ENTROPY = 80.0

# --- penalties ---------------------------------------------------------
PENALTY_COMMON_PASSWORD = 50
PENALTY_DICTIONARY_WORD = 15   # per word, capped below
PENALTY_REPEATED_PATTERN = 10  # per pattern, capped below
PENALTY_SEQUENTIAL_PATTERN = 10
_MAX_DICTIONARY_PENALTY = 30
_MAX_REPEAT_PENALTY = 20
_MAX_SEQUENCE_PENALTY = 20

_LABELS = (
    (20, "Very Weak"),
    (40, "Weak"),
    (60, "Moderate"),
    (80, "Strong"),
    (101, "Very Strong"),
)


def length_score(password: str) -> int:
    """0..MAX_LENGTH_POINTS, linear up to _FULL_CREDIT_LENGTH chars."""
    ratio = min(len(password) / _FULL_CREDIT_LENGTH, 1.0)
    return round(ratio * MAX_LENGTH_POINTS)


def variety_score(password: str) -> int:
    """0..MAX_VARIETY_POINTS based on distinct character classes used."""
    if not password:
        return 0
    classes = entropy_mod.detect_character_classes(password)
    return round((classes.count() / 4) * MAX_VARIETY_POINTS)


def entropy_score(password: str) -> int:
    """0..MAX_ENTROPY_POINTS, linear up to _FULL_CREDIT_ENTROPY bits."""
    bits = entropy_mod.calculate_entropy(password)
    ratio = min(bits / _FULL_CREDIT_ENTROPY, 1.0)
    return round(ratio * MAX_ENTROPY_POINTS)


def penalty(password: str, pattern_report: dict | None = None) -> int:
    """Total penalty points for structural weaknesses (>= 0)."""
    report = pattern_report or patterns_mod.pattern_report(password)
    total = 0
    if report["is_common_password"]:
        total += PENALTY_COMMON_PASSWORD
    total += min(
        len(report["dictionary_words"]) * PENALTY_DICTIONARY_WORD,
        _MAX_DICTIONARY_PENALTY,
    )
    total += min(
        len(report["repeated_patterns"]) * PENALTY_REPEATED_PATTERN,
        _MAX_REPEAT_PENALTY,
    )
    total += min(
        len(report["sequential_patterns"]) * PENALTY_SEQUENTIAL_PATTERN,
        _MAX_SEQUENCE_PENALTY,
    )
    return total


def label_for_score(score: int) -> str:
    for threshold, label in _LABELS:
        if score < threshold:
            return label
    return _LABELS[-1][1]


def score_password(password: str, pattern_report: dict | None = None) -> dict:
    """Return the composite score breakdown for ``password``."""
    if not password:
        return {
            "score": 0,
            "label": "Very Weak",
            "components": {"length": 0, "variety": 0, "entropy": 0, "penalty": 0},
        }
    components = {
        "length": length_score(password),
        "variety": variety_score(password),
        "entropy": entropy_score(password),
        "penalty": penalty(password, pattern_report),
    }
    raw = components["length"] + components["variety"] + components["entropy"]
    score = max(0, min(100, raw - components["penalty"]))
    return {"score": score, "label": label_for_score(score), "components": components}
