"""Structural weakness detection.

Detects the four classes of structural weakness the scorer penalises:

- membership in a common-password list
- embedded dictionary words
- repeated patterns ("aaa", "abcabcabc")
- sequential runs ("abcd", "4321", keyboard rows like "qwerty")
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Minimum length for a substring to count as a dictionary-word hit.
# Shorter words ("a", "it") would flag almost every password.
_MIN_DICT_WORD_LEN = 4

# Sequences an attacker will try first: alphabet, digits and keyboard rows.
_SEQUENCES = (
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
)
_SEQUENCE_RUN_LEN = 3  # runs of 3+ characters count as sequential


@lru_cache(maxsize=1)
def _load_wordlist(filename: str) -> frozenset[str]:
    """Load a newline-delimited wordlist from the bundled data directory."""
    path = _DATA_DIR / filename
    try:
        with path.open(encoding="utf-8") as fh:
            return frozenset(
                line.strip().lower() for line in fh if line.strip() and not line.startswith("#")
            )
    except OSError:
        # A missing data file must never take the analyzer down; the
        # corresponding check simply reports no matches.
        return frozenset()


def common_passwords() -> frozenset[str]:
    return _load_wordlist("common_passwords.txt")


def dictionary_words() -> frozenset[str]:
    return _load_wordlist("dictionary_words.txt")


def is_common_password(password: str) -> bool:
    """True if the password appears verbatim in the common-password list.

    Comparison is case-insensitive and also strips trailing digits, so
    "Password123" still matches "password".
    """
    lowered = password.lower()
    if lowered in common_passwords():
        return True
    stripped = lowered.rstrip("0123456789!@#$")
    return bool(stripped) and stripped in common_passwords()


def find_dictionary_words(password: str) -> list[str]:
    """Return dictionary words embedded in ``password`` (longest first).

    Scans every substring of length >= _MIN_DICT_WORD_LEN against the
    bundled wordlist.  Overlapping shorter matches inside an already
    matched word are suppressed to keep the output readable.
    """
    lowered = password.lower()
    words = dictionary_words()
    found: list[str] = []
    covered: set[int] = set()
    n = len(lowered)
    # Longest substrings first so "passwords" wins over "password"/"word".
    for length in range(n, _MIN_DICT_WORD_LEN - 1, -1):
        for start in range(0, n - length + 1):
            span = range(start, start + length)
            if any(i in covered for i in span):
                continue
            candidate = lowered[start : start + length]
            if candidate in words:
                found.append(candidate)
                covered.update(span)
    return found


def find_repeated_patterns(password: str) -> list[str]:
    """Return repeated units, e.g. "aaa" -> ["a"], "abcabc" -> ["abc"].

    Uses a backreference regex: any unit of 1+ chars immediately repeated
    at least once (or 2+ times for single characters).
    """
    matches: list[str] = []
    # Single character repeated 3+ times ("aaa", "111").
    for match in re.finditer(r"(.)\1{2,}", password):
        matches.append(match.group(1))
    # Multi-character unit repeated 2+ times ("abcabc", "121212").
    for match in re.finditer(r"(.{2,})\1+", password):
        matches.append(match.group(1))
    return matches


def find_sequential_patterns(password: str) -> list[str]:
    """Return sequential runs (forward or reverse) of 3+ characters."""
    lowered = password.lower()
    found: list[str] = []
    for seq in _SEQUENCES:
        reversed_seq = seq[::-1]
        for end in range(_SEQUENCE_RUN_LEN, len(lowered) + 1):
            for start in range(0, end - _SEQUENCE_RUN_LEN + 1):
                chunk = lowered[start:end]
                if len(chunk) < _SEQUENCE_RUN_LEN:
                    continue
                if chunk in seq or chunk in reversed_seq:
                    # Keep only maximal runs: skip chunks contained in an
                    # already recorded longer run.
                    if not any(chunk in existing for existing in found):
                        found = [f for f in found if f not in chunk]
                        found.append(chunk)
    return found


def pattern_report(password: str) -> dict:
    """Aggregate all structural checks for the API layer."""
    return {
        "is_common_password": is_common_password(password),
        "dictionary_words": find_dictionary_words(password),
        "repeated_patterns": find_repeated_patterns(password),
        "sequential_patterns": find_sequential_patterns(password),
    }
