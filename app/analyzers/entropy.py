"""Password entropy estimation.

Entropy here is the classic "guessing entropy" upper bound:

    E = L * log2(N)

where ``L`` is the password length and ``N`` is the size of the character
pool the attacker must search.  The pool is inferred from the character
classes actually present in the password (an attacker who knows the
password is all-lowercase only needs to search 26 symbols per position).

This is intentionally an *upper bound*: structural weaknesses (dictionary
words, sequences, repeats) reduce real-world strength, which is why the
composite score in ``scoring.py`` applies penalties on top of this value.
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass

# Character pool sizes per class.  The "special" pool size matches the
# printable ASCII punctuation set (32 symbols).
POOL_LOWERCASE = 26
POOL_UPPERCASE = 26
POOL_DIGITS = 10
POOL_SPECIAL = 32

# Entropy thresholds (in bits) for each strength category.  Aligned with
# commonly cited guidance: < 28 bits is trivially guessable offline, while
# 128+ bits is beyond any foreseeable brute-force capability.
ENTROPY_LEVELS = (
    (28, "Very Weak"),
    (36, "Weak"),
    (60, "Moderate"),
    (128, "Strong"),
    (float("inf"), "Very Strong"),
)

_SPECIAL_CHARS = set(string.punctuation)


@dataclass(frozen=True)
class CharacterClasses:
    """Which character classes appear in a password."""

    lowercase: bool
    uppercase: bool
    digits: bool
    special: bool

    def pool_size(self) -> int:
        """Size of the search space an attacker must cover per character."""
        size = 0
        if self.lowercase:
            size += POOL_LOWERCASE
        if self.uppercase:
            size += POOL_UPPERCASE
        if self.digits:
            size += POOL_DIGITS
        if self.special:
            size += POOL_SPECIAL
        return size

    def count(self) -> int:
        """Number of distinct character classes used."""
        return sum((self.lowercase, self.uppercase, self.digits, self.special))


def detect_character_classes(password: str) -> CharacterClasses:
    """Detect which character classes are present in ``password``."""
    return CharacterClasses(
        lowercase=any(c.islower() for c in password),
        uppercase=any(c.isupper() for c in password),
        digits=any(c.isdigit() for c in password),
        # Anything outside ASCII alphanumerics (punctuation, whitespace,
        # unicode letters/symbols) counts as "special" so that unusual
        # characters still widen the pool conservatively.
        special=any(not (c.isascii() and c.isalnum()) for c in password),
    )


def charset_pool_size(password: str) -> int:
    """Return the inferred character-pool size for ``password``."""
    if not password:
        return 0
    return detect_character_classes(password).pool_size()


def calculate_entropy(password: str) -> float:
    """Return the estimated entropy of ``password`` in bits."""
    if not password:
        return 0.0
    pool = charset_pool_size(password)
    if pool <= 1:
        return 0.0
    return round(len(password) * math.log2(pool), 2)


def categorize_entropy(bits: float) -> str:
    """Map an entropy value (bits) onto a human-readable category."""
    for threshold, label in ENTROPY_LEVELS:
        if bits < threshold:
            return label
    return ENTROPY_LEVELS[-1][1]


def entropy_report(password: str) -> dict:
    """Full entropy analysis used by the API layer."""
    bits = calculate_entropy(password)
    classes = detect_character_classes(password) if password else None
    return {
        "bits": bits,
        "category": categorize_entropy(bits),
        "pool_size": charset_pool_size(password),
        "character_classes": {
            "lowercase": bool(classes and classes.lowercase),
            "uppercase": bool(classes and classes.uppercase),
            "digits": bool(classes and classes.digits),
            "special": bool(classes and classes.special),
        },
    }
