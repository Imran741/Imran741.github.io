"""Have I Been Pwned breach detection via the k-anonymity range API.

How k-anonymity protects the password
-------------------------------------
1. The password is hashed locally with SHA-1 (HIBP's index format --
   SHA-1 is fine here because it is a lookup key, not a storage hash).
2. Only the FIRST FIVE hex characters of the hash are sent to the API:
       GET https://api.pwnedpasswords.com/range/{prefix}
   Five hex chars identify a bucket of ~800 hashes, so the server learns
   essentially nothing about which password (or even which hash) we hold.
3. HIBP returns every known-breached hash *suffix* in that bucket along
   with its breach count.  We compare the remaining 35 characters of our
   hash against that list locally.

The full password -- and even the full hash -- never leaves this machine.

The range endpoint requires NO API key.  An optional ``HIBP_API_KEY`` is
still read from the environment and forwarded if present, which raises
rate limits for licensed users; it is never required and never hardcoded.
"""

from __future__ import annotations

import hashlib
import logging
import os

import requests

logger = logging.getLogger(__name__)

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"
REQUEST_TIMEOUT_SECONDS = 5
# HIBP asks clients to identify themselves via User-Agent.
USER_AGENT = "PasswordSecurityAnalyzer/1.0 (+https://github.com/aimran546)"


class BreachCheckError(Exception):
    """Raised when the breach check cannot be completed (network/API issue)."""


def _sha1_hex(password: str) -> str:
    """Local SHA-1 of the password, uppercase hex (HIBP's index format)."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_breach(password: str) -> dict:
    """Check ``password`` against HIBP using k-anonymity.

    Returns ``{"breached": bool, "count": int}`` on success.
    Raises :class:`BreachCheckError` on network/API failure so the caller
    can degrade gracefully instead of mislabelling the password as safe.
    """
    if not password:
        return {"breached": False, "count": 0}

    digest = _sha1_hex(password)
    # k-anonymity split: 5-char prefix goes over the wire, the 35-char
    # suffix stays local and is only used for the in-memory comparison.
    prefix, suffix = digest[:5], digest[5:]

    headers = {
        "User-Agent": USER_AGENT,
        # Padded responses make every bucket the same approximate size,
        # defeating traffic analysis of the response length.
        "Add-Padding": "true",
    }
    # Optional licensed key from the environment -- never hardcoded.
    api_key = os.environ.get("HIBP_API_KEY")
    if api_key:
        headers["hibp-api-key"] = api_key

    try:
        response = requests.get(
            HIBP_RANGE_URL.format(prefix=prefix),
            headers=headers,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        # Log the failure class only -- never the password or its hash.
        logger.warning("HIBP range lookup failed: %s", exc.__class__.__name__)
        raise BreachCheckError("Breach database is unreachable") from exc

    # Response lines look like "0018A45C4D1DEF81644B54AB7F969B88D65:3".
    # Padding entries have a count of 0 and are filtered out implicitly
    # because we only report a breach on an exact suffix match with count > 0.
    for line in response.text.splitlines():
        candidate_suffix, _, count = line.partition(":")
        if candidate_suffix.strip() == suffix:
            occurrences = int(count.strip() or 0)
            if occurrences > 0:
                return {"breached": True, "count": occurrences}
    return {"breached": False, "count": 0}


def breach_report(password: str) -> dict:
    """Breach analysis used by the API layer; degrades gracefully on failure."""
    try:
        result = check_breach(password)
        return {**result, "checked": True, "error": None}
    except BreachCheckError as exc:
        return {"breached": False, "count": 0, "checked": False, "error": str(exc)}
