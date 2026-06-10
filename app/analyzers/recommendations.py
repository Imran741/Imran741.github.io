"""Security recommendations derived from the full analysis result."""

from __future__ import annotations

_MIN_RECOMMENDED_LENGTH = 12
_STRONG_LENGTH = 16


def build_recommendations(
    password: str,
    entropy_report: dict,
    pattern_report: dict,
    breach_report: dict,
    score_report: dict,
) -> list[dict]:
    """Return prioritised recommendations as ``{"severity", "message"}`` dicts.

    Severity drives the UI badge colour: "critical" > "warning" > "info" > "success".
    """
    recs: list[dict] = []

    if breach_report.get("breached"):
        recs.append(
            {
                "severity": "critical",
                "message": (
                    f"This password appears in known data breaches "
                    f"{breach_report['count']:,} times. Stop using it everywhere, immediately."
                ),
            }
        )
    if pattern_report["is_common_password"]:
        recs.append(
            {
                "severity": "critical",
                "message": "This is one of the most commonly used passwords. "
                "Attackers try these first - choose something unique.",
            }
        )

    if len(password) < _MIN_RECOMMENDED_LENGTH:
        recs.append(
            {
                "severity": "warning",
                "message": f"Use at least {_MIN_RECOMMENDED_LENGTH} characters "
                f"(currently {len(password)}). Length matters more than complexity.",
            }
        )
    elif len(password) < _STRONG_LENGTH:
        recs.append(
            {
                "severity": "info",
                "message": f"Consider extending to {_STRONG_LENGTH}+ characters "
                "for long-term resistance to offline attacks.",
            }
        )

    classes = entropy_report["character_classes"]
    missing = [name for name, present in classes.items() if not present]
    if missing:
        pretty = {
            "lowercase": "lowercase letters",
            "uppercase": "uppercase letters",
            "digits": "numbers",
            "special": "special characters",
        }
        recs.append(
            {
                "severity": "warning",
                "message": "Add " + ", ".join(pretty[m] for m in missing) + " to widen the search space attackers must cover.",
            }
        )

    if pattern_report["dictionary_words"]:
        words = ", ".join(f'"{w}"' for w in pattern_report["dictionary_words"][:3])
        recs.append(
            {
                "severity": "warning",
                "message": f"Contains dictionary words ({words}). "
                "Dictionary attacks crack these regardless of length.",
            }
        )
    if pattern_report["repeated_patterns"]:
        recs.append(
            {
                "severity": "warning",
                "message": "Contains repeated patterns. Repetition adds length "
                "but almost no real strength.",
            }
        )
    if pattern_report["sequential_patterns"]:
        seqs = ", ".join(f'"{s}"' for s in pattern_report["sequential_patterns"][:3])
        recs.append(
            {
                "severity": "warning",
                "message": f"Contains sequential characters ({seqs}). "
                "Sequences are in every attacker's first wordlist.",
            }
        )

    if not breach_report.get("checked", True):
        recs.append(
            {
                "severity": "info",
                "message": "Breach database could not be reached - the breach "
                "status of this password is unverified.",
            }
        )

    if not recs:
        recs.append(
            {
                "severity": "success",
                "message": "Excellent password. Store it in a password manager "
                "and never reuse it across sites.",
            }
        )
    elif score_report["score"] >= 80:
        recs.append(
            {
                "severity": "info",
                "message": "Use a password manager to generate and store unique "
                "passwords per site, and enable two-factor authentication.",
            }
        )
    else:
        recs.append(
            {
                "severity": "info",
                "message": "Tip: a passphrase of 4-5 random unrelated words "
                "(e.g. from a dice-word list) is both strong and memorable.",
            }
        )

    return recs
