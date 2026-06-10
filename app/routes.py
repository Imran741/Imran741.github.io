"""HTTP layer: dashboard page and the JSON analysis API.

Security notes
--------------
- The password is processed in memory only: it is never logged, never
  persisted, and never echoed back in the response.
- Input is strictly validated (type, presence, length) before any
  analysis runs.
- The breach check sends only a 5-character SHA-1 prefix upstream
  (see ``analyzers/breach.py``).
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template, request

from .analyzers import breach, crack_time, entropy, patterns, recommendations, scoring

bp = Blueprint("main", __name__)


@bp.get("/")
def index():
    """Render the dashboard."""
    return render_template("index.html")


@bp.post("/api/analyze")
def analyze():
    """Analyze a password and return the full report as JSON."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400

    password = payload.get("password")
    if not isinstance(password, str) or not password:
        return jsonify({"error": "Field 'password' must be a non-empty string."}), 400

    max_len = current_app.config["MAX_PASSWORD_LENGTH"]
    if len(password) > max_len:
        return jsonify({"error": f"Password exceeds maximum length of {max_len} characters."}), 400

    # The client may skip the network call (privacy choice in the UI).
    check_breach = bool(payload.get("check_breach", True))

    try:
        entropy_report = entropy.entropy_report(password)
        pattern_report = patterns.pattern_report(password)
        score_report = scoring.score_password(password, pattern_report)
        crack_report = crack_time.crack_time_report(password)
        breach_result = (
            breach.breach_report(password)
            if check_breach
            else {"breached": False, "count": 0, "checked": False, "error": None}
        )
        recs = recommendations.build_recommendations(
            password, entropy_report, pattern_report, breach_result, score_report
        )
    except Exception:  # noqa: BLE001 - never leak internals to the client
        current_app.logger.exception("Password analysis failed")
        return jsonify({"error": "Analysis failed due to an internal error."}), 500

    return jsonify(
        {
            "length": len(password),
            "score": score_report,
            "entropy": entropy_report,
            "crack_time": crack_report,
            "patterns": pattern_report,
            "breach": breach_result,
            "recommendations": recs,
        }
    )


@bp.app_errorhandler(404)
def not_found(_error):
    return jsonify({"error": "Not found."}), 404


@bp.app_errorhandler(405)
def method_not_allowed(_error):
    return jsonify({"error": "Method not allowed."}), 405
