"""Flask application factory."""

from __future__ import annotations

import logging

from flask import Flask

from config import get_config


def create_app(config_object: type | None = None) -> Flask:
    """Create and configure the Flask application.

    The factory pattern keeps the app importable without side effects,
    which makes testing and WSGI deployment straightforward.
    """
    app = Flask(__name__)
    app.config.from_object(config_object or get_config())

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    from .routes import bp as main_bp

    app.register_blueprint(main_bp)

    @app.after_request
    def set_security_headers(response):
        """Defence-in-depth headers on every response."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        # Only same-origin scripts/styles plus the Bootstrap CDN.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' https://cdn.jsdelivr.net; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        # Analysis responses derive from secrets - never cache them.
        response.headers["Cache-Control"] = "no-store"
        return response

    return app
