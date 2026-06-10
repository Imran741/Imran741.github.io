"""Application configuration.

All secrets and tunables come from environment variables -- nothing is
hardcoded.  Copy ``.env.example`` to ``.env`` for local development.
"""

from __future__ import annotations

import os
import secrets


class Config:
    """Base configuration shared by all environments."""

    # SECRET_KEY signs session cookies. In production it MUST be set via
    # the environment; the random fallback keeps development convenient
    # while guaranteeing we never ship a hardcoded key.
    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    # Optional licensed HIBP key (range API works without it).
    HIBP_API_KEY = os.environ.get("HIBP_API_KEY")

    # Hard upper bound on accepted password length (DoS guard: entropy
    # math is cheap, but pattern scanning is quadratic in length).
    MAX_PASSWORD_LENGTH = int(os.environ.get("MAX_PASSWORD_LENGTH", "128"))

    JSON_SORT_KEYS = False


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False


class TestingConfig(Config):
    TESTING = True


def get_config() -> type[Config]:
    """Select configuration class from the FLASK_ENV environment variable."""
    env = os.environ.get("FLASK_ENV", "production").lower()
    return {
        "development": DevelopmentConfig,
        "testing": TestingConfig,
        "production": ProductionConfig,
    }.get(env, ProductionConfig)
