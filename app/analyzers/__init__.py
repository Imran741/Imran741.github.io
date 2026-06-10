"""Password analysis engine.

Each analyzer is a self-contained module:

- ``entropy``         -- Shannon-style entropy estimation and categorisation.
- ``scoring``         -- composite 0-100 password strength scoring.
- ``patterns``        -- common-password / dictionary / repetition / sequence detection.
- ``crack_time``      -- brute-force crack time estimation.
- ``breach``          -- Have I Been Pwned k-anonymity breach lookup.
- ``recommendations`` -- human-readable hardening advice.
"""
