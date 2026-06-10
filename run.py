"""Development entry point.

Run with:  python run.py
In production, point a WSGI server at the factory instead:
    gunicorn "app:create_app()"
"""

import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # Bind to localhost by default; override HOST/PORT via environment.
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
    )
