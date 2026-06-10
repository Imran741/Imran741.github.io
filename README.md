# Password Security Analyzer

A production-quality Flask web application that analyzes password strength in real time: composite scoring, entropy estimation, brute-force crack-time projection, structural weakness detection, and breach lookups against **Have I Been Pwned** using the privacy-preserving k-anonymity model.

![Stack](https://img.shields.io/badge/stack-Python%20%7C%20Flask%20%7C%20Bootstrap%205-blue)

---

## Features

| Category | Checks |
| --- | --- |
| **Strength scoring** | 0–100 composite score: length (40 pts), character variety (30 pts), entropy (30 pts), minus structural penalties |
| **Character analysis** | Detects lowercase, uppercase, numbers, special characters |
| **Pattern detection** | Common-password list, embedded dictionary words, repeated patterns (`abcabc`, `aaa`), sequential runs (`abcd`, `4321`, `qwerty`) |
| **Entropy** | `L × log₂(N)` bits with five categories: Very Weak / Weak / Moderate / Strong / Very Strong |
| **Crack time** | Offline brute-force model at 10¹⁰ guesses/sec, rendered human-readably ("3 minutes", "5.2 thousand centuries") |
| **Breach detection** | HIBP Pwned Passwords range API with k-anonymity — only a 5-character SHA-1 prefix ever leaves the machine |
| **Dashboard** | Bootstrap 5, live strength meter, entropy / crack-time / recommendations cards, fully responsive |

---

## Quick start

```bash
# 1. Clone and enter the project
git clone <repo-url> && cd <repo>

# 2. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment (optional for development)
cp .env.example .env
# generate a secret key:
python -c "import secrets; print(secrets.token_hex(32))"   # paste into .env

# 5. Run
python run.py
# → http://127.0.0.1:5000
```

### Production

```bash
export SECRET_KEY="<64-hex-chars>"
export FLASK_ENV=production
gunicorn -w 4 -b 127.0.0.1:8000 "app:create_app()"
```

Put a TLS-terminating reverse proxy (nginx/Caddy) in front — passwords must only ever transit HTTPS.

### Tests

```bash
pytest -v
```

---

## Project structure

```
.
├── run.py                      # Dev entry point (gunicorn targets app:create_app)
├── config.py                   # Env-driven configuration (no hardcoded secrets)
├── requirements.txt
├── .env.example                # Template for local configuration
├── app/
│   ├── __init__.py             # Application factory + security headers
│   ├── routes.py               # Dashboard route + /api/analyze JSON API
│   ├── analyzers/              # Pure, independently testable analysis modules
│   │   ├── entropy.py          # Charset detection, entropy bits, categories
│   │   ├── scoring.py          # Composite 0–100 score with penalties
│   │   ├── patterns.py         # Common/dictionary/repeat/sequence detection
│   │   ├── crack_time.py       # Brute-force time model + humanizer
│   │   ├── breach.py           # HIBP k-anonymity client
│   │   └── recommendations.py  # Prioritised, severity-tagged advice
│   ├── data/
│   │   ├── common_passwords.txt
│   │   └── dictionary_words.txt
│   ├── templates/              # Bootstrap 5 dashboard
│   └── static/                 # CSS + vanilla-JS dashboard logic
└── tests/
    ├── test_entropy.py
    ├── test_scoring.py
    └── test_api.py
```

---

## Architecture

**Three clean layers:**

1. **Analysis engine (`app/analyzers/`)** — pure functions with no Flask imports. Each concern (entropy, scoring, patterns, crack time, breach, recommendations) lives in its own module, so each is unit-testable in isolation and reusable outside the web app (e.g. from a CLI).
2. **HTTP layer (`app/routes.py`)** — a thin blueprint that validates input, orchestrates the analyzers, and serialises the report. The app factory (`create_app`) keeps the application importable without side effects for tests and WSGI servers.
3. **Presentation (`templates/`, `static/`)** — server renders one page; all analysis happens through a debounced `fetch` to `POST /api/analyze`, returning pure JSON.

**Scoring model.** Raw entropy overstates the strength of structured passwords (`Password123!` has decent entropy on paper but is cracked instantly). The composite score therefore rewards length/variety/entropy and then subtracts penalties for common-password hits, dictionary words, repetition and sequences — mirroring how real cracking tools (wordlists + rules first, brute force last) actually behave.

**Crack-time model.** `pool_length ÷ 2` average guesses at 10¹⁰ guesses/sec — a realistic single-GPU rig attacking a fast hash. This is deliberately the *pessimistic* (offline) scenario, since that is what leaked password databases face.

---

## Security design decisions

| Decision | Rationale |
| --- | --- |
| **k-anonymity breach lookups** | The password is SHA-1-hashed *locally*; only the first 5 hex chars are sent to `api.pwnedpasswords.com/range/`. HIBP returns ~800 candidate suffixes and the match happens in local memory. Neither the password nor even its full hash ever leaves the machine. `Add-Padding: true` is sent so response sizes can't be traffic-analyzed. |
| **No persistence, no logging of secrets** | The password lives only in request memory. Log statements record error *classes*, never password material. Responses carry `Cache-Control: no-store`. The API never echoes the password back. |
| **Strict input validation** | JSON-only body, type-checked `password` field, hard `MAX_PASSWORD_LENGTH` cap (DoS guard — pattern scanning is quadratic in length). |
| **Secrets via environment** | `SECRET_KEY` and the optional `HIBP_API_KEY` come from env vars (`.env` is git-ignored; `.env.example` documents them). Nothing sensitive is hardcoded. |
| **Security headers** | Every response gets `Content-Security-Policy` (self + jsDelivr only), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`. |
| **XSS-safe rendering** | The dashboard JS inserts all server-supplied strings via `textContent`, never `innerHTML`. Bootstrap is loaded with subresource-integrity hashes. |
| **Graceful breach-check degradation** | If HIBP is unreachable the report says *"unverified"* rather than silently implying the password is clean — failing safe instead of failing misleadingly. |
| **Why SHA-1 here is fine** | SHA-1 is used only as HIBP's lookup-index format, not for password *storage*. Nothing derived from it is transmitted beyond the 5-char prefix. |

---

## API

### `POST /api/analyze`

```json
{ "password": "candidate-password", "check_breach": true }
```

**200 response (abridged):**

```json
{
  "length": 12,
  "score":   { "score": 84, "label": "Very Strong", "components": { "...": "..." } },
  "entropy": { "bits": 78.66, "category": "Strong", "pool_size": 94, "character_classes": { "...": "..." } },
  "crack_time": { "seconds": 1.2e13, "display": "3.9 thousand centuries", "...": "..." },
  "patterns": { "is_common_password": false, "dictionary_words": [], "...": "..." },
  "breach":   { "breached": false, "count": 0, "checked": true, "error": null },
  "recommendations": [ { "severity": "info", "message": "..." } ]
}
```

`400` for invalid input, `500` (sanitised) for internal errors.

---

## Disclaimer

This tool is for security education and password hygiene auditing. As a habit, never enter passwords you actively use into *any* third-party tool — use it to evaluate password *patterns* and candidate passwords instead.
