# Market Glass

Market Glass is a small, responsive end-of-day equity research application. It combines a
cream-and-ocean editorial interface, historical charts, and server-side accounts with private,
database-backed watchlists and chart preferences.

## What is implemented

- Landing/sign-in and account-registration experience.
- Server-protected dashboard route.
- Argon2id password hashing; passwords are never stored in plain text.
- Random session tokens stored as hashes in the database and delivered using HTTP-only,
  SameSite cookies. Sessions expire after 12 hours.
- User-scoped database watchlists and chart preferences.
- SQLite by default; PostgreSQL is supported with a PostgreSQL SQLAlchemy URL and the installed
  psycopg driver.
- Alembic schema migration.
- Yahoo Finance adjusted daily history for the dashboard's fixed 10-instrument universe.
- Historical analytics, chart comparison, watchlists, CSV export, and chart image export.

## Local setup (Windows PowerShell)

Run these commands from this project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Generate a session signing key:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Put the generated value in `.env` as `SESSION_HASH_KEY`. Do not commit `.env` or share its
contents. The example leaves this value blank so the application cannot accidentally use a known
example secret. If it is left blank in development, sessions are invalidated when the server
restarts.

Apply the schema, optionally refresh the end-of-day data, then run the web app:

```powershell
alembic upgrade head
python data\fetch_real_data.py
uvicorn app:app --reload
```

Open `http://127.0.0.1:8000`. Register an account to create a private workspace. SQLite data is
stored in `market_glass.db` in the project directory.

## Configuration

| Variable | Development default | Production guidance |
|---|---|---|
| `APP_ENV` | `development` | Set to `production`. |
| `DATABASE_URL` | `sqlite:///./market_glass.db` | Use a managed PostgreSQL URL and protect credentials. |
| `SESSION_HASH_KEY` | Temporary random key if unset | Required; use a high-entropy secret and rotate deliberately. |
| `COOKIE_SECURE` | `false` | Set `true` behind HTTPS so session cookies require TLS. |

When using PostgreSQL, create the database and supply a URL such as
`postgresql+psycopg://user:password@host:5432/market_glass`; URL-encode special characters in
credentials. Run `alembic upgrade head` after configuring the target database. Back up the database
and apply migrations as part of deployment.

## Data integrity and provider limitations

`data/market_data.js` contains adjusted daily close and volume observations downloaded from Yahoo
Finance. The page labels the latest completed observation; this is **not a real-time or intraday
feed**. Provider availability, adjustments, completeness, delays, and redistribution terms can
change. Verify important values with a properly licensed source. The refresh script refuses an
incomplete instrument response rather than replacing the current dataset with a partial one.

The current dashboard instruments are configured in `data/fetch_real_data.py`. The application
only accepts watchlist symbols present in its current market-data file; it is not an unrestricted
ticker search service.

## Authentication and account limitations

Passwords are hashed with Argon2id. Authentication endpoints have basic per-process sign-in
throttling; deploy behind a trusted HTTPS reverse proxy and add a shared rate limiter before
running multiple workers. The app has no email verification or password-reset delivery service, so
those flows are deliberately not presented as working features. Configure email delivery and the
associated token lifecycle before enabling account recovery in a deployment.

For production, also configure secure cookie delivery, a stable secret, database backups, monitoring,
provider licensing, and operational review. The in-memory sign-in limiter is intended as a basic
local safeguard, not a substitute for infrastructure-level abuse prevention.

## Implemented and not yet implemented

Authentication, protected access, private persistent watchlists, and persistent chart preferences
are implemented. The current application does not implement portfolio transaction tracking,
screening by fundamentals/sectors/market capitalization, market news, price-alert delivery, OAuth,
email verification, password reset, or self-service account settings. There is no live quote feed.
These are not represented as available features.

## Tests

```powershell
pytest -q
```

The tests cover registration and password hashing, sign-in/sign-out, dashboard protection,
watchlist persistence and user isolation, and preference validation.
