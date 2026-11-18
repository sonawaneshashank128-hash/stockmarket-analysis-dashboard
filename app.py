from __future__ import annotations

import hmac
import json
import logging
import os
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint, create_engine, event, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


ROOT = Path(__file__).resolve().parent
LOGGER = logging.getLogger("market_glass")
load_dotenv(ROOT / ".env")
APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{ROOT / 'market_glass.db'}")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true" if APP_ENV == "production" else "false").strip().lower() in {
    "1", "true", "yes"
}
SESSION_HOURS = 12
COOKIE_NAME = "market_glass_session"
SESSION_HASH_KEY = os.getenv("SESSION_HASH_KEY", "")
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,}$")
PASSWORD_HASHER = PasswordHasher(type=Type.ID)
DUMMY_PASSWORD_HASH = PASSWORD_HASHER.hash(secrets.token_urlsafe(32))
SUPPORTED_RANGES = {"1m", "3m", "6m", "ytd", "1y", "3y", "5y", "10y"}

if APP_ENV == "production" and not COOKIE_SECURE:
    raise RuntimeError("COOKIE_SECURE must be true in production.")

if not SESSION_HASH_KEY:
    if APP_ENV == "production":
        raise RuntimeError("SESSION_HASH_KEY must be configured in production.")
    SESSION_HASH_KEY = secrets.token_urlsafe(32)
    print("WARNING: using a temporary session key; all sessions expire when the app restarts.")

engine_options = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_options["connect_args"] = {"check_same_thread": False}
engine = create_engine(DATABASE_URL, **engine_options)
if DATABASE_URL.startswith("sqlite"):

    @event.listens_for(engine, "connect")
    def enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def utc_naive_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(80))
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_naive_now)


class LoginSession(Base):
    __tablename__ = "auth_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_naive_now)


class WatchlistItem(Base):
    __tablename__ = "watchlist_items"
    __table_args__ = (
        UniqueConstraint("user_id", "symbol", name="uq_watchlist_user_symbol"),
        UniqueConstraint("user_id", "position", name="uq_watchlist_user_position"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    symbol: Mapped[str] = mapped_column(String(32))
    position: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_naive_now)


class UserPreference(Base):
    __tablename__ = "user_preferences"

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    selected_symbol: Mapped[str] = mapped_column(String(32), default="")
    date_range: Mapped[str] = mapped_column(String(8), default="10y")
    compare_symbol: Mapped[str] = mapped_column(String(32), default="")
    sma50: Mapped[bool] = mapped_column(default=False)
    sma200: Mapped[bool] = mapped_column(default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utc_naive_now, onupdate=utc_naive_now)


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)
    display_name: str = Field(min_length=1, max_length=80)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class PreferenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    selected_symbol: str = Field(max_length=32)
    date_range: str = Field(max_length=8)
    compare_symbol: str = Field(max_length=32)
    sma50: bool
    sma200: bool


app = FastAPI(title="Market Glass", docs_url=None, redoc_url=None)
app.mount("/data", StaticFiles(directory=ROOT / "data"), name="data")
login_attempts: dict[str, deque[float]] = defaultdict(deque)
MAX_LOGIN_ATTEMPTS = 10
LOGIN_WINDOW_SECONDS = 15 * 60


def get_db():
    with SessionLocal() as db:
        yield db


DbSession = Annotated[Session, Depends(get_db)]


def load_symbols() -> set[str]:
    path = ROOT / "data" / "market_data.js"
    prefix = "window.MARKET_DATA = "
    contents = path.read_text(encoding="utf-8")
    if not contents.startswith(prefix):
        raise RuntimeError("Market data file has an invalid format.")
    dataset = json.loads(contents[len(prefix):].strip().removesuffix(";"))
    return set(dataset.get("symbols", {}))


SYMBOLS = load_symbols()


def ensure_same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if not origin:
        return
    host = request.headers.get("host", "")
    if origin not in {f"http://{host}", f"https://{host}"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid request origin.")


def token_digest(token: str) -> str:
    return hmac.new(SESSION_HASH_KEY.encode("utf-8"), token.encode("utf-8"), "sha256").hexdigest()


def get_current_user(request: Request, db: DbSession) -> User:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sign in to continue.")
    login_session = db.scalar(
        select(LoginSession).where(
            LoginSession.token_hash == token_digest(token),
            LoginSession.expires_at > datetime.now(timezone.utc).replace(tzinfo=None),
        )
    )
    if not login_session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your session expired. Sign in again.")
    user = db.get(User, login_session.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Your session is no longer valid.")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def set_session_cookie(response: Response, user: User, db: Session) -> None:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    db.query(LoginSession).filter(LoginSession.expires_at <= now).delete(synchronize_session=False)
    token = secrets.token_urlsafe(48)
    db.add(LoginSession(
        user_id=user.id,
        token_hash=token_digest(token),
        expires_at=now + timedelta(hours=SESSION_HOURS),
    ))
    db.commit()
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=SESSION_HOURS * 60 * 60,
        path="/",
    )


def check_login_rate_limit(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    attempts = login_attempts[client]
    while attempts and attempts[0] <= now - LOGIN_WINDOW_SECONDS:
        attempts.popleft()
    if len(attempts) >= MAX_LOGIN_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many sign-in attempts. Try again in 15 minutes.")
    attempts.append(now)


def user_payload(user: User) -> dict[str, object]:
    return {"id": user.id, "email": user.email, "display_name": user.display_name}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    return response


@app.get("/", include_in_schema=False)
def home(request: Request, db: DbSession):
    token = request.cookies.get(COOKIE_NAME)
    if token and db.scalar(select(LoginSession.id).where(
        LoginSession.token_hash == token_digest(token),
        LoginSession.expires_at > datetime.now(timezone.utc).replace(tzinfo=None),
    )):
        return RedirectResponse("/dashboard", status_code=303)
    return FileResponse(ROOT / "login.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard(request: Request, db: DbSession):
    token = request.cookies.get(COOKIE_NAME)
    if not token or not db.scalar(select(LoginSession.id).where(
        LoginSession.token_hash == token_digest(token),
        LoginSession.expires_at > datetime.now(timezone.utc).replace(tzinfo=None),
    )):
        return RedirectResponse("/", status_code=303)
    return FileResponse(ROOT / "index.html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, request: Request, response: Response, db: DbSession):
    ensure_same_origin(request)
    check_login_rate_limit(request)
    email = payload.email.strip().lower()
    display_name = payload.display_name.strip()
    if not EMAIL_PATTERN.fullmatch(email):
        raise HTTPException(status_code=422, detail="Enter a valid email address.")
    if not display_name:
        raise HTTPException(status_code=422, detail="Enter your name.")
    if db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(status_code=409, detail="An account with that email already exists.")
    user = User(email=email, display_name=display_name, password_hash=PASSWORD_HASHER.hash(payload.password))
    db.add(user)
    try:
        db.flush()
        db.add(UserPreference(user_id=user.id))
        db.add_all(
            WatchlistItem(user_id=user.id, symbol=symbol, position=position)
            for position, symbol in enumerate(sorted(SYMBOLS))
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        LOGGER.warning("Account creation conflicted with an existing record.")
        raise HTTPException(status_code=409, detail="Unable to create that account. Please try again.")
    db.refresh(user)
    set_session_cookie(response, user, db)
    return user_payload(user)


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, response: Response, db: DbSession):
    ensure_same_origin(request)
    check_login_rate_limit(request)
    email = payload.email.strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    try:
        PASSWORD_HASHER.verify(user.password_hash if user else DUMMY_PASSWORD_HASH, payload.password)
    except (VerifyMismatchError, InvalidHashError):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    if not user:
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    if PASSWORD_HASHER.check_needs_rehash(user.password_hash):
        user.password_hash = PASSWORD_HASHER.hash(payload.password)
        db.commit()
    set_session_cookie(response, user, db)
    return user_payload(user)


@app.post("/api/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, db: DbSession):
    ensure_same_origin(request)
    token = request.cookies.get(COOKIE_NAME)
    if token:
        db.query(LoginSession).filter(LoginSession.token_hash == token_digest(token)).delete()
        db.commit()
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, secure=COOKIE_SECURE, samesite="lax")


@app.get("/api/auth/me")
def me(user: CurrentUser):
    return user_payload(user)


@app.get("/api/watchlist")
def get_watchlist(user: CurrentUser, db: DbSession):
    items = db.scalars(
        select(WatchlistItem).where(WatchlistItem.user_id == user.id).order_by(WatchlistItem.position)
    ).all()
    return {"symbols": [item.symbol for item in items]}


@app.post("/api/watchlist/{symbol}", status_code=status.HTTP_201_CREATED)
def add_watchlist_item(symbol: str, request: Request, user: CurrentUser, db: DbSession):
    ensure_same_origin(request)
    symbol = symbol.strip().upper()
    if symbol not in SYMBOLS:
        raise HTTPException(status_code=404, detail="That instrument is not available in the current market dataset.")
    existing = db.scalar(select(WatchlistItem).where(
        WatchlistItem.user_id == user.id, WatchlistItem.symbol == symbol
    ))
    if existing:
        return {"symbols": list_watchlist_symbols(db, user.id)}
    count = db.scalar(select(func.count()).select_from(WatchlistItem).where(WatchlistItem.user_id == user.id)) or 0
    if count >= 100:
        raise HTTPException(status_code=409, detail="Watchlists can contain up to 100 instruments.")
    position = count
    db.add(WatchlistItem(user_id=user.id, symbol=symbol, position=position))
    db.commit()
    return {"symbols": list_watchlist_symbols(db, user.id)}


@app.delete("/api/watchlist/{symbol}")
def remove_watchlist_item(symbol: str, request: Request, user: CurrentUser, db: DbSession):
    ensure_same_origin(request)
    symbol = symbol.strip().upper()
    item = db.scalar(select(WatchlistItem).where(
        WatchlistItem.user_id == user.id, WatchlistItem.symbol == symbol
    ))
    if not item:
        raise HTTPException(status_code=404, detail="Instrument was not found in your watchlist.")
    count = db.scalar(select(WatchlistItem.id).where(
        WatchlistItem.user_id == user.id, WatchlistItem.id != item.id
    ).limit(2))
    if count is None:
        raise HTTPException(status_code=409, detail="Your watchlist must contain at least one instrument.")
    db.delete(item)
    db.commit()
    items = db.scalars(select(WatchlistItem).where(
        WatchlistItem.user_id == user.id
    ).order_by(WatchlistItem.position)).all()
    for position, remaining in enumerate(items):
        remaining.position = position
    db.commit()
    return {"symbols": [remaining.symbol for remaining in items]}


def list_watchlist_symbols(db: Session, user_id: int) -> list[str]:
    return list(db.scalars(
        select(WatchlistItem.symbol).where(WatchlistItem.user_id == user_id).order_by(WatchlistItem.position)
    ).all())


@app.get("/api/preferences")
def get_preferences(user: CurrentUser, db: DbSession):
    preference = db.get(UserPreference, user.id)
    if not preference:
        return {"selected_symbol": "", "date_range": "10y", "compare_symbol": "", "sma50": False, "sma200": False}
    return {
        "selected_symbol": preference.selected_symbol,
        "date_range": preference.date_range,
        "compare_symbol": preference.compare_symbol,
        "sma50": preference.sma50,
        "sma200": preference.sma200,
    }


@app.put("/api/preferences")
def update_preferences(payload: PreferenceRequest, request: Request, user: CurrentUser, db: DbSession):
    ensure_same_origin(request)
    if payload.date_range not in SUPPORTED_RANGES:
        raise HTTPException(status_code=422, detail="Choose a supported date range.")
    if payload.selected_symbol and payload.selected_symbol not in SYMBOLS:
        raise HTTPException(status_code=422, detail="Selected instrument is not available.")
    if payload.compare_symbol and payload.compare_symbol not in SYMBOLS:
        raise HTTPException(status_code=422, detail="Comparison instrument is not available.")
    if payload.compare_symbol == payload.selected_symbol:
        raise HTTPException(status_code=422, detail="Choose a different instrument to compare.")
    preference = db.get(UserPreference, user.id)
    if not preference:
        preference = UserPreference(user_id=user.id)
        db.add(preference)
    preference.selected_symbol = payload.selected_symbol
    preference.date_range = payload.date_range
    preference.compare_symbol = payload.compare_symbol
    preference.sma50 = payload.sma50
    preference.sma200 = payload.sma200
    db.commit()
    return {"status": "saved"}
