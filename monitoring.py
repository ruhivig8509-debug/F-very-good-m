#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    MONITORPRO SAAS - GOD LEVEL EDITION v4.0                  ║
║══════════════════════════════════════════════════════════════════════════════║
║  Ultimate Production Monitoring Platform                                     ║
║  Cyberpunk Glassmorphism UI + Advanced Backend                              ║
║  70+ Admin Features | JWT + 2FA | Real-time WebSocket                       ║
║  Default SuperAdmin: RUHIVIGQNR / RUHIVIGQNR                               ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

# =============================================================================
# SECTION 1: IMPORTS & DEPENDENCY MANAGEMENT
# =============================================================================
import os, sys, json, time, uuid, hashlib, secrets, asyncio, logging, sqlite3
import subprocess, re, threading, traceback, socket, platform, signal
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
from collections import defaultdict
from io import BytesIO, StringIO
from pathlib import Path
from contextlib import asynccontextmanager
from urllib.parse import urlparse
import csv

def install_deps():
    """Auto-install missing dependencies on first run"""
    deps = ["fastapi","uvicorn","sqlalchemy","python-jose","python-multipart",
            "httpx","pyotp","apscheduler","pydantic","psycopg2-binary","bcrypt","psutil"]
    for d in deps:
        try: __import__(d.replace("-","_"))
        except ImportError:
            print(f"[SETUP] Installing {d}...")
            subprocess.check_call([sys.executable,"-m","pip","install",d,"-q"])
install_deps()

from fastapi import (FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect,
    Request, Response, Query, Body, BackgroundTasks)
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import (create_engine, Column, Integer, String, Float, Boolean,
    DateTime, Text, ForeignKey, JSON as SA_JSON, func, text as sa_text)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.pool import StaticPool
from jose import JWTError, jwt
from pydantic import BaseModel
import pyotp, httpx, bcrypt as bcrypt_lib, psutil
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

# =============================================================================
# SECTION 2: CONFIGURATION
# =============================================================================
class Config:
    """Central configuration - reads from env vars with smart defaults"""
    APP_NAME = "MonitorPro God Level"
    VERSION = "4.0.0"
    SECRET = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
    JWT_ALGO = "HS256"
    JWT_EXPIRY = 24          # hours for access token
    REFRESH_EXPIRY = 168     # hours for refresh token (7 days)

    # Database: auto-detect Render PostgreSQL or fallback to SQLite
    _raw = os.environ.get("DATABASE_URL", "")
    if _raw:
        DB_URL = _raw.replace("postgres://", "postgresql://", 1) if _raw.startswith("postgres://") else _raw
    else:
        DB_URL = "sqlite:///./monitorpro.db"

    SUPERADMIN_USER = "RUHIVIGQNR"
    SUPERADMIN_PASS = "RUHIVIGQNR"
    HOST = "0.0.0.0"
    PORT = int(os.environ.get("PORT", 8000))
    MAX_MONITORS = 100
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_MINS = 30
    CHECK_INTERVAL = 60     # seconds between monitor checks
    LOG_RETENTION = 90      # days

    # Notification defaults (set via admin settings)
    TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
    TELEGRAM_CHAT = os.environ.get("TELEGRAM_CHAT", "")
    DISCORD_WEBHOOK = os.environ.get("DISCORD_WEBHOOK", "")

C = Config()

# =============================================================================
# SECTION 3: LOGGING
# =============================================================================
handlers = [logging.StreamHandler(sys.stdout)]
try: handlers.append(logging.FileHandler('monitorpro.log', mode='a'))
except: pass
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s', handlers=handlers)
log = logging.getLogger("MonitorPro")

# =============================================================================
# SECTION 4: DATABASE ENGINE
# =============================================================================
if C.DB_URL.startswith("sqlite"):
    engine = create_engine(C.DB_URL, connect_args={"check_same_thread": False}, poolclass=StaticPool, echo=False)
else:
    engine = create_engine(C.DB_URL, echo=False, pool_pre_ping=True, pool_size=5, max_overflow=10)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# =============================================================================
# SECTION 5: PASSWORD HASHING (Direct bcrypt - no passlib)
# =============================================================================
def hash_pw(password: str) -> str:
    """Hash password with bcrypt. Handles >72 byte passwords via SHA-256 pre-hash."""
    raw = password.encode("utf-8")
    if len(raw) > 72:
        raw = hashlib.sha256(raw).hexdigest().encode("utf-8")
    return bcrypt_lib.hashpw(raw, bcrypt_lib.gensalt(rounds=12)).decode("utf-8")

def check_pw(plain: str, hashed: str) -> bool:
    """Verify password against bcrypt hash."""
    try:
        raw = plain.encode("utf-8")
        if len(raw) > 72:
            raw = hashlib.sha256(raw).hexdigest().encode("utf-8")
        return bcrypt_lib.checkpw(raw, hashed.encode("utf-8"))
    except Exception as e:
        log.error(f"Password check error: {e}")
        return False

# =============================================================================
# SECTION 6: CACHE
# =============================================================================
class Cache:
    """Thread-safe in-memory cache with TTL support"""
    def __init__(self):
        self._d, self._e, self._l = {}, {}, threading.Lock()

    def get(self, k):
        with self._l:
            if k in self._d and time.time() < self._e.get(k, 0):
                return self._d[k]
            self._d.pop(k, None); self._e.pop(k, None)
            return None

    def set(self, k, v, ttl=300):
        with self._l:
            self._d[k] = v; self._e[k] = time.time() + ttl

    def delete(self, k):
        with self._l:
            self._d.pop(k, None); self._e.pop(k, None)

    def clear(self):
        with self._l:
            self._d.clear(); self._e.clear()

    def size(self):
        with self._l:
            now = time.time()
            return sum(1 for k in self._e if self._e[k] > now)

    def keys(self):
        with self._l:
            now = time.time()
            return [k for k in self._e if self._e[k] > now]

cache = Cache()

# =============================================================================
# SECTION 7: DATABASE MODELS (All Integer PKs, proper FKs)
# =============================================================================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    uid = Column(String(36), unique=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="user", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_banned = Column(Boolean, default=False, nullable=False)
    ban_reason = Column(String(500), nullable=True)
    totp_secret = Column(String(32), nullable=True)
    totp_enabled = Column(Boolean, default=False, nullable=False)
    avatar_url = Column(String(500), nullable=True)
    timezone = Column(String(50), default="UTC")
    theme = Column(String(20), default="dark")
    login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    last_login = Column(DateTime, nullable=True)
    last_ip = Column(String(45), nullable=True)
    api_key = Column(String(64), unique=True, nullable=True)
    refresh_token = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    monitors = relationship("Monitor", back_populates="owner", cascade="all, delete-orphan")
    alerts = relationship("AlertChannel", back_populates="owner", cascade="all, delete-orphan")
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")

class Monitor(Base):
    __tablename__ = "monitors"
    id = Column(Integer, primary_key=True, autoincrement=True)
    uid = Column(String(36), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(200), nullable=False)
    url = Column(String(2000), nullable=False)
    monitor_type = Column(String(20), default="http", nullable=False)
    status = Column(String(20), default="pending", nullable=False)
    interval = Column(Integer, default=60, nullable=False)
    timeout = Column(Integer, default=30, nullable=False)
    retries = Column(Integer, default=3, nullable=False)
    method = Column(String(10), default="GET")
    headers = Column(SA_JSON, nullable=True)
    body = Column(Text, nullable=True)
    expected_status = Column(Integer, default=200)
    keyword = Column(String(500), nullable=True)
    keyword_type = Column(String(20), default="contains")
    port = Column(Integer, nullable=True)
    uptime_percentage = Column(Float, default=100.0, nullable=False)
    avg_response_time = Column(Float, default=0.0, nullable=False)
    last_checked = Column(DateTime, nullable=True)
    last_status_change = Column(DateTime, nullable=True)
    is_paused = Column(Boolean, default=False, nullable=False)
    maintenance_mode = Column(Boolean, default=False, nullable=False)
    tags = Column(SA_JSON, nullable=True)
    ssl_check = Column(Boolean, default=True)
    ssl_expiry_date = Column(DateTime, nullable=True)
    ssl_days_remaining = Column(Integer, nullable=True)
    follow_redirects = Column(Boolean, default=True)
    regex_pattern = Column(String(500), nullable=True)
    alert_threshold = Column(Integer, default=1)
    consecutive_failures = Column(Integer, default=0, nullable=False)
    total_checks = Column(Integer, default=0, nullable=False)
    total_downtime_seconds = Column(Integer, default=0, nullable=False)
    notify_telegram = Column(Boolean, default=False)
    notify_discord = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    owner = relationship("User", back_populates="monitors")
    logs = relationship("MonitorLog", back_populates="monitor", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="monitor", cascade="all, delete-orphan")

class MonitorLog(Base):
    __tablename__ = "monitor_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    monitor_id = Column(Integer, ForeignKey("monitors.id", ondelete="CASCADE"), nullable=False)
    status = Column(String(20), nullable=False)
    response_time = Column(Float, nullable=True)
    status_code = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    ssl_days = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    monitor = relationship("Monitor", back_populates="logs")

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, autoincrement=True)
    uid = Column(String(36), unique=True, nullable=False)
    monitor_id = Column(Integer, ForeignKey("monitors.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(20), default="ongoing", nullable=False)
    severity = Column(String(20), default="high")
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(Integer, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    resolution = Column(Text, nullable=True)
    notified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    monitor = relationship("Monitor", back_populates="incidents")

class AlertChannel(Base):
    __tablename__ = "alert_channels"
    id = Column(Integer, primary_key=True, autoincrement=True)
    uid = Column(String(36), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(200), nullable=False)
    channel_type = Column(String(20), nullable=False)
    config = Column(SA_JSON, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_default = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    owner = relationship("User", back_populates="alerts")

class UserSession(Base):
    __tablename__ = "user_sessions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    session_token = Column(String(128), unique=True, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    device_type = Column(String(50), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow, nullable=False)
    user = relationship("User", back_populates="sessions")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=True)
    username = Column(String(100), nullable=True)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(50), nullable=True)
    details = Column(SA_JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)

class SiteSetting(Base):
    __tablename__ = "site_settings"
    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=True)
    category = Column(String(50), default="general")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    updated_by = Column(Integer, nullable=True)

class StatusPage(Base):
    __tablename__ = "status_pages"
    id = Column(Integer, primary_key=True, autoincrement=True)
    uid = Column(String(36), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(200), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    monitor_ids = Column(SA_JSON, nullable=True)
    is_public = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class IPWhitelist(Base):
    __tablename__ = "ip_whitelist"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), nullable=False)
    description = Column(String(200), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_by = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

# Create tables with error recovery
try:
    Base.metadata.create_all(bind=engine)
    log.info("✅ Database tables ready")
except Exception as e:
    log.error(f"Table error: {e}, attempting recreate...")
    try:
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        log.info("✅ Tables recreated")
    except Exception as e2:
        log.error(f"Fatal DB error: {e2}")

# =============================================================================
# SECTION 8: PYDANTIC SCHEMAS
# =============================================================================
class LoginReq(BaseModel):
    username: str; password: str; totp_code: Optional[str] = None

class RegisterReq(BaseModel):
    username: str; email: Optional[str] = None; password: str

class MonitorCreate(BaseModel):
    name: str; url: str; monitor_type: str = "http"; interval: int = 60
    timeout: int = 30; method: str = "GET"; expected_status: int = 200
    keyword: Optional[str] = None; port: Optional[int] = None
    tags: list = []; regex_pattern: Optional[str] = None
    notify_telegram: bool = False; notify_discord: bool = False

class MonitorUpdate(BaseModel):
    name: Optional[str]=None; url: Optional[str]=None; interval: Optional[int]=None
    is_paused: Optional[bool]=None; expected_status: Optional[int]=None
    keyword: Optional[str]=None; tags: Optional[list]=None

class UserUpdate(BaseModel):
    email: Optional[str]=None; role: Optional[str]=None
    is_active: Optional[bool]=None; theme: Optional[str]=None

class SettingUpdate(BaseModel):
    value: str; category: Optional[str] = None

# =============================================================================
# SECTION 9: JWT TOKEN SYSTEM (Access + Refresh)
# =============================================================================
def create_access_token(uid: int, uname: str, role: str) -> str:
    """Create short-lived access token"""
    return jwt.encode({"user_id": uid, "username": uname, "role": role,
        "type": "access", "exp": datetime.utcnow() + timedelta(hours=C.JWT_EXPIRY),
        "jti": str(uuid.uuid4())}, C.JWT_SECRET, algorithm=C.JWT_ALGO)

def create_refresh_token(uid: int) -> str:
    """Create long-lived refresh token"""
    return jwt.encode({"user_id": uid, "type": "refresh",
        "exp": datetime.utcnow() + timedelta(hours=C.REFRESH_EXPIRY),
        "jti": str(uuid.uuid4())}, C.JWT_SECRET, algorithm=C.JWT_ALGO)

def verify_token(token: str, token_type: str = "access") -> Optional[dict]:
    """Verify and decode JWT token"""
    try:
        p = jwt.decode(token, C.JWT_SECRET, algorithms=[C.JWT_ALGO])
        if p.get("type") != token_type: return None
        return p
    except JWTError:
        return None

# =============================================================================
# SECTION 10: AUTH DEPENDENCIES
# =============================================================================
security = HTTPBearer(auto_error=False)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

async def get_current_user(request: Request, cred: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Extract and verify current user from JWT token"""
    t = cred.credentials if cred else None
    if not t:
        ah = request.headers.get("Authorization", "")
        if ah.startswith("Bearer "): t = ah[7:]
    if not t: t = request.query_params.get("token")
    if not t: raise HTTPException(401, "Not authenticated")
    p = verify_token(t, "access")
    if not p: raise HTTPException(401, "Invalid or expired token")
    return p

async def require_admin(user=Depends(get_current_user)):
    if user["role"] not in ["admin", "superadmin"]: raise HTTPException(403, "Admin required")
    return user

async def require_superadmin(user=Depends(get_current_user)):
    if user["role"] != "superadmin": raise HTTPException(403, "Superadmin required")
    return user

def audit(db, uid, uname, action, rtype=None, rid=None, details=None, ip=None):
    """Log admin/user actions for audit trail"""
    try:
        db.add(AuditLog(user_id=uid, username=uname, action=action,
            resource_type=rtype, resource_id=rid, details=details or {}, ip_address=ip))
        db.commit()
    except: db.rollback()

# =============================================================================
# SECTION 11: NOTIFICATION ENGINE (Telegram + Discord)
# =============================================================================
class Notifier:
    """Send alerts to Telegram and Discord"""

    @staticmethod
    async def send_telegram(message: str, token: str = "", chat_id: str = ""):
        """Send message via Telegram Bot API"""
        tk = token or C.TELEGRAM_TOKEN
        ch = chat_id or C.TELEGRAM_CHAT
        if not tk or not ch: return False
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(f"https://api.telegram.org/bot{tk}/sendMessage",
                    json={"chat_id": ch, "text": message, "parse_mode": "HTML"})
                return r.status_code == 200
        except Exception as e:
            log.error(f"Telegram error: {e}")
            return False

    @staticmethod
    async def send_discord(message: str, webhook: str = ""):
        """Send message via Discord webhook"""
        wh = webhook or C.DISCORD_WEBHOOK
        if not wh: return False
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(wh, json={"content": message})
                return r.status_code in [200, 204]
        except Exception as e:
            log.error(f"Discord error: {e}")
            return False

    @staticmethod
    async def alert_monitor_down(monitor, error_msg=""):
        """Send DOWN alert to configured channels"""
        msg = f"🔴 <b>MONITOR DOWN</b>\n\n📌 {monitor.name}\n🔗 {monitor.url}\n❌ {error_msg}\n⏰ {datetime.utcnow().strftime('%H:%M:%S UTC')}"
        discord_msg = f"🔴 **MONITOR DOWN**\n📌 {monitor.name}\n🔗 {monitor.url}\n❌ {error_msg}"
        if monitor.notify_telegram: await Notifier.send_telegram(msg)
        if monitor.notify_discord: await Notifier.send_discord(discord_msg)

    @staticmethod
    async def alert_monitor_up(monitor):
        """Send UP recovery alert"""
        msg = f"🟢 <b>MONITOR RECOVERED</b>\n\n📌 {monitor.name}\n🔗 {monitor.url}\n✅ Back online\n⏰ {datetime.utcnow().strftime('%H:%M:%S UTC')}"
        discord_msg = f"🟢 **MONITOR RECOVERED**\n📌 {monitor.name}\n🔗 {monitor.url}\n✅ Back online"
        if monitor.notify_telegram: await Notifier.send_telegram(msg)
        if monitor.notify_discord: await Notifier.send_discord(discord_msg)

notifier = Notifier()

# =============================================================================
# SECTION 12: WEBSOCKET MANAGER
# =============================================================================
class WSManager:
    def __init__(self):
        self.user_conns: Dict[int, List[WebSocket]] = defaultdict(list)
        self.all_conns: List[WebSocket] = []

    async def connect(self, ws: WebSocket, user_id: int = 0):
        await ws.accept()
        if user_id: self.user_conns[user_id].append(ws)
        self.all_conns.append(ws)

    def disconnect(self, ws: WebSocket, user_id: int = 0):
        if user_id and ws in self.user_conns[user_id]:
            self.user_conns[user_id].remove(ws)
        if ws in self.all_conns: self.all_conns.remove(ws)

    async def send_user(self, uid: int, msg: dict):
        for c in self.user_conns.get(uid, []):
            try: await c.send_json(msg)
            except: pass

    async def broadcast(self, msg: dict):
        dead = []
        for c in self.all_conns:
            try: await c.send_json(msg)
            except: dead.append(c)
        for c in dead:
            if c in self.all_conns: self.all_conns.remove(c)

    @property
    def count(self): return len(self.all_conns)

wsman = WSManager()

# =============================================================================
# SECTION 13: MONITOR CHECKER ENGINE
# =============================================================================
class MonitorEngine:
    """Advanced async monitor checker with SSL tracking"""

    def __init__(self):
        self._client = None

    async def client(self):
        if not self._client:
            self._client = httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False)
        return self._client

    async def check_ssl(self, hostname: str) -> Optional[int]:
        """Check SSL certificate expiry days remaining"""
        try:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            loop = asyncio.get_event_loop()
            def _check():
                with socket.create_connection((hostname, 443), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        exp = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        return (exp - datetime.utcnow()).days
            return await loop.run_in_executor(None, _check)
        except:
            return None

    async def check_http(self, m: Monitor) -> dict:
        """HTTP/HTTPS/Keyword check"""
        start = time.time()
        r = {"status":"down","response_time":0,"status_code":None,"error_message":None,"ssl_days":None}
        try:
            c = await self.client()
            resp = await c.request(method=m.method or "GET", url=m.url,
                headers=m.headers or {}, content=m.body, timeout=m.timeout or 30)
            r["response_time"] = round((time.time()-start)*1000, 2)
            r["status_code"] = resp.status_code
            ok = resp.status_code == (m.expected_status or 200)

            # Keyword check
            if m.keyword and m.monitor_type == "keyword":
                body = resp.text[:5000]
                if m.keyword_type == "contains": ok = ok and m.keyword in body
                elif m.keyword_type == "not_contains": ok = ok and m.keyword not in body

            # Regex check
            if m.regex_pattern:
                try: ok = ok and bool(re.search(m.regex_pattern, resp.text[:5000]))
                except: pass

            r["status"] = "up" if ok else "down"

            # SSL expiry check
            if m.ssl_check and m.url.startswith("https"):
                try:
                    host = urlparse(m.url).hostname
                    r["ssl_days"] = await self.check_ssl(host)
                except: pass

        except Exception as e:
            r["response_time"] = round((time.time()-start)*1000, 2)
            r["error_message"] = str(e)[:500]
        return r

    async def check_port(self, m: Monitor) -> dict:
        """TCP Port check"""
        start = time.time()
        r = {"status":"down","response_time":0,"status_code":None,"error_message":None,"ssl_days":None}
        try:
            host = urlparse(m.url).hostname or m.url
            port = m.port or urlparse(m.url).port or 80
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(m.timeout or 10)
            await asyncio.get_event_loop().run_in_executor(None, s.connect, (host, port))
            s.close()
            r["response_time"] = round((time.time()-start)*1000, 2)
            r["status"] = "up"
        except Exception as e:
            r["response_time"] = round((time.time()-start)*1000, 2)
            r["error_message"] = str(e)[:500]
        return r

    async def check_ping(self, m: Monitor) -> dict:
        """ICMP Ping check"""
        start = time.time()
        r = {"status":"down","response_time":0,"error_message":None,"ssl_days":None,"status_code":None}
        try:
            host = urlparse(m.url).hostname or m.url
            cmd = ["ping","-c","1","-W",str(m.timeout or 10),host] if sys.platform != "win32" else \
                  ["ping","-n","1","-w",str((m.timeout or 10)*1000),host]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            await asyncio.wait_for(proc.communicate(), timeout=m.timeout or 15)
            r["response_time"] = round((time.time()-start)*1000, 2)
            r["status"] = "up" if proc.returncode == 0 else "down"
            if proc.returncode != 0: r["error_message"] = "Ping failed"
        except Exception as e:
            r["response_time"] = round((time.time()-start)*1000, 2)
            r["error_message"] = str(e)[:500]
        return r

    async def check(self, m: Monitor) -> dict:
        """Route to appropriate checker based on monitor type"""
        if m.monitor_type in ["http","https","keyword"]: return await self.check_http(m)
        elif m.monitor_type in ["port","tcp"]: return await self.check_port(m)
        elif m.monitor_type == "ping": return await self.check_ping(m)
        else: return await self.check_http(m)

engine_checker = MonitorEngine()
scheduler = AsyncIOScheduler()

# =============================================================================
# SECTION 14: BACKGROUND MONITOR CHECK LOOP
# =============================================================================
async def run_all_checks():
    """Main monitor check loop - runs every 60 seconds"""
    db = SessionLocal()
    try:
        monitors = db.query(Monitor).filter(Monitor.is_paused==False, Monitor.maintenance_mode==False).all()
        for m in monitors:
            try:
                r = await engine_checker.check(m)

                # Save log
                db.add(MonitorLog(monitor_id=m.id, status=r["status"],
                    response_time=r.get("response_time"), status_code=r.get("status_code"),
                    error_message=r.get("error_message"), ssl_days=r.get("ssl_days")))

                old_status = m.status
                m.status = r["status"]
                m.last_checked = datetime.utcnow()
                m.avg_response_time = r.get("response_time", 0)
                m.total_checks = (m.total_checks or 0) + 1

                # SSL tracking
                if r.get("ssl_days") is not None:
                    m.ssl_days_remaining = r["ssl_days"]
                    m.ssl_expiry_date = datetime.utcnow() + timedelta(days=r["ssl_days"])

                # Failure tracking
                if r["status"] == "down":
                    m.consecutive_failures = (m.consecutive_failures or 0) + 1
                    m.total_downtime_seconds = (m.total_downtime_seconds or 0) + m.interval
                else:
                    m.consecutive_failures = 0

                # Status change detection
                if old_status != r["status"]:
                    m.last_status_change = datetime.utcnow()

                    if r["status"] == "down":
                        # Create incident
                        inc = Incident(uid=str(uuid.uuid4()), monitor_id=m.id,
                            title=f"{m.name} is DOWN", description=r.get("error_message","Not responding"),
                            status="ongoing", severity="high")
                        db.add(inc)
                        # Send notifications
                        try: await notifier.alert_monitor_down(m, r.get("error_message",""))
                        except: pass

                    elif r["status"] == "up" and old_status == "down":
                        # Resolve incidents
                        for inc in db.query(Incident).filter(Incident.monitor_id==m.id, Incident.status=="ongoing").all():
                            inc.status = "resolved"; inc.resolved_at = datetime.utcnow()
                            if inc.started_at: inc.duration_seconds = int((datetime.utcnow()-inc.started_at).total_seconds())
                        try: await notifier.alert_monitor_up(m)
                        except: pass

                # Update uptime percentage
                total = db.query(MonitorLog).filter(MonitorLog.monitor_id==m.id).count()
                up = db.query(MonitorLog).filter(MonitorLog.monitor_id==m.id, MonitorLog.status=="up").count()
                if total > 0: m.uptime_percentage = round((up/total)*100, 2)

                db.commit()

                # WebSocket push
                try:
                    await wsman.send_user(m.user_id, {"type":"monitor_update","monitor_id":m.id,
                        "status":r["status"],"response_time":r.get("response_time"),"timestamp":datetime.utcnow().isoformat()})
                except: pass

            except Exception as e:
                log.error(f"Check error monitor {m.id}: {e}")
                db.rollback()
    except Exception as e:
        log.error(f"Check cycle error: {e}")
    finally:
        db.close()

async def cleanup_old_logs():
    """Remove logs older than retention period"""
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(days=C.LOG_RETENTION)
        db.query(MonitorLog).filter(MonitorLog.created_at < cutoff).delete()
        db.commit(); log.info("🧹 Old logs cleaned")
    except: db.rollback()
    finally: db.close()

# =============================================================================
# SECTION 15: SUPERADMIN INITIALIZATION
# =============================================================================
def init_superadmin():
    """Create superadmin user and default settings on first run"""
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username==C.SUPERADMIN_USER).first():
            log.info(f"🔑 Creating superadmin: {C.SUPERADMIN_USER}")
            db.add(User(uid=str(uuid.uuid4()), username=C.SUPERADMIN_USER,
                email="superadmin@monitorpro.io", password_hash=hash_pw(C.SUPERADMIN_PASS),
                role="superadmin", is_active=True, is_verified=True, is_banned=False,
                totp_enabled=False, login_attempts=0, api_key=secrets.token_hex(32),
                created_at=datetime.utcnow(), updated_at=datetime.utcnow()))
            db.flush()

        # Default settings
        defaults = {
            "site_name": ("MonitorPro God Level","general"),
            "maintenance_mode": ("false","general"),
            "registration_enabled": ("true","general"),
            "theme_primary": ("#6366f1","theme"),
            "theme_accent": ("#06b6d4","theme"),
            "particle_effects": ("true","theme"),
            "bg_video_url": ("https://cdn.pixabay.com/video/2020/05/25/40130-424930032_large.mp4","theme"),
            "bg_music_url": ("https://www.bensound.com/bensound-music/bensound-creativeminds.mp3","theme"),
            "telegram_token": ("","integrations"),
            "telegram_chat": ("","integrations"),
            "discord_webhook": ("","integrations"),
            "two_factor_required": ("false","security"),
        }
        for k,(v,c) in defaults.items():
            if not db.query(SiteSetting).filter(SiteSetting.key==k).first():
                db.add(SiteSetting(key=k, value=v, category=c, updated_at=datetime.utcnow()))
        db.commit()
        log.info("✅ SuperAdmin & settings initialized")
    except Exception as e:
        log.error(f"Init error: {e}\n{traceback.format_exc()}")
        db.rollback()
    finally:
        db.close()

# =============================================================================
# SECTION 16: FASTAPI APPLICATION
# =============================================================================
APP_START = time.time()

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_superadmin()
    scheduler.add_job(run_all_checks, IntervalTrigger(seconds=C.CHECK_INTERVAL), id="checks", replace_existing=True)
    scheduler.add_job(cleanup_old_logs, IntervalTrigger(hours=24), id="cleanup", replace_existing=True)
    scheduler.start()
    log.info("🚀 MonitorPro God Level v4.0 STARTED")
    yield
    scheduler.shutdown()
    if engine_checker._client: await engine_checker._client.aclose()
    log.info("🛑 MonitorPro STOPPED")

app = FastAPI(title="MonitorPro God Level", version="4.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# =============================================================================
# SECTION 17: AUTH API ROUTES
# =============================================================================
@app.post("/api/auth/login")
async def login(req: LoginReq, request: Request, db: Session = Depends(get_db)):
    try:
        u = db.query(User).filter(User.username==req.username).first()
        if not u: raise HTTPException(400, "Invalid credentials")
        if u.is_banned: raise HTTPException(403, f"Account banned: {u.ban_reason or 'Contact admin'}")
        if u.locked_until and u.locked_until > datetime.utcnow(): raise HTTPException(423, "Account locked")
        if not check_pw(req.password, u.password_hash):
            u.login_attempts = (u.login_attempts or 0) + 1
            if u.login_attempts >= C.MAX_LOGIN_ATTEMPTS:
                u.locked_until = datetime.utcnow() + timedelta(minutes=C.LOCKOUT_MINS)
            db.commit(); raise HTTPException(400, "Invalid credentials")
        if u.totp_enabled:
            if not req.totp_code: return JSONResponse({"requires_2fa": True, "message": "Enter 2FA code"})
            if not pyotp.TOTP(u.totp_secret).verify(req.totp_code, valid_window=1):
                raise HTTPException(400, "Invalid 2FA code")
        if not u.is_active: raise HTTPException(403, "Account disabled")

        # Reset login state
        u.login_attempts = 0; u.locked_until = None
        u.last_login = datetime.utcnow(); u.last_ip = request.client.host if request.client else None

        # Create tokens
        access = create_access_token(u.id, u.username, u.role)
        refresh = create_refresh_token(u.id)
        u.refresh_token = refresh

        # Create session
        ua = request.headers.get("user-agent","")[:500]
        device = "Mobile" if any(x in ua.lower() for x in ["mobile","android","iphone"]) else "Desktop"
        db.add(UserSession(user_id=u.id, session_token=secrets.token_hex(32),
            ip_address=request.client.host if request.client else None,
            user_agent=ua, device_type=device,
            expires_at=datetime.utcnow()+timedelta(hours=C.JWT_EXPIRY), last_activity=datetime.utcnow()))

        audit(db, u.id, u.username, "login", ip=request.client.host if request.client else None)
        db.commit()

        return JSONResponse({"access_token": access, "refresh_token": refresh, "token_type": "bearer",
            "user": {"id":u.id,"uid":u.uid,"username":u.username,"email":u.email,"role":u.role,
                "theme":u.theme,"totp_enabled":u.totp_enabled,"is_banned":u.is_banned}})
    except HTTPException: raise
    except Exception as e:
        log.error(f"Login error: {e}"); raise HTTPException(500, str(e))

@app.post("/api/auth/refresh")
async def refresh_token(refresh_token: str = Body(..., embed=True), db: Session = Depends(get_db)):
    """Get new access token using refresh token"""
    p = verify_token(refresh_token, "refresh")
    if not p: raise HTTPException(401, "Invalid refresh token")
    u = db.query(User).filter(User.id==p["user_id"]).first()
    if not u or u.refresh_token != refresh_token: raise HTTPException(401, "Token revoked")
    new_access = create_access_token(u.id, u.username, u.role)
    return JSONResponse({"access_token": new_access, "token_type": "bearer"})

@app.post("/api/auth/register")
async def register(req: RegisterReq, db: Session = Depends(get_db)):
    try:
        s = db.query(SiteSetting).filter(SiteSetting.key=="registration_enabled").first()
        if s and s.value == "false": raise HTTPException(403, "Registration disabled")
        if db.query(User).filter(User.username==req.username).first(): raise HTTPException(400, "Username taken")
        if req.email and db.query(User).filter(User.email==req.email).first(): raise HTTPException(400, "Email taken")
        u = User(uid=str(uuid.uuid4()), username=req.username, email=req.email,
            password_hash=hash_pw(req.password), role="user", is_active=True, is_banned=False,
            totp_enabled=False, login_attempts=0, api_key=secrets.token_hex(32),
            created_at=datetime.utcnow(), updated_at=datetime.utcnow())
        db.add(u); db.commit(); db.refresh(u)
        access = create_access_token(u.id, u.username, u.role)
        refresh = create_refresh_token(u.id); u.refresh_token = refresh; db.commit()
        return JSONResponse({"access_token": access, "refresh_token": refresh,
            "user": {"id":u.id,"username":u.username,"role":u.role}})
    except HTTPException: raise
    except Exception as e: db.rollback(); raise HTTPException(500, str(e))

@app.get("/api/auth/me")
async def me(user=Depends(get_current_user), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id==user["user_id"]).first()
    if not u: raise HTTPException(404)
    return JSONResponse({"id":u.id,"uid":u.uid,"username":u.username,"email":u.email,
        "role":u.role,"is_active":u.is_active,"is_banned":u.is_banned,"totp_enabled":u.totp_enabled,
        "theme":u.theme,"timezone":u.timezone,"api_key":u.api_key,
        "created_at":str(u.created_at),"last_login":str(u.last_login) if u.last_login else None})

@app.post("/api/auth/setup-2fa")
async def setup_2fa(user=Depends(get_current_user), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id==user["user_id"]).first()
    s = pyotp.random_base32(); u.totp_secret = s; db.commit()
    return JSONResponse({"secret":s,"uri":pyotp.TOTP(s).provisioning_uri(name=u.username,issuer_name="MonitorPro")})

@app.post("/api/auth/enable-2fa")
async def enable_2fa(code:str=Body(...,embed=True), user=Depends(get_current_user), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id==user["user_id"]).first()
    if not u.totp_secret: raise HTTPException(400,"Setup 2FA first")
    if not pyotp.TOTP(u.totp_secret).verify(code,valid_window=1): raise HTTPException(400,"Invalid code")
    u.totp_enabled = True; db.commit()
    return JSONResponse({"message":"2FA enabled"})

@app.post("/api/auth/change-password")
async def change_pw_route(current_password:str=Body(...),new_password:str=Body(...),user=Depends(get_current_user),db:Session=Depends(get_db)):
    u = db.query(User).filter(User.id==user["user_id"]).first()
    if not check_pw(current_password, u.password_hash): raise HTTPException(400,"Wrong password")
    u.password_hash = hash_pw(new_password); db.commit()
    return JSONResponse({"message":"Password changed"})

@app.post("/api/auth/regenerate-api-key")
async def regen_key(user=Depends(get_current_user), db:Session=Depends(get_db)):
    u = db.query(User).filter(User.id==user["user_id"]).first()
    u.api_key = secrets.token_hex(32); db.commit()
    return JSONResponse({"api_key":u.api_key})

@app.post("/api/auth/logout")
async def logout(user=Depends(get_current_user), db:Session=Depends(get_db)):
    u = db.query(User).filter(User.id==user["user_id"]).first()
    u.refresh_token = None
    db.query(UserSession).filter(UserSession.user_id==u.id).update({"is_active":False})
    db.commit()
    return JSONResponse({"message":"Logged out"})

# =============================================================================
# SECTION 18: MONITOR API ROUTES
# =============================================================================
@app.get("/api/monitors")
async def list_monitors(user=Depends(get_current_user), db:Session=Depends(get_db)):
    ms = db.query(Monitor).all() if user["role"]=="superadmin" else db.query(Monitor).filter(Monitor.user_id==user["user_id"]).all()
    return JSONResponse([{"id":m.id,"uid":m.uid,"name":m.name,"url":m.url,"monitor_type":m.monitor_type,
        "status":m.status,"interval":m.interval,"uptime_percentage":m.uptime_percentage,
        "avg_response_time":m.avg_response_time,"last_checked":str(m.last_checked) if m.last_checked else None,
        "is_paused":m.is_paused,"tags":m.tags or [],"consecutive_failures":m.consecutive_failures,
        "ssl_days_remaining":m.ssl_days_remaining,"total_checks":m.total_checks,
        "notify_telegram":m.notify_telegram,"notify_discord":m.notify_discord,
        "created_at":str(m.created_at),"user_id":m.user_id} for m in ms])

@app.post("/api/monitors")
async def create_monitor(data:MonitorCreate, user=Depends(get_current_user), db:Session=Depends(get_db)):
    if db.query(Monitor).filter(Monitor.user_id==user["user_id"]).count() >= C.MAX_MONITORS and user["role"]!="superadmin":
        raise HTTPException(400,"Monitor limit reached")
    m = Monitor(uid=str(uuid.uuid4()),user_id=user["user_id"],name=data.name,url=data.url,
        monitor_type=data.monitor_type,interval=data.interval,timeout=data.timeout,method=data.method,
        expected_status=data.expected_status,keyword=data.keyword,port=data.port,tags=data.tags or [],
        regex_pattern=data.regex_pattern,notify_telegram=data.notify_telegram,notify_discord=data.notify_discord,
        uptime_percentage=100.0,avg_response_time=0.0,consecutive_failures=0,total_checks=0,
        created_at=datetime.utcnow(),updated_at=datetime.utcnow())
    db.add(m); db.commit(); db.refresh(m)
    audit(db,user["user_id"],user["username"],"create_monitor","monitor",str(m.id))
    return JSONResponse({"id":m.id,"uid":m.uid,"message":"Monitor created"})

@app.get("/api/monitors/{mid}")
async def get_monitor(mid:int, user=Depends(get_current_user), db:Session=Depends(get_db)):
    m = db.query(Monitor).filter(Monitor.id==mid).first()
    if not m: raise HTTPException(404)
    if m.user_id!=user["user_id"] and user["role"]!="superadmin": raise HTTPException(403)
    return JSONResponse({"id":m.id,"uid":m.uid,"name":m.name,"url":m.url,"monitor_type":m.monitor_type,
        "status":m.status,"interval":m.interval,"timeout":m.timeout,"method":m.method,
        "expected_status":m.expected_status,"keyword":m.keyword,"port":m.port,
        "uptime_percentage":m.uptime_percentage,"avg_response_time":m.avg_response_time,
        "last_checked":str(m.last_checked) if m.last_checked else None,
        "is_paused":m.is_paused,"tags":m.tags or[],"ssl_check":m.ssl_check,
        "ssl_days_remaining":m.ssl_days_remaining,"ssl_expiry_date":str(m.ssl_expiry_date) if m.ssl_expiry_date else None,
        "regex_pattern":m.regex_pattern,"consecutive_failures":m.consecutive_failures,
        "total_checks":m.total_checks,"total_downtime_seconds":m.total_downtime_seconds,
        "notify_telegram":m.notify_telegram,"notify_discord":m.notify_discord,"created_at":str(m.created_at)})

@app.put("/api/monitors/{mid}")
async def update_monitor(mid:int, data:MonitorUpdate, user=Depends(get_current_user), db:Session=Depends(get_db)):
    m = db.query(Monitor).filter(Monitor.id==mid).first()
    if not m: raise HTTPException(404)
    if m.user_id!=user["user_id"] and user["role"]!="superadmin": raise HTTPException(403)
    for k,v in data.dict(exclude_unset=True).items(): setattr(m,k,v)
    db.commit()
    return JSONResponse({"message":"Updated"})

@app.delete("/api/monitors/{mid}")
async def delete_monitor(mid:int, user=Depends(get_current_user), db:Session=Depends(get_db)):
    m = db.query(Monitor).filter(Monitor.id==mid).first()
    if not m: raise HTTPException(404)
    if m.user_id!=user["user_id"] and user["role"]!="superadmin": raise HTTPException(403)
    db.delete(m); db.commit()
    return JSONResponse({"message":"Deleted"})

@app.post("/api/monitors/{mid}/pause")
async def pause_monitor(mid:int, user=Depends(get_current_user), db:Session=Depends(get_db)):
    m = db.query(Monitor).filter(Monitor.id==mid).first()
    if not m: raise HTTPException(404)
    if m.user_id!=user["user_id"] and user["role"]!="superadmin": raise HTTPException(403)
    m.is_paused = not m.is_paused; m.status = "paused" if m.is_paused else "pending"; db.commit()
    return JSONResponse({"is_paused":m.is_paused})

@app.post("/api/monitors/{mid}/check")
async def check_now(mid:int, user=Depends(get_current_user), db:Session=Depends(get_db)):
    m = db.query(Monitor).filter(Monitor.id==mid).first()
    if not m: raise HTTPException(404)
    if m.user_id!=user["user_id"] and user["role"]!="superadmin": raise HTTPException(403)
    r = await engine_checker.check(m)
    db.add(MonitorLog(monitor_id=m.id,status=r["status"],response_time=r.get("response_time"),
        status_code=r.get("status_code"),error_message=r.get("error_message"),ssl_days=r.get("ssl_days")))
    m.status=r["status"];m.last_checked=datetime.utcnow();m.avg_response_time=r.get("response_time",0);db.commit()
    return JSONResponse(r)

@app.get("/api/monitors/{mid}/logs")
async def monitor_logs(mid:int, limit:int=100, user=Depends(get_current_user), db:Session=Depends(get_db)):
    m = db.query(Monitor).filter(Monitor.id==mid).first()
    if not m: raise HTTPException(404)
    if m.user_id!=user["user_id"] and user["role"]!="superadmin": raise HTTPException(403)
    logs = db.query(MonitorLog).filter(MonitorLog.monitor_id==mid).order_by(MonitorLog.created_at.desc()).limit(limit).all()
    return JSONResponse([{"id":l.id,"status":l.status,"response_time":l.response_time,"status_code":l.status_code,
        "error_message":l.error_message,"ssl_days":l.ssl_days,"created_at":str(l.created_at)} for l in logs])

@app.get("/api/monitors/{mid}/uptime")
async def monitor_uptime(mid:int, days:int=30, user=Depends(get_current_user), db:Session=Depends(get_db)):
    m = db.query(Monitor).filter(Monitor.id==mid).first()
    if not m: raise HTTPException(404)
    since = datetime.utcnow()-timedelta(days=days)
    logs = db.query(MonitorLog).filter(MonitorLog.monitor_id==mid,MonitorLog.created_at>=since).all()
    total=len(logs); up=sum(1 for l in logs if l.status=="up")
    daily={}
    for l in logs:
        d=l.created_at.strftime("%Y-%m-%d")
        if d not in daily: daily[d]={"up":0,"total":0,"rt":[]}
        daily[d]["total"]+=1
        if l.status=="up": daily[d]["up"]+=1
        if l.response_time: daily[d]["rt"].append(l.response_time)
    heatmap=[{"date":d,"uptime":round(s["up"]/s["total"]*100,2) if s["total"] else 100,
        "avg_rt":round(sum(s["rt"])/len(s["rt"]),2) if s["rt"] else 0,"checks":s["total"]} for d,s in sorted(daily.items())]
    return JSONResponse({"uptime_percentage":round(up/total*100,2) if total else 100,"total_checks":total,"days":days,"heatmap":heatmap})

# =============================================================================
# SECTION 19: INCIDENTS
# =============================================================================
@app.get("/api/incidents")
async def list_incidents(status:Optional[str]=None, user=Depends(get_current_user), db:Session=Depends(get_db)):
    q = db.query(Incident).join(Monitor)
    if user["role"]!="superadmin": q=q.filter(Monitor.user_id==user["user_id"])
    if status: q=q.filter(Incident.status==status)
    return JSONResponse([{"id":i.id,"uid":i.uid,"monitor_id":i.monitor_id,"title":i.title,"description":i.description,
        "status":i.status,"severity":i.severity,"started_at":str(i.started_at),
        "resolved_at":str(i.resolved_at) if i.resolved_at else None,
        "duration_seconds":i.duration_seconds,"created_at":str(i.created_at)} for i in q.order_by(Incident.created_at.desc()).limit(100).all()])

@app.post("/api/incidents/{iid}/acknowledge")
async def ack_incident(iid:int, user=Depends(get_current_user), db:Session=Depends(get_db)):
    i=db.query(Incident).filter(Incident.id==iid).first()
    if not i: raise HTTPException(404)
    i.status="acknowledged";i.acknowledged_at=datetime.utcnow();i.acknowledged_by=user["user_id"];db.commit()
    return JSONResponse({"message":"Acknowledged"})

@app.post("/api/incidents/{iid}/resolve")
async def resolve_incident(iid:int, resolution:str=Body("",embed=True), user=Depends(get_current_user), db:Session=Depends(get_db)):
    i=db.query(Incident).filter(Incident.id==iid).first()
    if not i: raise HTTPException(404)
    i.status="resolved";i.resolved_at=datetime.utcnow();i.resolution=resolution
    if i.started_at: i.duration_seconds=int((datetime.utcnow()-i.started_at).total_seconds())
    db.commit()
    return JSONResponse({"message":"Resolved"})

# =============================================================================
# SECTION 20: DASHBOARD
# =============================================================================
@app.get("/api/dashboard/stats")
async def dash_stats(user=Depends(get_current_user), db:Session=Depends(get_db)):
    ms = db.query(Monitor).all() if user["role"]=="superadmin" else db.query(Monitor).filter(Monitor.user_id==user["user_id"]).all()
    t=len(ms); up=sum(1 for m in ms if m.status=="up"); dn=sum(1 for m in ms if m.status=="down")
    ssl_expiring = sum(1 for m in ms if m.ssl_days_remaining and m.ssl_days_remaining < 30)
    inc_q = db.query(Incident).filter(Incident.status=="ongoing") if user["role"]=="superadmin" else \
        db.query(Incident).join(Monitor).filter(Monitor.user_id==user["user_id"],Incident.status=="ongoing")
    return JSONResponse({"total_monitors":t,"up":up,"down":dn,"paused":sum(1 for m in ms if m.is_paused),
        "avg_uptime":round(sum(m.uptime_percentage or 0 for m in ms)/t,2) if t else 100,
        "avg_response_time":round(sum(m.avg_response_time or 0 for m in ms)/t,2) if t else 0,
        "ongoing_incidents":inc_q.count(),"ssl_expiring":ssl_expiring})

@app.get("/api/dashboard/charts")
async def dash_charts(hours:int=24, user=Depends(get_current_user), db:Session=Depends(get_db)):
    since=datetime.utcnow()-timedelta(hours=hours)
    if user["role"]=="superadmin": logs=db.query(MonitorLog).filter(MonitorLog.created_at>=since).all()
    else:
        mids=[m.id for m in db.query(Monitor).filter(Monitor.user_id==user["user_id"]).all()]
        logs=db.query(MonitorLog).filter(MonitorLog.monitor_id.in_(mids),MonitorLog.created_at>=since).all() if mids else []
    hourly={}
    for l in logs:
        h=l.created_at.strftime("%H:00")
        if h not in hourly: hourly[h]={"up":0,"down":0,"rt":[]}
        if l.status=="up": hourly[h]["up"]+=1
        else: hourly[h]["down"]+=1
        if l.response_time: hourly[h]["rt"].append(l.response_time)
    return JSONResponse({"chart_data":[{"time":h,"uptime":round(d["up"]/(d["up"]+d["down"])*100,2) if(d["up"]+d["down"]) else 100,
        "avg_response_time":round(sum(d["rt"])/len(d["rt"]),2) if d["rt"] else 0,"checks":d["up"]+d["down"]}
        for h,d in sorted(hourly.items())],"hours":hours})

# =============================================================================
# SECTION 21: ALERTS & STATUS PAGES
# =============================================================================
@app.get("/api/alerts")
async def list_alerts(user=Depends(get_current_user), db:Session=Depends(get_db)):
    return JSONResponse([{"id":a.id,"uid":a.uid,"name":a.name,"channel_type":a.channel_type,
        "config":a.config or{},"is_active":a.is_active,"is_default":a.is_default}
        for a in db.query(AlertChannel).filter(AlertChannel.user_id==user["user_id"]).all()])

@app.post("/api/alerts")
async def create_alert(data:AlertChannelCreate, user=Depends(get_current_user), db:Session=Depends(get_db)):
    a=AlertChannel(uid=str(uuid.uuid4()),user_id=user["user_id"],name=data.name,
        channel_type=data.channel_type,config=data.config,is_default=data.is_default,created_at=datetime.utcnow())
    db.add(a);db.commit()
    return JSONResponse({"id":a.id,"message":"Created"})

@app.delete("/api/alerts/{aid}")
async def del_alert(aid:int, user=Depends(get_current_user), db:Session=Depends(get_db)):
    a=db.query(AlertChannel).filter(AlertChannel.id==aid,AlertChannel.user_id==user["user_id"]).first()
    if a: db.delete(a); db.commit()
    return JSONResponse({"message":"Deleted"})

@app.get("/api/status/{slug}")
async def public_status(slug:str, db:Session=Depends(get_db)):
    p=db.query(StatusPage).filter(StatusPage.slug==slug,StatusPage.is_public==True).first()
    if not p: raise HTTPException(404)
    ms=db.query(Monitor).filter(Monitor.id.in_(p.monitor_ids or[])).all()
    return JSONResponse({"title":p.title,"description":p.description,
        "monitors":[{"name":m.name,"status":m.status,"uptime_percentage":m.uptime_percentage} for m in ms]})

# =============================================================================
# SECTION 22: SUPERADMIN COMMAND CENTER (70+ Features)
# =============================================================================

# --- User Management ---
@app.get("/api/admin/users")
async def admin_users(user=Depends(require_admin), db:Session=Depends(get_db)):
    return JSONResponse([{"id":u.id,"uid":u.uid,"username":u.username,"email":u.email,"role":u.role,
        "is_active":u.is_active,"is_banned":u.is_banned,"ban_reason":u.ban_reason,"totp_enabled":u.totp_enabled,
        "last_login":str(u.last_login) if u.last_login else None,"last_ip":u.last_ip,
        "login_attempts":u.login_attempts,"created_at":str(u.created_at)} for u in db.query(User).all()])

@app.post("/api/admin/users")
async def admin_create_user(username:str=Body(...),password:str=Body(...),email:str=Body(None),role:str=Body("user"),user=Depends(require_superadmin),db:Session=Depends(get_db)):
    u=User(uid=str(uuid.uuid4()),username=username,email=email,password_hash=hash_pw(password),role=role,
        is_active=True,is_banned=False,totp_enabled=False,login_attempts=0,api_key=secrets.token_hex(32),
        created_at=datetime.utcnow(),updated_at=datetime.utcnow())
    db.add(u);db.commit()
    audit(db,user["user_id"],user["username"],"create_user","user",str(u.id))
    return JSONResponse({"id":u.id,"message":"Created"})

@app.put("/api/admin/users/{uid}")
async def admin_update_user(uid:int,data:UserUpdate,user=Depends(require_admin),db:Session=Depends(get_db)):
    t=db.query(User).filter(User.id==uid).first()
    if not t: raise HTTPException(404)
    if t.role=="superadmin" and user["role"]!="superadmin": raise HTTPException(403)
    if data.role and user["role"]!="superadmin": raise HTTPException(403)
    for k,v in data.dict(exclude_unset=True).items(): setattr(t,k,v)
    db.commit()
    return JSONResponse({"message":"Updated"})

@app.delete("/api/admin/users/{uid}")
async def admin_del_user(uid:int,user=Depends(require_superadmin),db:Session=Depends(get_db)):
    t=db.query(User).filter(User.id==uid).first()
    if not t: raise HTTPException(404)
    if t.role=="superadmin": raise HTTPException(400,"Cannot delete superadmin")
    db.delete(t);db.commit()
    audit(db,user["user_id"],user["username"],"delete_user","user",str(uid))
    return JSONResponse({"message":"Deleted"})

# --- Ban/Unban ---
@app.post("/api/admin/users/{uid}/ban")
async def ban_user(uid:int,reason:str=Body("Violation",embed=True),user=Depends(require_superadmin),db:Session=Depends(get_db)):
    t=db.query(User).filter(User.id==uid).first()
    if not t: raise HTTPException(404)
    if t.role=="superadmin": raise HTTPException(400)
    t.is_banned=True;t.ban_reason=reason;t.is_active=False;t.refresh_token=None
    db.query(UserSession).filter(UserSession.user_id==uid).update({"is_active":False})
    db.commit()
    audit(db,user["user_id"],user["username"],"ban_user","user",str(uid),{"reason":reason})
    return JSONResponse({"message":"User banned"})

@app.post("/api/admin/users/{uid}/unban")
async def unban_user(uid:int,user=Depends(require_superadmin),db:Session=Depends(get_db)):
    t=db.query(User).filter(User.id==uid).first()
    if not t: raise HTTPException(404)
    t.is_banned=False;t.ban_reason=None;t.is_active=True;t.login_attempts=0;t.locked_until=None;db.commit()
    return JSONResponse({"message":"User unbanned"})

# --- Impersonation ---
@app.post("/api/admin/impersonate/{uid}")
async def impersonate(uid:int,user=Depends(require_superadmin),db:Session=Depends(get_db)):
    t=db.query(User).filter(User.id==uid).first()
    if not t: raise HTTPException(404)
    audit(db,user["user_id"],user["username"],"impersonate","user",str(uid))
    return JSONResponse({"access_token":create_access_token(t.id,t.username,t.role),
        "user":{"id":t.id,"username":t.username,"role":t.role}})

# --- Toggle/Reset ---
@app.post("/api/admin/users/{uid}/toggle-active")
async def toggle_active(uid:int,user=Depends(require_admin),db:Session=Depends(get_db)):
    t=db.query(User).filter(User.id==uid).first()
    if not t: raise HTTPException(404)
    t.is_active=not t.is_active;db.commit()
    return JSONResponse({"is_active":t.is_active})

@app.post("/api/admin/users/{uid}/reset-password")
async def reset_pw(uid:int,new_password:str=Body(...,embed=True),user=Depends(require_superadmin),db:Session=Depends(get_db)):
    t=db.query(User).filter(User.id==uid).first()
    if not t: raise HTTPException(404)
    t.password_hash=hash_pw(new_password);t.login_attempts=0;t.locked_until=None;db.commit()
    return JSONResponse({"message":"Password reset"})

@app.post("/api/admin/users/{uid}/unlock")
async def unlock_user(uid:int,user=Depends(require_admin),db:Session=Depends(get_db)):
    t=db.query(User).filter(User.id==uid).first()
    if not t: raise HTTPException(404)
    t.login_attempts=0;t.locked_until=None;db.commit()
    return JSONResponse({"message":"Unlocked"})

# --- Session Manager ---
@app.get("/api/admin/sessions")
async def admin_sessions(user=Depends(require_admin),db:Session=Depends(get_db)):
    return JSONResponse([{"id":s.id,"user_id":s.user_id,"ip_address":s.ip_address,
        "user_agent":s.user_agent[:100] if s.user_agent else None,"device_type":s.device_type,
        "is_active":s.is_active,"created_at":str(s.created_at),"expires_at":str(s.expires_at),
        "last_activity":str(s.last_activity)} for s in db.query(UserSession).filter(UserSession.is_active==True).order_by(UserSession.last_activity.desc()).limit(100).all()])

@app.delete("/api/admin/sessions/{sid}")
async def kill_session(sid:int,user=Depends(require_superadmin),db:Session=Depends(get_db)):
    s=db.query(UserSession).filter(UserSession.id==sid).first()
    if s: s.is_active=False;db.commit()
    audit(db,user["user_id"],user["username"],"kill_session","session",str(sid))
    return JSONResponse({"message":"Session killed"})

@app.post("/api/admin/users/{uid}/kill-all-sessions")
async def kill_all_sessions(uid:int,user=Depends(require_superadmin),db:Session=Depends(get_db)):
    db.query(UserSession).filter(UserSession.user_id==uid).update({"is_active":False});db.commit()
    return JSONResponse({"message":"All sessions killed"})

# --- System Stats with CPU/RAM ---
@app.get("/api/admin/system-stats")
async def sys_stats(user=Depends(require_admin),db:Session=Depends(get_db)):
    db_size=0
    if C.DB_URL.startswith("sqlite"):
        p=Path("monitorpro.db"); db_size=p.stat().st_size if p.exists() else 0
    else:
        try: db_size=db.execute(sa_text("SELECT pg_database_size(current_database())")).scalar() or 0
        except: pass

    # Server health via psutil
    cpu=psutil.cpu_percent(interval=0.5)
    mem=psutil.virtual_memory()
    disk=psutil.disk_usage('/')

    return JSONResponse({
        "total_users":db.query(User).count(),"total_monitors":db.query(Monitor).count(),
        "total_logs":db.query(MonitorLog).count(),"total_incidents":db.query(Incident).count(),
        "active_incidents":db.query(Incident).filter(Incident.status=="ongoing").count(),
        "active_sessions":db.query(UserSession).filter(UserSession.is_active==True).count(),
        "banned_users":db.query(User).filter(User.is_banned==True).count(),
        "cache_size":cache.size(),"database_size_mb":round(db_size/(1024*1024),2),
        "uptime_seconds":int(time.time()-APP_START),"websocket_connections":wsman.count,
        "scheduler_jobs":len(scheduler.get_jobs()),
        "server":{"cpu_percent":cpu,"ram_total_gb":round(mem.total/(1024**3),2),
            "ram_used_gb":round(mem.used/(1024**3),2),"ram_percent":mem.percent,
            "disk_total_gb":round(disk.total/(1024**3),2),"disk_used_gb":round(disk.used/(1024**3),2),
            "disk_percent":round(disk.percent,1),"platform":platform.platform(),
            "python":platform.python_version()}
    })

# --- Settings ---
@app.get("/api/admin/settings")
async def get_settings(user=Depends(require_admin),db:Session=Depends(get_db)):
    return JSONResponse([{"id":s.id,"key":s.key,"value":s.value,"category":s.category,"updated_at":str(s.updated_at)} for s in db.query(SiteSetting).all()])

@app.put("/api/admin/settings/{key}")
async def update_setting(key:str,data:SettingUpdate,user=Depends(require_superadmin),db:Session=Depends(get_db)):
    s=db.query(SiteSetting).filter(SiteSetting.key==key).first()
    if s: s.value=data.value;s.updated_by=user["user_id"]
    else: db.add(SiteSetting(key=key,value=data.value,category=data.category or"general",updated_at=datetime.utcnow()))
    db.commit()
    return JSONResponse({"message":f"'{key}' updated"})

# --- Audit Logs ---
@app.get("/api/admin/audit-logs")
async def audit_logs(limit:int=100,user=Depends(require_admin),db:Session=Depends(get_db)):
    return JSONResponse([{"id":l.id,"user_id":l.user_id,"username":l.username,"action":l.action,
        "resource_type":l.resource_type,"resource_id":l.resource_id,"details":l.details or{},
        "ip_address":l.ip_address,"created_at":str(l.created_at)}
        for l in db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()])

# --- Database Management ---
@app.post("/api/admin/database/backup")
async def db_backup(user=Depends(require_superadmin),db:Session=Depends(get_db)):
    if C.DB_URL.startswith("sqlite"):
        import shutil;n=f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.db"
        try: shutil.copy2("monitorpro.db",n); return JSONResponse({"message":f"Backup: {n}"})
        except Exception as e: raise HTTPException(500,str(e))
    return JSONResponse({"message":"Use pg_dump for PostgreSQL backups"})

@app.post("/api/admin/database/vacuum")
async def db_vacuum(user=Depends(require_superadmin),db:Session=Depends(get_db)):
    if C.DB_URL.startswith("sqlite"):
        c=sqlite3.connect("monitorpro.db");c.execute("VACUUM");c.close()
    else:
        try: db.execute(sa_text("VACUUM ANALYZE"));db.commit()
        except: db.rollback()
    return JSONResponse({"message":"Vacuumed"})

@app.get("/api/admin/database/stats")
async def db_table_stats(user=Depends(require_admin),db:Session=Depends(get_db)):
    tables={}
    for t in["users","monitors","monitor_logs","incidents","alert_channels","audit_logs","site_settings","user_sessions","status_pages","ip_whitelist"]:
        try: tables[t]=db.execute(sa_text(f"SELECT COUNT(*) FROM {t}")).scalar()
        except: tables[t]=0
    return JSONResponse({"tables":tables})

# --- Bulk Monitor Operations ---
@app.post("/api/admin/monitors/pause-all")
async def pause_all(user=Depends(require_superadmin),db:Session=Depends(get_db)):
    count=db.query(Monitor).update({Monitor.is_paused:True,Monitor.status:"paused"},synchronize_session=False);db.commit()
    audit(db,user["user_id"],user["username"],"pause_all_monitors")
    return JSONResponse({"message":f"{count} monitors paused"})

@app.post("/api/admin/monitors/resume-all")
async def resume_all(user=Depends(require_superadmin),db:Session=Depends(get_db)):
    count=db.query(Monitor).update({Monitor.is_paused:False,Monitor.status:"pending"},synchronize_session=False);db.commit()
    audit(db,user["user_id"],user["username"],"resume_all_monitors")
    return JSONResponse({"message":f"{count} monitors resumed"})

@app.post("/api/admin/monitors/delete-all")
async def delete_all_monitors(user=Depends(require_superadmin),db:Session=Depends(get_db)):
    db.query(MonitorLog).delete();db.query(Incident).delete();c=db.query(Monitor).delete();db.commit()
    audit(db,user["user_id"],user["username"],"delete_all_monitors",details={"count":c})
    return JSONResponse({"message":f"{c} monitors deleted"})

@app.post("/api/admin/monitors/bulk-pause")
async def bulk_pause(monitor_ids:List[int]=Body(...),user=Depends(require_admin),db:Session=Depends(get_db)):
    db.query(Monitor).filter(Monitor.id.in_(monitor_ids)).update({Monitor.is_paused:True,Monitor.status:"paused"},synchronize_session=False);db.commit()
    return JSONResponse({"message":f"{len(monitor_ids)} paused"})

@app.post("/api/admin/monitors/bulk-resume")
async def bulk_resume(monitor_ids:List[int]=Body(...),user=Depends(require_admin),db:Session=Depends(get_db)):
    db.query(Monitor).filter(Monitor.id.in_(monitor_ids)).update({Monitor.is_paused:False,Monitor.status:"pending"},synchronize_session=False);db.commit()
    return JSONResponse({"message":f"{len(monitor_ids)} resumed"})

# --- Log Management ---
@app.post("/api/admin/logs/rotate")
async def rotate_logs(days:int=Body(90,embed=True),user=Depends(require_superadmin),db:Session=Depends(get_db)):
    d=db.query(MonitorLog).filter(MonitorLog.created_at<datetime.utcnow()-timedelta(days=days)).delete();db.commit()
    return JSONResponse({"deleted_count":d})

@app.post("/api/admin/logs/clear-all")
async def clear_all_logs(user=Depends(require_superadmin),db:Session=Depends(get_db)):
    d=db.query(MonitorLog).delete();db.commit()
    return JSONResponse({"deleted_count":d})

# --- Cache & Scheduler ---
@app.post("/api/admin/cache/clear")
async def clear_cache(user=Depends(require_superadmin)): cache.clear(); return JSONResponse({"message":"Cleared"})

@app.get("/api/admin/cache/stats")
async def cache_st(user=Depends(require_admin)): return JSONResponse({"size":cache.size()})

@app.post("/api/admin/scheduler/trigger")
async def trigger_checks(user=Depends(require_superadmin)):
    asyncio.create_task(run_all_checks())
    return JSONResponse({"message":"Check cycle triggered"})

@app.get("/api/admin/scheduler/jobs")
async def sched_jobs(user=Depends(require_admin)):
    return JSONResponse({"jobs":[{"id":j.id,"next_run":str(j.next_run_time) if j.next_run_time else None} for j in scheduler.get_jobs()]})

# --- Health Check ---
@app.get("/api/admin/health")
async def admin_health(user=Depends(require_admin)):
    checks={"database":"ok","scheduler":"ok" if scheduler.running else "error","cache":"ok","notifications":"ok"}
    try: db=SessionLocal();db.execute(sa_text("SELECT 1"));db.close()
    except: checks["database"]="error"
    return JSONResponse({"status":"healthy" if all(v=="ok" for v in checks.values()) else "degraded","checks":checks})

# --- Toggles ---
@app.post("/api/admin/maintenance-mode/toggle")
async def toggle_maint(user=Depends(require_superadmin),db:Session=Depends(get_db)):
    s=db.query(SiteSetting).filter(SiteSetting.key=="maintenance_mode").first()
    if s: s.value="false" if s.value=="true" else "true"
    db.commit()
    return JSONResponse({"maintenance_mode":s.value if s else "false"})

@app.post("/api/admin/registration/toggle")
async def toggle_reg(user=Depends(require_superadmin),db:Session=Depends(get_db)):
    s=db.query(SiteSetting).filter(SiteSetting.key=="registration_enabled").first()
    if s: s.value="false" if s.value=="true" else "true"
    db.commit()
    return JSONResponse({"registration_enabled":s.value if s else "true"})

# --- Analytics ---
@app.get("/api/admin/analytics/uptime-heatmap")
async def heatmap(days:int=30,user=Depends(require_admin),db:Session=Depends(get_db)):
    since=datetime.utcnow()-timedelta(days=days);data=[]
    for m in db.query(Monitor).all():
        logs=db.query(MonitorLog).filter(MonitorLog.monitor_id==m.id,MonitorLog.created_at>=since).all()
        daily={}
        for l in logs:
            d=l.created_at.strftime("%Y-%m-%d")
            if d not in daily: daily[d]={"up":0,"t":0}
            daily[d]["t"]+=1
            if l.status=="up": daily[d]["up"]+=1
        data.append({"monitor_id":m.id,"name":m.name,"days":[{"date":d,"uptime":round(s["up"]/s["t"]*100,2) if s["t"] else 100} for d,s in sorted(daily.items())]})
    return JSONResponse({"heatmap":data})

@app.get("/api/admin/analytics/latency")
async def latency_stats(hours:int=24,user=Depends(require_admin),db:Session=Depends(get_db)):
    since=datetime.utcnow()-timedelta(hours=hours);data=[]
    for m in db.query(Monitor).all():
        rts=[l.response_time for l in db.query(MonitorLog).filter(MonitorLog.monitor_id==m.id,MonitorLog.created_at>=since,MonitorLog.response_time.isnot(None)).all() if l.response_time]
        if rts:
            sr=sorted(rts)
            data.append({"monitor_id":m.id,"name":m.name,"avg":round(sum(rts)/len(rts),2),"min":round(min(rts),2),
                "max":round(max(rts),2),"p95":round(sr[int(len(sr)*0.95)],2) if sr else 0,"samples":len(rts)})
    return JSONResponse({"data":data})

@app.get("/api/admin/analytics/incident-stats")
async def inc_stats(days:int=30,user=Depends(require_admin),db:Session=Depends(get_db)):
    incs=db.query(Incident).filter(Incident.created_at>=datetime.utcnow()-timedelta(days=days)).all()
    durs=[i.duration_seconds for i in incs if i.duration_seconds]
    return JSONResponse({"total":len(incs),"resolved":sum(1 for i in incs if i.status=="resolved"),
        "ongoing":sum(1 for i in incs if i.status=="ongoing"),
        "avg_duration":round(sum(durs)/len(durs),2) if durs else 0,"mttr":round(sum(durs)/len(durs)/60,2) if durs else 0})

@app.get("/api/admin/analytics/ssl-report")
async def ssl_report(user=Depends(require_admin),db:Session=Depends(get_db)):
    ms=db.query(Monitor).filter(Monitor.ssl_days_remaining.isnot(None)).all()
    return JSONResponse({"monitors":[{"id":m.id,"name":m.name,"url":m.url,"ssl_days":m.ssl_days_remaining,
        "expiry":str(m.ssl_expiry_date) if m.ssl_expiry_date else None,
        "status":"critical" if m.ssl_days_remaining<7 else "warning" if m.ssl_days_remaining<30 else "ok"} for m in ms]})

@app.get("/api/admin/analytics/error-breakdown")
async def errors(hours:int=24,user=Depends(require_admin),db:Session=Depends(get_db)):
    logs=db.query(MonitorLog).filter(MonitorLog.created_at>=datetime.utcnow()-timedelta(hours=hours),MonitorLog.status=="down").all()
    errs={}
    for l in logs: k=(l.error_message or"Unknown")[:100]; errs[k]=errs.get(k,0)+1
    return JSONResponse({"errors":errs,"total":len(logs)})

# --- Data Export ---
@app.get("/api/admin/export/monitors/json")
async def export_monitors_json(user=Depends(require_admin),db:Session=Depends(get_db)):
    data=[{"id":m.id,"name":m.name,"url":m.url,"type":m.monitor_type,"status":m.status,
        "uptime":m.uptime_percentage,"avg_rt":m.avg_response_time,"ssl_days":m.ssl_days_remaining}
        for m in db.query(Monitor).all()]
    return StreamingResponse(BytesIO(json.dumps(data,indent=2).encode()),media_type="application/json",
        headers={"Content-Disposition":"attachment;filename=monitors.json"})

@app.get("/api/admin/export/monitors/csv")
async def export_monitors_csv(user=Depends(require_admin),db:Session=Depends(get_db)):
    output=StringIO()
    writer=csv.writer(output)
    writer.writerow(["ID","Name","URL","Type","Status","Uptime%","AvgRT","SSL Days"])
    for m in db.query(Monitor).all():
        writer.writerow([m.id,m.name,m.url,m.monitor_type,m.status,m.uptime_percentage,m.avg_response_time,m.ssl_days_remaining])
    output.seek(0)
    return StreamingResponse(BytesIO(output.getvalue().encode()),media_type="text/csv",
        headers={"Content-Disposition":"attachment;filename=monitors.csv"})

@app.get("/api/admin/export/logs/json")
async def export_logs_json(days:int=7,user=Depends(require_admin),db:Session=Depends(get_db)):
    logs=db.query(MonitorLog).filter(MonitorLog.created_at>=datetime.utcnow()-timedelta(days=days)).limit(50000).all()
    data=[{"monitor_id":l.monitor_id,"status":l.status,"response_time":l.response_time,
        "status_code":l.status_code,"error":l.error_message,"ssl_days":l.ssl_days,"time":str(l.created_at)} for l in logs]
    return StreamingResponse(BytesIO(json.dumps(data).encode()),media_type="application/json",
        headers={"Content-Disposition":"attachment;filename=logs.json"})

@app.get("/api/admin/export/logs/csv")
async def export_logs_csv(days:int=7,user=Depends(require_admin),db:Session=Depends(get_db)):
    logs=db.query(MonitorLog).filter(MonitorLog.created_at>=datetime.utcnow()-timedelta(days=days)).limit(50000).all()
    output=StringIO()
    writer=csv.writer(output)
    writer.writerow(["MonitorID","Status","ResponseTime","StatusCode","Error","SSLDays","Time"])
    for l in logs: writer.writerow([l.monitor_id,l.status,l.response_time,l.status_code,l.error_message,l.ssl_days,str(l.created_at)])
    output.seek(0)
    return StreamingResponse(BytesIO(output.getvalue().encode()),media_type="text/csv",
        headers={"Content-Disposition":"attachment;filename=logs.csv"})

@app.get("/api/admin/export/users")
async def export_users(user=Depends(require_superadmin),db:Session=Depends(get_db)):
    return StreamingResponse(BytesIO(json.dumps([{"id":u.id,"username":u.username,"email":u.email,
        "role":u.role,"is_active":u.is_active,"is_banned":u.is_banned,"created":str(u.created_at)} for u in db.query(User).all()],indent=2).encode()),
        media_type="application/json",headers={"Content-Disposition":"attachment;filename=users.json"})

# --- IP Whitelist ---
@app.get("/api/admin/ip-whitelist")
async def get_ips(user=Depends(require_admin),db:Session=Depends(get_db)):
    return JSONResponse([{"id":i.id,"ip_address":i.ip_address,"description":i.description,"is_active":i.is_active} for i in db.query(IPWhitelist).all()])

@app.post("/api/admin/ip-whitelist")
async def add_ip(ip_address:str=Body(...),description:str=Body(""),user=Depends(require_superadmin),db:Session=Depends(get_db)):
    db.add(IPWhitelist(ip_address=ip_address,description=description,created_by=user["user_id"]));db.commit()
    return JSONResponse({"message":"Added"})

@app.delete("/api/admin/ip-whitelist/{iid}")
async def del_ip(iid:int,user=Depends(require_superadmin),db:Session=Depends(get_db)):
    i=db.query(IPWhitelist).filter(IPWhitelist.id==iid).first()
    if i: db.delete(i);db.commit()
    return JSONResponse({"message":"Removed"})

# --- Notification Test ---
@app.post("/api/admin/test-telegram")
async def test_tg(message:str=Body("Test from MonitorPro!",embed=True),user=Depends(require_superadmin)):
    ok=await Notifier.send_telegram(message)
    return JSONResponse({"success":ok})

@app.post("/api/admin/test-discord")
async def test_dc(message:str=Body("Test from MonitorPro!",embed=True),user=Depends(require_superadmin)):
    ok=await Notifier.send_discord(message)
    return JSONResponse({"success":ok})

# --- All Features List ---
@app.get("/api/admin/features")
async def features_list(user=Depends(require_admin)):
    f=[
        ("User CRUD","Users"),("Ban/Unban Users","Users"),("User Impersonation","Users"),("Toggle Active","Users"),
        ("Reset Password","Users"),("Unlock User","Users"),("Session Manager","Security"),("Kill Session","Security"),
        ("Kill All Sessions","Security"),("IP Whitelist","Security"),("2FA Toggle","Security"),("Audit Logs","Security"),
        ("System Stats + CPU/RAM","System"),("Health Check","System"),("Scheduler Jobs","System"),("Trigger Checks","System"),
        ("Maintenance Mode","System"),("Registration Toggle","System"),("Site Settings","Settings"),("Theme Engine","Theme"),
        ("Video Background","Theme"),("Music Player","Theme"),("Database Backup","Database"),("Database Vacuum","Database"),
        ("Database Stats","Database"),("Cache Clear","Cache"),("Cache Stats","Cache"),("Log Rotation","Maintenance"),
        ("Clear All Logs","Maintenance"),("Bulk Pause","Monitors"),("Bulk Resume","Monitors"),("Bulk Delete","Monitors"),
        ("Pause All","Monitors"),("Resume All","Monitors"),("Delete All","Monitors"),("SSL Expiry Report","Analytics"),
        ("Uptime Heatmap","Analytics"),("Latency Analytics","Analytics"),("Incident Stats","Analytics"),
        ("Error Breakdown","Analytics"),("Export Monitors JSON","Export"),("Export Monitors CSV","Export"),
        ("Export Logs JSON","Export"),("Export Logs CSV","Export"),("Export Users","Export"),
        ("Test Telegram","Notifications"),("Test Discord","Notifications"),("Telegram Alerts","Notifications"),
        ("Discord Alerts","Notifications"),("HTTP Monitoring","Monitors"),("HTTPS + SSL","Monitors"),
        ("Ping Monitoring","Monitors"),("TCP Port Check","Monitors"),("Keyword Check","Monitors"),
        ("Regex Check","Monitors"),("JWT Access Tokens","Auth"),("JWT Refresh Tokens","Auth"),
        ("2FA TOTP","Auth"),("API Key Auth","Auth"),("WebSocket Updates","Realtime"),
        ("Status Pages","Public"),("Monitor Logs","Reports"),("Uptime Reports","Reports"),
        ("Incident Management","Incidents"),("Alert Channels","Alerts"),("Dashboard Stats","Dashboard"),
        ("Dashboard Charts","Dashboard"),("Password Change","Auth"),("API Key Regeneration","Auth"),
        ("User Registration","Auth"),("Session Tracking","Security"),("Device Detection","Security"),
        ("Feature List","System"),("Public Health","System"),("Monitor Pause/Resume","Monitors"),
        ("Instant Check","Monitors"),("Auto Log Cleanup","Maintenance"),("Downtime Tracking","Analytics"),
    ]
    return JSONResponse({"features":[{"id":i+1,"name":n,"category":c} for i,(n,c) in enumerate(f)],"total":len(f)})

# =============================================================================
# SECTION 23: WEBSOCKET
# =============================================================================
@app.websocket("/ws")
async def ws_endpoint(websocket:WebSocket, token:Optional[str]=Query(None)):
    uid=0
    if token:
        p=verify_token(token)
        if p: uid=p.get("user_id",0)
    await wsman.connect(websocket,uid)
    try:
        while True:
            data=await websocket.receive_text()
            try:
                m=json.loads(data)
                if m.get("type")=="ping": await websocket.send_json({"type":"pong","ts":datetime.utcnow().isoformat()})
            except: pass
    except WebSocketDisconnect: wsman.disconnect(websocket,uid)

# =============================================================================
# SECTION 24: PUBLIC ENDPOINTS
# =============================================================================
@app.get("/api/health")
async def public_health():
    return JSONResponse({"status":"healthy","app":C.APP_NAME,"version":C.VERSION,
        "database":"postgresql" if "postgresql" in C.DB_URL else "sqlite",
        "uptime":int(time.time()-APP_START)})

# =============================================================================
# SECTION 25: GOD-LEVEL CYBERPUNK FRONTEND
# =============================================================================
# Due to the massive size, the frontend is loaded as a separate constant
# This is the complete React + Tailwind + Framer Motion inspired UI

FRONTEND = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<meta name="theme-color" content="#020617">
<meta name="apple-mobile-web-app-capable" content="yes">
<title>MonitorPro ⚡ God Level</title>
<script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{font-family:'Inter',system-ui,sans-serif}
body{background:#020617;color:#e2e8f0;overflow-x:hidden;min-height:100vh}
::-webkit-scrollbar{width:3px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#6366f1;border-radius:4px}

/* Video Background */
#vbg{position:fixed;top:0;left:0;width:100vw;height:100vh;object-fit:cover;z-index:0;opacity:0.15;pointer-events:none;filter:saturate(0.5) hue-rotate(220deg)}
#ovl{position:fixed;top:0;left:0;width:100%;height:100%;background:linear-gradient(180deg,rgba(2,6,23,0.88) 0%,rgba(2,6,23,0.95) 100%);z-index:1;pointer-events:none}
.z2{position:relative;z-index:2}

/* Glassmorphism */
.glass{background:rgba(15,23,42,0.6);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid rgba(99,102,241,0.12)}
.card{background:rgba(15,23,42,0.5);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid rgba(148,163,184,0.06);border-radius:20px;transition:all 0.3s cubic-bezier(0.16,1,0.3,1)}
.card:hover{border-color:rgba(99,102,241,0.2);box-shadow:0 0 40px rgba(99,102,241,0.06)}
.card:active{transform:scale(0.98)}

/* Neon glow effects */
.neon-purple{text-shadow:0 0 10px rgba(139,92,246,0.5),0 0 40px rgba(139,92,246,0.2)}
.neon-cyan{text-shadow:0 0 10px rgba(6,182,212,0.5),0 0 40px rgba(6,182,212,0.2)}
.glow-box{box-shadow:0 0 30px rgba(99,102,241,0.1),inset 0 0 30px rgba(99,102,241,0.02)}

/* Animations */
@keyframes slideUp{from{transform:translateY(40px);opacity:0}to{transform:translateY(0);opacity:1}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes pulse-g{0%,100%{box-shadow:0 0 0 0 rgba(34,197,94,0.5)}50%{box-shadow:0 0 0 12px rgba(34,197,94,0)}}
@keyframes pulse-r{0%,100%{box-shadow:0 0 0 0 rgba(239,68,68,0.5)}50%{box-shadow:0 0 0 12px rgba(239,68,68,0)}}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
@keyframes scanline{0%{top:-100%}100%{top:200%}}
@keyframes glitch{0%,100%{transform:translate(0)}20%{transform:translate(-2px,2px)}40%{transform:translate(2px,-2px)}60%{transform:translate(-1px,1px)}80%{transform:translate(1px,-1px)}}
@keyframes borderGlow{0%,100%{border-color:rgba(99,102,241,0.2)}50%{border-color:rgba(99,102,241,0.5)}}
@keyframes typing{from{width:0}to{width:100%}}
@keyframes eq{to{height:3px}}

.anim{animation:slideUp 0.5s cubic-bezier(0.16,1,0.3,1) both}
.anim-d1{animation-delay:0.05s}.anim-d2{animation-delay:0.1s}.anim-d3{animation-delay:0.15s}.anim-d4{animation-delay:0.2s}
.fade{animation:fadeIn 0.4s ease}
.pulse-g{animation:pulse-g 2s infinite}.pulse-r{animation:pulse-r 1.5s infinite}
.float{animation:float 3s ease-in-out infinite}
.skeleton{background:linear-gradient(90deg,#0f172a 25%,#1e293b 50%,#0f172a 75%);background-size:200% 100%;animation:shimmer 1.5s infinite;border-radius:12px}
.border-glow{animation:borderGlow 3s ease-in-out infinite}

/* Buttons */
.btn{padding:12px 24px;border-radius:14px;font-weight:700;font-size:13px;border:none;cursor:pointer;transition:all 0.25s;display:inline-flex;align-items:center;justify-content:center;gap:8px;letter-spacing:0.3px;position:relative;overflow:hidden}
.btn:active{transform:scale(0.95)}
.btn::after{content:'';position:absolute;top:50%;left:50%;width:0;height:0;background:rgba(255,255,255,0.1);border-radius:50%;transition:all 0.4s;transform:translate(-50%,-50%)}
.btn:active::after{width:200px;height:200px}
.btn-primary{background:linear-gradient(135deg,#6366f1,#8b5cf6,#a78bfa);color:#fff;box-shadow:0 4px 25px rgba(99,102,241,0.35)}
.btn-primary:hover{box-shadow:0 8px 40px rgba(99,102,241,0.5);transform:translateY(-2px)}
.btn-ghost{background:rgba(99,102,241,0.08);color:#a5b4fc;border:1px solid rgba(99,102,241,0.15)}
.btn-ghost:hover{background:rgba(99,102,241,0.15);border-color:rgba(99,102,241,0.3)}
.btn-danger{background:rgba(239,68,68,0.08);color:#fca5a5;border:1px solid rgba(239,68,68,0.15)}
.btn-success{background:rgba(34,197,94,0.08);color:#86efac;border:1px solid rgba(34,197,94,0.15)}
.btn-cyan{background:rgba(6,182,212,0.08);color:#67e8f9;border:1px solid rgba(6,182,212,0.15)}
.btn-amber{background:rgba(245,158,11,0.08);color:#fcd34d;border:1px solid rgba(245,158,11,0.15)}
.btn-sm{padding:8px 16px;font-size:11px;border-radius:10px}

/* Inputs */
.input{background:rgba(2,6,23,0.8);border:2px solid rgba(148,163,184,0.1);color:#f1f5f9;padding:14px 18px;border-radius:14px;width:100%;font-size:16px;outline:none;transition:all 0.3s;font-family:'Inter',sans-serif}
.input:focus{border-color:#6366f1;box-shadow:0 0 0 4px rgba(99,102,241,0.08),0 0 20px rgba(99,102,241,0.05);background:rgba(2,6,23,0.95)}
.input::placeholder{color:#475569}
select.input{appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2364748b' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 14px center;padding-right:40px}

/* FAB */
.fab{position:fixed;right:20px;bottom:90px;width:60px;height:60px;border-radius:30px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border:none;font-size:26px;cursor:pointer;box-shadow:0 8px 35px rgba(99,102,241,0.5);z-index:40;display:flex;align-items:center;justify-content:center;transition:all 0.3s}
.fab:active{transform:scale(0.88) rotate(45deg)}

/* Bottom Nav */
.bnav{position:fixed;bottom:0;left:0;right:0;height:72px;z-index:30}
.safe-b{padding-bottom:95px}

/* Modal */
.modal-bg{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.8);backdrop-filter:blur(10px);z-index:50;display:flex;align-items:flex-end;justify-content:center}
.modal{background:linear-gradient(180deg,#0f172a,#020617);border-radius:28px 28px 0 0;width:100%;max-width:500px;max-height:90vh;overflow-y:auto;padding:28px;border:1px solid rgba(99,102,241,0.1);border-bottom:none}

/* Badges */
.badge{padding:4px 12px;border-radius:20px;font-size:10px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;display:inline-block}
.b-up{background:rgba(34,197,94,0.12);color:#4ade80;border:1px solid rgba(34,197,94,0.2)}
.b-down{background:rgba(239,68,68,0.12);color:#f87171;border:1px solid rgba(239,68,68,0.2)}
.b-pending{background:rgba(245,158,11,0.12);color:#fbbf24;border:1px solid rgba(245,158,11,0.2)}
.b-paused{background:rgba(148,163,184,0.12);color:#94a3b8;border:1px solid rgba(148,163,184,0.2)}
.b-sa{background:rgba(168,85,247,0.12);color:#c084fc;border:1px solid rgba(168,85,247,0.2)}
.b-admin{background:rgba(6,182,212,0.12);color:#67e8f9;border:1px solid rgba(6,182,212,0.2)}
.b-banned{background:rgba(239,68,68,0.2);color:#f87171;border:1px solid rgba(239,68,68,0.3)}

/* Stat Card */
.stat{border-radius:20px;padding:20px;position:relative;overflow:hidden}
.stat::after{content:'';position:absolute;top:-30px;right:-30px;width:100px;height:100px;border-radius:50%;opacity:0.06}
.s-indigo{background:linear-gradient(135deg,rgba(99,102,241,0.12),rgba(99,102,241,0.03));border:1px solid rgba(99,102,241,0.15)}.s-indigo::after{background:#6366f1}
.s-green{background:linear-gradient(135deg,rgba(34,197,94,0.12),rgba(34,197,94,0.03));border:1px solid rgba(34,197,94,0.15)}.s-green::after{background:#22c55e}
.s-red{background:linear-gradient(135deg,rgba(239,68,68,0.12),rgba(239,68,68,0.03));border:1px solid rgba(239,68,68,0.15)}.s-red::after{background:#ef4444}
.s-purple{background:linear-gradient(135deg,rgba(168,85,247,0.12),rgba(168,85,247,0.03));border:1px solid rgba(168,85,247,0.15)}.s-purple::after{background:#a855f7}
.s-cyan{background:linear-gradient(135deg,rgba(6,182,212,0.12),rgba(6,182,212,0.03));border:1px solid rgba(6,182,212,0.15)}.s-cyan::after{background:#06b6d4}
.s-amber{background:linear-gradient(135deg,rgba(245,158,11,0.12),rgba(245,158,11,0.03));border:1px solid rgba(245,158,11,0.15)}.s-amber::after{background:#f59e0b}

/* Chart */
.chart-bar{transition:height 0.5s cubic-bezier(0.16,1,0.3,1);border-radius:4px 4px 0 0}

/* Music */
.music{position:fixed;top:0;left:0;right:0;height:44px;z-index:25;display:flex;align-items:center;justify-content:space-between;padding:0 16px}
.eq{display:flex;gap:2px;align-items:flex-end;height:14px}
.eq span{width:2px;background:linear-gradient(180deg,#06b6d4,#6366f1);border-radius:2px;animation:eq 0.6s ease-in-out infinite alternate}
.eq span:nth-child(1){height:5px;animation-delay:0s}.eq span:nth-child(2){height:10px;animation-delay:0.15s}
.eq span:nth-child(3){height:7px;animation-delay:0.3s}.eq span:nth-child(4){height:12px;animation-delay:0.1s}
.eq span:nth-child(5){height:4px;animation-delay:0.25s}

/* Terminal feel */
.terminal{background:rgba(2,6,23,0.9);border:1px solid rgba(34,197,94,0.15);border-radius:12px;font-family:'JetBrains Mono',monospace;font-size:11px;padding:14px;max-height:240px;overflow-y:auto;color:#4ade80}
.terminal .line{padding:2px 0;display:flex;gap:8px}
.terminal .ts{color:#475569;flex-shrink:0}
.terminal .st-up{color:#4ade80}.terminal .st-dn{color:#f87171}

.top-pad{padding-top:52px}
.hm{width:11px;height:11px;border-radius:3px;display:inline-block;margin:1px}

/* Scanline overlay for cyberpunk feel */
.scanlines::before{content:'';position:fixed;top:0;left:0;right:0;bottom:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.03) 2px,rgba(0,0,0,0.03) 4px);pointer-events:none;z-index:3}

/* Toast */
.toast{position:fixed;top:56px;right:16px;z-index:100;padding:14px 20px;border-radius:14px;font-size:13px;font-weight:600;animation:slideUp 0.3s ease;backdrop-filter:blur(20px)}
.toast-error{background:rgba(239,68,68,0.15);border:1px solid rgba(239,68,68,0.3);color:#fca5a5}
.toast-success{background:rgba(34,197,94,0.15);border:1px solid rgba(34,197,94,0.3);color:#86efac}
</style>
</head>
<body class="scanlines">
<video id="vbg" autoplay muted loop playsinline><source src="https://cdn.pixabay.com/video/2020/05/25/40130-424930032_large.mp4" type="video/mp4"></video>
<div id="ovl"></div>
<audio id="bgm" loop preload="auto"><source src="https://www.bensound.com/bensound-music/bensound-creativeminds.mp3" type="audio/mpeg"></audio>
<div id="root"></div>

<script type="text/babel">
const{useState:S,useEffect:E,useCallback:CB,useRef:R,createContext:CC,useContext:UC}=React;
const Ctx=CC();const useApp=()=>UC(Ctx);

// === API ===
const A={
    t:localStorage.getItem('t'),rt:localStorage.getItem('rt'),
    set(t,r){this.t=t;this.rt=r;t?localStorage.setItem('t',t):localStorage.removeItem('t');r?localStorage.setItem('rt',r):localStorage.removeItem('rt')},
    clear(){this.t=null;this.rt=null;localStorage.removeItem('t');localStorage.removeItem('rt')},
    async r(m,u,b){
        const o={method:m,headers:{'Content-Type':'application/json'}};
        if(this.t)o.headers.Authorization='Bearer '+this.t;
        if(b)o.body=JSON.stringify(b);
        let r=await fetch(u,o);
        if(r.status===401&&this.rt){
            const ref=await fetch('/api/auth/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({refresh_token:this.rt})});
            if(ref.ok){const d=await ref.json();this.t=d.access_token;localStorage.setItem('t',d.access_token);o.headers.Authorization='Bearer '+d.access_token;r=await fetch(u,o)}
            else{this.clear();location.reload();return}
        }
        if(r.status===401){this.clear();location.reload();return}
        const txt=await r.text();
        try{const d=JSON.parse(txt);if(!r.ok)throw new Error(d.detail||'Error');return d}catch(e){if(!r.ok)throw new Error('Error '+r.status);throw e}
    },
    g:u=>A.r('GET',u),p:(u,b)=>A.r('POST',u,b),u:(u,b)=>A.r('PUT',u,b),d:u=>A.r('DELETE',u)
};

// === Toast ===
let toastTimer;
function showToast(msg,type='error'){
    const el=document.getElementById('toast');if(!el)return;
    el.textContent=msg;el.className='toast toast-'+type;el.style.display='block';
    clearTimeout(toastTimer);toastTimer=setTimeout(()=>{el.style.display='none'},3000);
}

// === Icons ===
const Ic={
    Home:()=><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>,
    Mon:()=><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>,
    Bell:()=><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/></svg>,
    Shield:()=><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>,
    Gear:()=><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>,
    Plus:()=><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M5 12h14M12 5v14"/></svg>,
    X:()=><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6 6 18M6 6l12 12"/></svg>,
    Play:()=><svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21"/></svg>,
    Pause:()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect width="4" height="16" x="6" y="4"/><rect width="4" height="16" x="14" y="4"/></svg>,
    Ref:()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8M21 3v5h-5"/></svg>,
    Trash:()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 6h18M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>,
    ChevR:()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m9 18 6-6-6-6"/></svg>,
    Out:()=><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>,
    Check:()=><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>,
    Vol:()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07"/></svg>,
    Mute:()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19"/><line x1="23" x2="17" y1="9" y2="15"/><line x1="17" x2="23" y1="9" y2="15"/></svg>,
    Cpu:()=><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect width="16" height="16" x="4" y="4" rx="2"/><rect width="6" height="6" x="9" y="9"/><path d="M15 2v2M15 20v2M2 15h2M2 9h2M20 15h2M20 9h2M9 2v2M9 20v2"/></svg>,
    Lock:()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
    Ban:()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/></svg>,
    Ssl:()=><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/><path d="m9 12 2 2 4-4"/></svg>,
};

// === Music Bar ===
function Music(){
    const[p,sp]=S(false);
    const tog=()=>{const a=document.getElementById('bgm');if(a){if(p)a.pause();else{a.volume=0.2;a.play().catch(()=>{})}sp(!p)}};
    return(<div className="music glass"><div style={{display:'flex',alignItems:'center',gap:8}}>{p&&<div className="eq"><span/><span/><span/><span/><span/></div>}<span style={{fontSize:10,color:'#475569',fontWeight:600,letterSpacing:1}}>{p?'♫ PLAYING':'♫ MUSIC'}</span></div>
        <button onClick={tog} style={{width:32,height:32,borderRadius:16,background:'rgba(99,102,241,0.15)',border:'1px solid rgba(99,102,241,0.2)',color:'#a5b4fc',display:'flex',alignItems:'center',justifyContent:'center',cursor:'pointer'}}>{p?<Ic.Mute/>:<Ic.Vol/>}</button></div>);
}

// === Stat Card ===
function SC({l,v,c='indigo'}){return(<div className={`stat s-${c} anim`}><p style={{fontSize:10,color:'#64748b',textTransform:'uppercase',letterSpacing:1.5,fontWeight:700}}>{l}</p><p style={{fontSize:30,fontWeight:900,marginTop:6,fontFamily:"'JetBrains Mono',monospace",background:`linear-gradient(135deg,#f1f5f9,#94a3b8)`,WebkitBackgroundClip:'text',WebkitTextFillColor:'transparent'}}>{v}</p></div>)}

// === Chart ===
function Chart({data,h=65}){
    if(!data||!data.length)return<div style={{textAlign:'center',color:'#334155',fontSize:11,padding:24,fontFamily:"'JetBrains Mono',monospace"}}>// no data</div>;
    const mx=Math.max(...data.map(d=>d.v),1);
    return(<div style={{display:'flex',alignItems:'flex-end',gap:2,height:h}}>{data.slice(-30).map((d,i)=>(<div key={i} className="chart-bar" title={d.l+': '+d.v} style={{flex:1,height:Math.max(d.v/mx*100,3)+'%',background:d.c||'linear-gradient(180deg,#6366f1,#4f46e5)'}}/>))}</div>);
}

// === Login ===
function Login({onLogin}){
    const[u,su]=S('');const[p,sp]=S('');const[e,se]=S('');const[ld,sl]=S(false);const[reg,sr]=S(false);const[em,sem]=S('');
    const go=async ev=>{ev.preventDefault();sl(true);se('');try{
        if(reg){const d=await A.p('/api/auth/register',{username:u,password:p,email:em});A.set(d.access_token,d.refresh_token);onLogin(d.user)}
        else{const d=await A.p('/api/auth/login',{username:u,password:p});if(d.requires_2fa){se('Enter 2FA code');sl(false);return}A.set(d.access_token,d.refresh_token);onLogin(d.user)}
    }catch(x){se(x.message)}sl(false)};
    return(<div className="z2" style={{minHeight:'100vh',display:'flex',alignItems:'center',justifyContent:'center',padding:20}}>
        <div className="card glow-box border-glow anim" style={{padding:40,width:'100%',maxWidth:400}}>
            <div style={{textAlign:'center',marginBottom:36}}>
                <div className="float" style={{width:80,height:80,borderRadius:24,background:'linear-gradient(135deg,#6366f1,#8b5cf6,#06b6d4)',margin:'0 auto 20px',display:'flex',alignItems:'center',justifyContent:'center',boxShadow:'0 10px 40px rgba(99,102,241,0.4),0 0 80px rgba(99,102,241,0.1)'}}><Ic.Shield/></div>
                <h1 style={{fontSize:32,fontWeight:900}} className="neon-purple">MonitorPro</h1>
                <p style={{color:'#475569',fontSize:12,marginTop:6,letterSpacing:1,textTransform:'uppercase',fontWeight:600}}>⚡ God Level Edition</p>
            </div>
            {e&&<div style={{background:'rgba(239,68,68,0.08)',border:'1px solid rgba(239,68,68,0.15)',borderRadius:14,padding:14,marginBottom:18,color:'#fca5a5',fontSize:12,fontWeight:600}}>{e}</div>}
            <form onSubmit={go} style={{display:'flex',flexDirection:'column',gap:16}}>
                <input className="input" placeholder="Username" value={u} onChange={x=>su(x.target.value)} required/>
                {reg&&<input className="input" type="email" placeholder="Email" value={em} onChange={x=>sem(x.target.value)}/>}
                <input className="input" type="password" placeholder="Password" value={p} onChange={x=>sp(x.target.value)} required/>
                <button className="btn btn-primary" disabled={ld} style={{marginTop:8,height:52,fontSize:15}}>{ld?'⏳':'⚡'} {ld?'...':reg?'Create Account':'Sign In'}</button>
            </form>
            <p style={{textAlign:'center',color:'#475569',fontSize:12,marginTop:24}}><button onClick={()=>sr(!reg)} style={{background:'none',border:'none',color:'#818cf8',cursor:'pointer',fontWeight:700,letterSpacing:0.5}}>{reg?'← Back to Login':'Create Account →'}</button></p>
        </div>
    </div>);
}

// === Monitor Card ===
function MC({m,onClick,onPause,onCheck}){
    const dc={up:'#22c55e',down:'#ef4444',pending:'#f59e0b',paused:'#475569'};
    const bc={up:'b-up',down:'b-down',pending:'b-pending',paused:'b-paused'};
    const pc={up:'pulse-g',down:'pulse-r'};
    return(<div className="card glow-box anim" style={{padding:18,marginBottom:14,cursor:'pointer'}} onClick={()=>onClick&&onClick(m)}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
            <div style={{display:'flex',alignItems:'center',gap:12,flex:1,minWidth:0}}>
                <div className={pc[m.status]||''} style={{width:12,height:12,borderRadius:6,background:dc[m.status]||'#475569',flexShrink:0}}/>
                <div style={{minWidth:0}}><h3 style={{fontSize:14,fontWeight:700,whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{m.name}</h3>
                <p style={{fontSize:10,color:'#475569',fontFamily:"'JetBrains Mono',monospace",whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{m.url}</p></div>
            </div>
            <div style={{textAlign:'right',marginLeft:12,flexShrink:0}}>
                <p style={{fontSize:16,fontWeight:900,fontFamily:"'JetBrains Mono',monospace",color:m.uptime_percentage>=99.5?'#4ade80':m.uptime_percentage>=95?'#fbbf24':'#f87171'}}>{(m.uptime_percentage||100).toFixed(1)}%</p>
                <p style={{fontSize:10,color:'#475569',fontFamily:"'JetBrains Mono',monospace"}}>{(m.avg_response_time||0).toFixed(0)}ms</p>
            </div>
        </div>
        <div style={{display:'flex',gap:6,marginTop:14,alignItems:'center'}}>
            <button className="btn btn-ghost btn-sm" style={{flex:1}} onClick={e=>{e.stopPropagation();onPause&&onPause(m)}}>{m.is_paused?<Ic.Play/>:<Ic.Pause/>}{m.is_paused?' Resume':' Pause'}</button>
            <button className="btn btn-cyan btn-sm" style={{flex:1}} onClick={e=>{e.stopPropagation();onCheck&&onCheck(m)}}><Ic.Ref/> Check</button>
            {m.ssl_days_remaining!=null&&<span className="badge" style={{background:m.ssl_days_remaining<7?'rgba(239,68,68,0.15)':m.ssl_days_remaining<30?'rgba(245,158,11,0.15)':'rgba(34,197,94,0.15)',color:m.ssl_days_remaining<7?'#f87171':m.ssl_days_remaining<30?'#fbbf24':'#4ade80',border:'none',fontSize:9}}><Ic.Ssl/> {m.ssl_days_remaining}d</span>}
        </div>
    </div>);
}

// === Dashboard ===
function Dash(){
    const{user}=useApp();const[s,ss]=S(null);const[cd,scd]=S([]);const[ld,sl]=S(true);
    const load=CB(async()=>{try{const[a,b]=await Promise.all([A.g('/api/dashboard/stats'),A.g('/api/dashboard/charts?hours=24')]);ss(a);scd(b.chart_data||[])}catch(e){showToast(e.message)}sl(false)},[]);
    E(()=>{load();const t=setInterval(load,30000);return()=>clearInterval(t)},[load]);
    if(ld)return<div className="safe-b top-pad" style={{padding:20}}><div className="skeleton" style={{height:100,marginBottom:16}}/><div className="skeleton" style={{height:100,marginBottom:16}}/><div className="skeleton" style={{height:160}}/></div>;
    const uc=cd.map(d=>({v:d.uptime,l:d.time,c:d.uptime>=99?'#22c55e':d.uptime>=95?'#f59e0b':'#ef4444'}));
    const rc=cd.map(d=>({v:d.avg_response_time,l:d.time,c:'#6366f1'}));
    return(<div className="safe-b top-pad" style={{padding:20}}>
        <div style={{marginBottom:28}}><h1 style={{fontSize:26,fontWeight:900}} className="neon-purple">Dashboard</h1><p style={{color:'#475569',fontSize:12,marginTop:4}}>Welcome, <span style={{color:'#a5b4fc',fontWeight:700}}>{user?.username}</span> <span style={{color:'#06b6d4'}}>⚡</span></p></div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:22}}>
            <SC l="Monitors" v={s?.total_monitors||0} c="indigo"/><SC l="Online" v={s?.up||0} c="green"/>
            <SC l="Offline" v={s?.down||0} c="red"/><SC l="Uptime" v={(s?.avg_uptime||100)+'%'} c="cyan"/>
        </div>
        {s?.ssl_expiring>0&&<div className="anim card" style={{padding:14,marginBottom:14,borderColor:'rgba(245,158,11,0.3)',display:'flex',alignItems:'center',gap:10}}>
            <Ic.Ssl/><span style={{fontSize:12,color:'#fbbf24',fontWeight:600}}>⚠️ {s.ssl_expiring} SSL cert{s.ssl_expiring>1?'s':''} expiring soon</span></div>}
        <div className="card glow-box" style={{padding:18,marginBottom:14}}><h3 style={{fontSize:12,fontWeight:700,marginBottom:14,color:'#64748b',letterSpacing:1,textTransform:'uppercase'}}>📈 Uptime (24h)</h3><Chart data={uc}/></div>
        <div className="card glow-box" style={{padding:18,marginBottom:14}}><h3 style={{fontSize:12,fontWeight:700,marginBottom:14,color:'#64748b',letterSpacing:1,textTransform:'uppercase'}}>⚡ Response Time</h3><Chart data={rc} h={50}/></div>
        {s?.ongoing_incidents>0&&<div className="card anim" style={{padding:18,borderColor:'rgba(239,68,68,0.3)',display:'flex',alignItems:'center',gap:14}}>
            <div className="pulse-r" style={{width:14,height:14,borderRadius:7,background:'#ef4444',flexShrink:0}}/><div><p style={{fontWeight:800,color:'#fca5a5',fontSize:15}}>🚨 {s.ongoing_incidents} Active Incident{s.ongoing_incidents>1?'s':''}</p><p style={{fontSize:11,color:'#475569'}}>Immediate attention required</p></div></div>}
    </div>);
}

// === Monitors Page ===
function Monitors(){
    const[ms,sms]=S([]);const[ld,sl]=S(true);const[cr,scr]=S(false);const[dt,sdt]=S(null);const[f,sf]=S('all');
    const load=CB(async()=>{try{sms(await A.g('/api/monitors')||[])}catch(e){showToast(e.message)}sl(false)},[]);
    E(()=>{load()},[load]);
    const pause=async m=>{try{await A.p('/api/monitors/'+m.id+'/pause');load();showToast(m.is_paused?'Resumed':'Paused','success')}catch(e){showToast(e.message)}};
    const chk=async m=>{try{const r=await A.p('/api/monitors/'+m.id+'/check');showToast('Status: '+r.status,'success');load()}catch(e){showToast(e.message)}};
    const del=async m=>{if(!confirm('Delete '+m.name+'?'))return;try{await A.d('/api/monitors/'+m.id);sdt(null);load();showToast('Deleted','success')}catch(e){showToast(e.message)}};
    const fl=ms.filter(m=>f==='all'||f==='up'&&m.status==='up'||f==='down'&&m.status==='down'||f==='paused'&&m.is_paused);
    return(<div className="safe-b top-pad" style={{padding:20}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:18}}><h1 style={{fontSize:26,fontWeight:900}} className="neon-purple">Monitors</h1><span className="badge b-paused">{ms.length}</span></div>
        <div style={{display:'flex',gap:6,marginBottom:16,overflowX:'auto',paddingBottom:8}}>{['all','up','down','paused'].map(x=>(<button key={x} onClick={()=>sf(x)} className={'btn btn-sm '+(f===x?'btn-primary':'btn-ghost')}>{x[0].toUpperCase()+x.slice(1)}</button>))}</div>
        {ld?<div><div className="skeleton" style={{height:100,marginBottom:14}}/><div className="skeleton" style={{height:100}}/></div>:
        fl.length===0?<div style={{textAlign:'center',color:'#334155',padding:'60px 0'}}><p style={{fontSize:48}}>📡</p><p style={{marginTop:12,fontFamily:"'JetBrains Mono',monospace",fontSize:12}}>// no monitors found</p></div>:
        fl.map(m=><MC key={m.id} m={m} onClick={sdt} onPause={pause} onCheck={chk}/>)}
        <button className="fab" onClick={()=>scr(true)}><Ic.Plus/></button>
        {cr&&<CrModal onClose={()=>scr(false)} onDone={()=>{scr(false);load();showToast('Monitor created!','success')}}/>}
        {dt&&<DtModal m={dt} onClose={()=>sdt(null)} onDel={del}/>}
    </div>);
}

function CrModal({onClose,onDone}){
    const[f,sf]=S({name:'',url:'',monitor_type:'http',interval:60,timeout:30,expected_status:200,keyword:'',method:'GET',notify_telegram:false,notify_discord:false});
    const[ld,sl]=S(false);const s=(k,v)=>sf(p=>({...p,[k]:v}));
    const go=async e=>{e.preventDefault();sl(true);try{await A.p('/api/monitors',f);onDone()}catch(e){showToast(e.message)}sl(false)};
    return(<div className="modal-bg" onClick={onClose}><div className="modal anim" onClick={e=>e.stopPropagation()}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:28}}><h2 style={{fontSize:22,fontWeight:900}} className="neon-cyan">✨ New Monitor</h2><button onClick={onClose} style={{background:'none',border:'none',color:'#64748b',cursor:'pointer',padding:8}}><Ic.X/></button></div>
        <form onSubmit={go} style={{display:'flex',flexDirection:'column',gap:16}}>
            <div><label style={{fontSize:11,color:'#475569',fontWeight:700,marginBottom:8,display:'block',letterSpacing:1,textTransform:'uppercase'}}>Name</label><input className="input" value={f.name} onChange={e=>s('name',e.target.value)} placeholder="My Website" required/></div>
            <div><label style={{fontSize:11,color:'#475569',fontWeight:700,marginBottom:8,display:'block',letterSpacing:1,textTransform:'uppercase'}}>URL</label><input className="input" value={f.url} onChange={e=>s('url',e.target.value)} placeholder="https://example.com" required/></div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
                <div><label style={{fontSize:11,color:'#475569',fontWeight:700,marginBottom:8,display:'block',letterSpacing:1}}>TYPE</label><select className="input" value={f.monitor_type} onChange={e=>s('monitor_type',e.target.value)}><option value="http">HTTP</option><option value="https">HTTPS+SSL</option><option value="ping">Ping</option><option value="port">TCP Port</option><option value="keyword">Keyword</option></select></div>
                <div><label style={{fontSize:11,color:'#475569',fontWeight:700,marginBottom:8,display:'block',letterSpacing:1}}>INTERVAL</label><input className="input" type="number" value={f.interval} onChange={e=>s('interval',parseInt(e.target.value)||60)}/></div>
            </div>
            <div style={{display:'flex',gap:12}}>
                <label style={{display:'flex',alignItems:'center',gap:6,fontSize:12,color:'#94a3b8',cursor:'pointer'}}><input type="checkbox" checked={f.notify_telegram} onChange={e=>s('notify_telegram',e.target.checked)}/> 📱 Telegram</label>
                <label style={{display:'flex',alignItems:'center',gap:6,fontSize:12,color:'#94a3b8',cursor:'pointer'}}><input type="checkbox" checked={f.notify_discord} onChange={e=>s('notify_discord',e.target.checked)}/> 💬 Discord</label>
            </div>
            <button className="btn btn-primary" disabled={ld} style={{marginTop:8,height:50}}>{ld?'⏳ Creating...':'🚀 Create Monitor'}</button>
        </form>
    </div></div>);
}

function DtModal({m,onClose,onDel}){
    const[logs,slo]=S([]);const[up,sup]=S(null);const[tab,st]=S('info');
    E(()=>{A.g('/api/monitors/'+m.id+'/logs?limit=30').then(d=>slo(d||[])).catch(()=>{});A.g('/api/monitors/'+m.id+'/uptime?days=30').then(sup).catch(()=>{})},[m.id]);
    return(<div className="modal-bg" onClick={onClose}><div className="modal anim" onClick={e=>e.stopPropagation()} style={{maxHeight:'92vh'}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:18}}>
            <div style={{minWidth:0}}><h2 style={{fontSize:18,fontWeight:800}}>{m.name}</h2><p style={{fontSize:10,color:'#475569',fontFamily:"'JetBrains Mono',monospace",overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{m.url}</p></div>
            <button onClick={onClose} style={{background:'none',border:'none',color:'#64748b',cursor:'pointer',padding:8,flexShrink:0}}><Ic.X/></button>
        </div>
        <div style={{display:'flex',gap:10,alignItems:'center',marginBottom:18,flexWrap:'wrap'}}>
            <span className={'badge b-'+m.status}>{m.status}</span>
            <span style={{fontSize:12,color:'#94a3b8',fontWeight:700,fontFamily:"'JetBrains Mono',monospace"}}>{(m.uptime_percentage||100).toFixed(2)}%</span>
            <span style={{fontSize:12,color:'#64748b',fontFamily:"'JetBrains Mono',monospace"}}>{(m.avg_response_time||0).toFixed(0)}ms</span>
            {m.ssl_days_remaining!=null&&<span className="badge" style={{background:m.ssl_days_remaining<7?'rgba(239,68,68,0.1)':'rgba(34,197,94,0.1)',color:m.ssl_days_remaining<7?'#f87171':'#4ade80',border:'none'}}>🔒 SSL: {m.ssl_days_remaining}d</span>}
        </div>
        <div style={{display:'flex',gap:2,borderBottom:'1px solid rgba(148,163,184,0.06)',marginBottom:18}}>{['info','terminal','uptime'].map(t=>(<button key={t} style={{padding:'10px 16px',fontSize:12,fontWeight:700,color:tab===t?'#a5b4fc':'#475569',borderBottom:tab===t?'2px solid #6366f1':'2px solid transparent',background:'none',border:'none',cursor:'pointer',letterSpacing:0.5}} onClick={()=>st(t)}>{t==='terminal'?'📟 Logs':t==='uptime'?'📊 Uptime':'ℹ️ Info'}</button>))}</div>

        {tab==='info'&&<div style={{display:'flex',flexDirection:'column',gap:12}}>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
                {[['Type',m.monitor_type?.toUpperCase()],['Interval',m.interval+'s'],['Last Check',m.last_checked?new Date(m.last_checked).toLocaleTimeString():'Never'],['Failures',m.consecutive_failures||0],['Total Checks',m.total_checks||0],['Downtime',(m.total_downtime_seconds||0)+'s']].map(([l,v],i)=>(
                    <div key={i} style={{background:'rgba(2,6,23,0.5)',borderRadius:14,padding:14,border:'1px solid rgba(148,163,184,0.04)'}}><p style={{fontSize:9,color:'#475569',textTransform:'uppercase',letterSpacing:1.5,fontWeight:700}}>{l}</p><p style={{fontSize:14,fontWeight:800,marginTop:4,fontFamily:"'JetBrains Mono',monospace"}}>{v}</p></div>
                ))}
            </div>
            <button className="btn btn-danger" style={{marginTop:8}} onClick={()=>onDel(m)}>🗑️ Delete Monitor</button>
        </div>}

        {tab==='terminal'&&<div className="terminal">{logs.length===0?<div className="line" style={{color:'#475569'}}>// waiting for data...</div>:logs.map(l=>(
            <div key={l.id} className="line"><span className="ts">{new Date(l.created_at).toLocaleTimeString()}</span>
            <span className={l.status==='up'?'st-up':'st-dn'}>[{l.status.toUpperCase()}]</span>
            <span style={{color:'#94a3b8'}}>{l.response_time?.toFixed(0)||'-'}ms</span>
            {l.status_code&&<span style={{color:'#64748b'}}>{l.status_code}</span>}
            {l.ssl_days!=null&&<span style={{color:'#06b6d4'}}>SSL:{l.ssl_days}d</span>}
            {l.error_message&&<span style={{color:'#f87171',fontSize:10}}>{l.error_message.substring(0,50)}</span>}
            </div>))}</div>}

        {tab==='uptime'&&up&&<div>
            <div style={{textAlign:'center',marginBottom:18}}><p style={{fontSize:48,fontWeight:900,fontFamily:"'JetBrains Mono',monospace"}} className="neon-cyan">{up.uptime_percentage}%</p><p style={{fontSize:11,color:'#475569'}}>{up.days}-day uptime · {up.total_checks} checks</p></div>
            <div style={{display:'flex',flexWrap:'wrap',gap:2}}>{(up.heatmap||[]).map((d,i)=>{const c=d.uptime>=99.9?'#22c55e':d.uptime>=99?'#86efac':d.uptime>=95?'#f59e0b':d.uptime>=90?'#f97316':'#ef4444';return<div key={i} className="hm" style={{background:c}} title={d.date+': '+d.uptime+'%'}/>})}</div>
        </div>}
    </div></div>);
}

// === Incidents ===
function Incidents(){
    const[inc,si]=S([]);const[ld,sl]=S(true);const[f,sf]=S('');
    E(()=>{A.g('/api/incidents'+(f?'?status='+f:'')).then(d=>{si(d||[]);sl(false)}).catch(()=>sl(false))},[f]);
    const ack=async id=>{try{await A.p('/api/incidents/'+id+'/acknowledge');si(p=>p.map(i=>i.id===id?{...i,status:'acknowledged'}:i));showToast('Acknowledged','success')}catch{}};
    const res=async id=>{try{await A.p('/api/incidents/'+id+'/resolve',{resolution:'Resolved'});si(p=>p.map(i=>i.id===id?{...i,status:'resolved'}:i));showToast('Resolved','success')}catch{}};
    const bc={ongoing:'b-down',resolved:'b-up',acknowledged:'b-pending'};
    return(<div className="safe-b top-pad" style={{padding:20}}>
        <h1 style={{fontSize:26,fontWeight:900,marginBottom:18}} className="neon-purple">Incidents</h1>
        <div style={{display:'flex',gap:6,marginBottom:16,overflowX:'auto',paddingBottom:8}}>{['','ongoing','acknowledged','resolved'].map(x=>(<button key={x} onClick={()=>sf(x)} className={'btn btn-sm '+(f===x?'btn-primary':'btn-ghost')}>{x||'All'}</button>))}</div>
        {ld?<div className="skeleton" style={{height:80}}/>:inc.length===0?<div style={{textAlign:'center',color:'#334155',padding:'60px 0'}}><p style={{fontSize:48}}>✅</p><p style={{marginTop:12,fontFamily:"'JetBrains Mono',monospace",fontSize:12}}>// all clear</p></div>:
        inc.map(i=><div key={i.id} className="card anim" style={{padding:18,marginBottom:14}}>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:10}}>
                <div style={{flex:1}}><h3 style={{fontSize:14,fontWeight:700}}>{i.title}</h3><p style={{fontSize:10,color:'#475569',fontFamily:"'JetBrains Mono',monospace",marginTop:4}}>{new Date(i.started_at).toLocaleString()}</p></div>
                <span className={'badge '+(bc[i.status]||'')}>{i.status}</span>
            </div>
            {i.status==='ongoing'&&<div style={{display:'flex',gap:8,marginTop:12}}>
                <button className="btn btn-amber btn-sm" style={{flex:1}} onClick={()=>ack(i.id)}>⚡ Acknowledge</button>
                <button className="btn btn-success btn-sm" style={{flex:1}} onClick={()=>res(i.id)}>✅ Resolve</button>
            </div>}
        </div>)}
    </div>);
}

// === Admin ===
function Admin(){
    const{user}=useApp();const[tab,st]=S('stats');const[ss,sss]=S(null);const[us,sus]=S([]);const[al,sal]=S([]);const[se,sse]=S([]);const[ld,sl]=S(true);
    const sa=user?.role==='superadmin';
    E(()=>{Promise.all([A.g('/api/admin/system-stats').catch(()=>null),A.g('/api/admin/users').catch(()=>[]),A.g('/api/admin/audit-logs?limit=30').catch(()=>[]),A.g('/api/admin/settings').catch(()=>[])]).then(([a,b,c,d])=>{sss(a);sus(b||[]);sal(c||[]);sse(d||[]);sl(false)})},[]);

    const tog=async id=>{try{await A.p('/api/admin/users/'+id+'/toggle-active');sus(await A.g('/api/admin/users')||[]);showToast('Toggled','success')}catch(e){showToast(e.message)}};
    const ban=async id=>{const r=prompt('Ban reason:');if(!r)return;try{await A.p('/api/admin/users/'+id+'/ban',{reason:r});sus(await A.g('/api/admin/users')||[]);showToast('User banned','success')}catch(e){showToast(e.message)}};
    const unban=async id=>{try{await A.p('/api/admin/users/'+id+'/unban');sus(await A.g('/api/admin/users')||[]);showToast('Unbanned','success')}catch(e){showToast(e.message)}};
    const del=async id=>{if(!confirm('Delete user?'))return;try{await A.d('/api/admin/users/'+id);sus(p=>p.filter(u=>u.id!==id));showToast('Deleted','success')}catch(e){showToast(e.message)}};
    const imp=async id=>{try{const d=await A.p('/api/admin/impersonate/'+id);alert('Access Token:\n'+d.access_token.substring(0,40)+'...')}catch(e){showToast(e.message)}};

    if(ld)return<div className="safe-b top-pad" style={{padding:20}}><div className="skeleton" style={{height:120,marginBottom:16}}/><div className="skeleton" style={{height:120}}/></div>;

    return(<div className="safe-b top-pad" style={{padding:20}}>
        <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:18}}><Ic.Shield/><h1 style={{fontSize:26,fontWeight:900}} className="neon-purple">{sa?'Super':''}Admin</h1></div>
        <div style={{display:'flex',gap:4,marginBottom:18,overflowX:'auto',paddingBottom:8}}>{['stats','users','sessions','audit','settings','tools'].map(t=>(<button key={t} onClick={()=>st(t)} className={'btn btn-sm '+(tab===t?'btn-primary':'btn-ghost')} style={{minWidth:60}}>{t[0].toUpperCase()+t.slice(1)}</button>))}</div>

        {tab==='stats'&&ss&&<div style={{display:'flex',flexDirection:'column',gap:14}}>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
                <SC l="Users" v={ss.total_users} c="indigo"/><SC l="Monitors" v={ss.total_monitors} c="green"/>
                <SC l="Logs" v={(ss.total_logs||0).toLocaleString()} c="purple"/><SC l="Incidents" v={ss.active_incidents} c="red"/>
                <SC l="Sessions" v={ss.active_sessions} c="cyan"/><SC l="Banned" v={ss.banned_users} c="red"/>
                <SC l="DB" v={ss.database_size_mb+'MB'} c="amber"/><SC l="WS" v={ss.websocket_connections} c="indigo"/>
            </div>
            {ss.server&&<div className="card glow-box" style={{padding:18}}>
                <h3 style={{fontSize:12,fontWeight:700,marginBottom:14,color:'#64748b',display:'flex',alignItems:'center',gap:6}}><Ic.Cpu/> SERVER HEALTH</h3>
                <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:8}}>
                    <div style={{textAlign:'center'}}><p style={{fontSize:24,fontWeight:900,color:ss.server.cpu_percent>80?'#f87171':'#4ade80',fontFamily:"'JetBrains Mono',monospace"}}>{ss.server.cpu_percent}%</p><p style={{fontSize:9,color:'#475569'}}>CPU</p></div>
                    <div style={{textAlign:'center'}}><p style={{fontSize:24,fontWeight:900,color:ss.server.ram_percent>80?'#f87171':'#67e8f9',fontFamily:"'JetBrains Mono',monospace"}}>{ss.server.ram_percent}%</p><p style={{fontSize:9,color:'#475569'}}>RAM</p></div>
                    <div style={{textAlign:'center'}}><p style={{fontSize:24,fontWeight:900,color:ss.server.disk_percent>80?'#f87171':'#a5b4fc',fontFamily:"'JetBrains Mono',monospace"}}>{ss.server.disk_percent}%</p><p style={{fontSize:9,color:'#475569'}}>DISK</p></div>
                </div>
            </div>}
            <div className="card" style={{padding:18}}>
                <h3 style={{fontSize:12,fontWeight:700,marginBottom:12,color:'#64748b'}}>⚡ QUICK ACTIONS</h3>
                <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:6}}>
                    {[['🔄 Run Checks',()=>A.p('/api/admin/scheduler/trigger'),'btn-ghost'],['🧹 Clear Cache',()=>A.p('/api/admin/cache/clear'),'btn-amber'],
                      ['💾 Backup',()=>A.p('/api/admin/database/backup'),'btn-success'],['🗜️ Vacuum',()=>A.p('/api/admin/database/vacuum'),'btn-ghost'],
                      ['📋 Rotate Logs',()=>A.p('/api/admin/logs/rotate',{days:90}),'btn-danger'],['💚 Health',()=>A.g('/api/admin/health'),'btn-success'],
                      ['⏸️ Pause All',()=>A.p('/api/admin/monitors/pause-all'),'btn-amber'],['▶️ Resume All',()=>A.p('/api/admin/monitors/resume-all'),'btn-cyan']
                    ].map(([l,fn,c],i)=>(<button key={i} className={'btn btn-sm '+c} onClick={async()=>{try{const d=await fn();showToast(JSON.stringify(d).substring(0,80),'success')}catch(e){showToast(e.message)}}}>{l}</button>))}
                </div>
            </div>
        </div>}

        {tab==='users'&&<div style={{display:'flex',flexDirection:'column',gap:10}}>{us.map(u=><div key={u.id} className="card anim" style={{padding:16}}>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
                <div><div style={{display:'flex',alignItems:'center',gap:8,marginBottom:4,flexWrap:'wrap'}}>
                    <span style={{fontWeight:800,fontSize:14}}>{u.username}</span>
                    <span className={'badge '+(u.role==='superadmin'?'b-sa':u.role==='admin'?'b-admin':'b-paused')}>{u.role}</span>
                    {u.is_banned&&<span className="badge b-banned"><Ic.Ban/> BANNED</span>}
                    {u.totp_enabled&&<span className="badge" style={{background:'rgba(34,197,94,0.1)',color:'#4ade80',border:'none'}}><Ic.Lock/> 2FA</span>}
                </div><p style={{fontSize:10,color:'#475569'}}>{u.email||'–'} · IP: {u.last_ip||'–'}</p></div>
                <div style={{width:10,height:10,borderRadius:5,background:u.is_active&&!u.is_banned?'#22c55e':'#ef4444',flexShrink:0}}/>
            </div>
            {sa&&u.role!=='superadmin'&&<div style={{display:'flex',gap:4,marginTop:12,flexWrap:'wrap'}}>
                <button className="btn btn-ghost btn-sm" onClick={()=>tog(u.id)}>{u.is_active?'Disable':'Enable'}</button>
                {u.is_banned?<button className="btn btn-success btn-sm" onClick={()=>unban(u.id)}>Unban</button>:<button className="btn btn-danger btn-sm" onClick={()=>ban(u.id)}><Ic.Ban/> Ban</button>}
                <button className="btn btn-cyan btn-sm" onClick={()=>imp(u.id)}>👤 Impersonate</button>
                <button className="btn btn-danger btn-sm" onClick={()=>del(u.id)}><Ic.Trash/></button>
            </div>}
        </div>)}</div>}

        {tab==='sessions'&&<SessionsTab/>}

        {tab==='audit'&&<div className="terminal" style={{maxHeight:400}}>{al.map(l=><div key={l.id} className="line"><span className="ts">{new Date(l.created_at).toLocaleTimeString()}</span><span style={{color:'#a5b4fc'}}>[{l.action}]</span><span style={{color:'#94a3b8'}}>{l.username}</span>{l.resource_type&&<span style={{color:'#475569'}}>{l.resource_type}#{l.resource_id}</span>}</div>)}</div>}

        {tab==='settings'&&<div style={{display:'flex',flexDirection:'column',gap:6}}>{se.map(s=><div key={s.id} className="card" style={{padding:14,display:'flex',justifyContent:'space-between',alignItems:'center'}}>
            <div><p style={{fontSize:13,fontWeight:700}}>{s.key}</p><p style={{fontSize:9,color:'#334155',textTransform:'uppercase'}}>{s.category}</p></div>
            <span style={{fontSize:11,color:'#818cf8',fontFamily:"'JetBrains Mono',monospace",maxWidth:120,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{s.value||'—'}</span>
        </div>)}</div>}

        {tab==='tools'&&<div style={{display:'flex',flexDirection:'column',gap:14}}>
            <div className="card" style={{padding:18}}>
                <h3 style={{fontSize:12,fontWeight:700,marginBottom:12,color:'#64748b'}}>📊 ANALYTICS</h3>
                <div style={{display:'flex',flexDirection:'column',gap:6}}>
                    {[['📈 Uptime Heatmap','/api/admin/analytics/uptime-heatmap'],['⚡ Latency Stats','/api/admin/analytics/latency'],['🔴 Incident Stats','/api/admin/analytics/incident-stats'],['🔒 SSL Report','/api/admin/analytics/ssl-report'],['❌ Errors','/api/admin/analytics/error-breakdown']].map(([l,u],i)=>(
                        <button key={i} className="btn btn-ghost btn-sm" style={{justifyContent:'space-between'}} onClick={async()=>{try{const d=await A.g(u);alert(JSON.stringify(d,null,2))}catch(e){showToast(e.message)}}}>{l}<Ic.ChevR/></button>
                    ))}
                </div>
            </div>
            <div className="card" style={{padding:18}}>
                <h3 style={{fontSize:12,fontWeight:700,marginBottom:12,color:'#64748b'}}>📦 EXPORT</h3>
                <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:6}}>
                    <a href="/api/admin/export/monitors/json" className="btn btn-ghost btn-sm" style={{textDecoration:'none'}}>📋 Monitors JSON</a>
                    <a href="/api/admin/export/monitors/csv" className="btn btn-ghost btn-sm" style={{textDecoration:'none'}}>📊 Monitors CSV</a>
                    <a href="/api/admin/export/logs/json" className="btn btn-ghost btn-sm" style={{textDecoration:'none'}}>📋 Logs JSON</a>
                    <a href="/api/admin/export/logs/csv" className="btn btn-ghost btn-sm" style={{textDecoration:'none'}}>📊 Logs CSV</a>
                </div>
            </div>
            <div className="card" style={{padding:18}}>
                <h3 style={{fontSize:12,fontWeight:700,marginBottom:12,color:'#64748b'}}>🔔 NOTIFICATIONS</h3>
                <div style={{display:'flex',gap:6}}>
                    <button className="btn btn-cyan btn-sm" style={{flex:1}} onClick={async()=>{try{await A.p('/api/admin/test-telegram',{message:'Test!'});showToast('Telegram sent!','success')}catch(e){showToast(e.message)}}}>📱 Test Telegram</button>
                    <button className="btn btn-ghost btn-sm" style={{flex:1}} onClick={async()=>{try{await A.p('/api/admin/test-discord',{message:'Test!'});showToast('Discord sent!','success')}catch(e){showToast(e.message)}}}>💬 Test Discord</button>
                </div>
            </div>
            <button className="btn btn-ghost btn-sm" style={{width:'100%'}} onClick={async()=>{const d=await A.g('/api/admin/features');alert('Total: '+d.total+'\n\n'+d.features.map(f=>'#'+f.id+' '+f.name+' ['+f.category+']').join('\n'))}}>📋 View All {'>'}70 Features</button>
        </div>}
    </div>);
}

function SessionsTab(){
    const[ss,sss]=S([]);const[ld,sl]=S(true);
    E(()=>{A.g('/api/admin/sessions').then(d=>{sss(d||[]);sl(false)}).catch(()=>sl(false))},[]);
    const kill=async id=>{try{await A.d('/api/admin/sessions/'+id);sss(p=>p.filter(s=>s.id!==id));showToast('Session killed','success')}catch(e){showToast(e.message)}};
    if(ld)return<div className="skeleton" style={{height:80}}/>;
    return(<div style={{display:'flex',flexDirection:'column',gap:6}}>{ss.length===0?<p style={{textAlign:'center',color:'#475569',padding:20}}>No active sessions</p>:ss.map(s=>(
        <div key={s.id} className="card" style={{padding:14}}>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
                <div><p style={{fontSize:12,fontWeight:700}}>User #{s.user_id} · <span style={{color:'#06b6d4'}}>{s.device_type||'Unknown'}</span></p>
                <p style={{fontSize:10,color:'#475569',fontFamily:"'JetBrains Mono',monospace"}}>{s.ip_address||'–'} · {new Date(s.last_activity).toLocaleString()}</p></div>
                <button className="btn btn-danger btn-sm" onClick={()=>kill(s.id)}>Kill</button>
            </div>
        </div>
    ))}</div>);
}

// === Settings ===
function Settings(){
    const{user,logout}=useApp();const[p,sp]=S(null);
    E(()=>{A.g('/api/auth/me').then(sp).catch(()=>{})},[]);
    return(<div className="safe-b top-pad" style={{padding:20}}>
        <h1 style={{fontSize:26,fontWeight:900,marginBottom:18}} className="neon-purple">Settings</h1>
        {p&&<div className="card glow-box" style={{padding:22,marginBottom:18}}>
            <div style={{display:'flex',alignItems:'center',gap:16,marginBottom:18}}>
                <div style={{width:60,height:60,borderRadius:30,background:'linear-gradient(135deg,#6366f1,#06b6d4)',display:'flex',alignItems:'center',justifyContent:'center',fontSize:24,fontWeight:900,boxShadow:'0 4px 25px rgba(99,102,241,0.3)'}}>{p.username?.[0]?.toUpperCase()}</div>
                <div><h2 style={{fontWeight:900,fontSize:20}}>{p.username}</h2><p style={{fontSize:11,color:'#475569'}}>{p.email||'No email'}</p>
                <div style={{display:'flex',gap:6,marginTop:6}}>
                    <span className={'badge '+(p.role==='superadmin'?'b-sa':'b-admin')}>{p.role}</span>
                    {p.is_banned&&<span className="badge b-banned">BANNED</span>}
                    {p.totp_enabled&&<span className="badge" style={{background:'rgba(34,197,94,0.1)',color:'#4ade80',border:'none'}}>2FA ✓</span>}
                </div></div>
            </div>
        </div>}
        <div style={{display:'flex',flexDirection:'column',gap:8}}>
            {[['🔑 Regenerate API Key',async()=>{const d=await A.p('/api/auth/regenerate-api-key');alert('Key: '+d.api_key)}],
              ['🔐 Setup 2FA',async()=>{const d=await A.p('/api/auth/setup-2fa');alert('Secret: '+d.secret+'\nURI: '+d.uri)}]
            ].map(([l,fn],i)=>(<button key={i} className="card" style={{padding:16,display:'flex',justifyContent:'space-between',alignItems:'center',border:'none',cursor:'pointer',textAlign:'left',color:'#e2e8f0'}} onClick={async()=>{try{await fn();showToast('Done!','success')}catch(e){showToast(e.message)}}}><span style={{fontSize:14,fontWeight:700}}>{l}</span><Ic.ChevR/></button>))}
            <button className="card" style={{padding:16,display:'flex',justifyContent:'space-between',alignItems:'center',border:'none',cursor:'pointer',textAlign:'left',color:'#fca5a5'}} onClick={logout}><span style={{fontSize:14,fontWeight:700,display:'flex',alignItems:'center',gap:8}}><Ic.Out/>Logout</span><Ic.ChevR/></button>
        </div>
    </div>);
}

// === Bottom Nav ===
function Nav({active,onChange,isAdmin}){
    const items=[{id:'dash',l:'Home',i:Ic.Home},{id:'monitors',l:'Monitors',i:Ic.Mon},{id:'incidents',l:'Alerts',i:Ic.Bell},...(isAdmin?[{id:'admin',l:'Admin',i:Ic.Shield}]:[]),{id:'settings',l:'Settings',i:Ic.Gear}];
    return(<div className="bnav glass"><div style={{display:'flex',justifyContent:'space-around',alignItems:'center',height:'100%',maxWidth:500,margin:'0 auto'}}>
        {items.map(it=>{const Icon=it.i;const a=active===it.id;return(<button key={it.id} onClick={()=>onChange(it.id)} style={{display:'flex',flexDirection:'column',alignItems:'center',gap:4,padding:'8px 12px',background:'none',border:'none',cursor:'pointer',color:a?'#a5b4fc':'#334155',transition:'all 0.3s',transform:a?'scale(1.1)':'scale(1)'}}>
            <Icon/><span style={{fontSize:9,fontWeight:a?800:500,letterSpacing:0.5}}>{it.l}</span>{a&&<div style={{width:4,height:4,borderRadius:2,background:'linear-gradient(135deg,#6366f1,#06b6d4)'}}/>}
        </button>)})}
    </div></div>);
}

// === App ===
function App(){
    const[user,setUser]=S(null);const[page,setPage]=S('dash');const[ld,sl]=S(true);
    E(()=>{if(A.t){A.g('/api/auth/me').then(u=>{setUser(u);sl(false)}).catch(()=>{A.clear();sl(false)})}else sl(false)},[]);
    E(()=>{if(!user)return;try{const p=location.protocol==='https:'?'wss':'ws';const w=new WebSocket(p+'://'+location.host+'/ws?token='+A.t);w.onopen=()=>console.log('⚡ WS connected');const t=setInterval(()=>{if(w.readyState===1)w.send('{"type":"ping"}')},30000);return()=>{clearInterval(t);w.close()}}catch{}},[user]);
    const logout=()=>{A.p('/api/auth/logout').catch(()=>{});A.clear();setUser(null);setPage('dash');document.getElementById('bgm')?.pause()};
    const isAdmin=user?.role==='admin'||user?.role==='superadmin';
    if(ld)return<div className="z2" style={{minHeight:'100vh',display:'flex',alignItems:'center',justifyContent:'center'}}><div className="skeleton float" style={{width:64,height:64,borderRadius:20}}/></div>;
    if(!user)return<><Music/><Login onLogin={setUser}/></>;
    return(<Ctx.Provider value={{user,setUser,logout}}><div className="z2" style={{minHeight:'100vh'}}>
        <Music/><div id="toast" style={{display:'none'}}/>
        {page==='dash'&&<Dash/>}{page==='monitors'&&<Monitors/>}{page==='incidents'&&<Incidents/>}{page==='admin'&&isAdmin&&<Admin/>}{page==='settings'&&<Settings/>}
        <Nav active={page} onChange={setPage} isAdmin={isAdmin}/>
    </div></Ctx.Provider>);
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
</script>
</body>
</html>"""

# =============================================================================
# SECTION 26: SERVE FRONTEND
# =============================================================================
@app.get("/", response_class=HTMLResponse)
async def serve():
    return HTMLResponse(FRONTEND)

@app.get("/app", response_class=HTMLResponse)
async def serve_app():
    return HTMLResponse(FRONTEND)

# =============================================================================
# SECTION 27: MAIN ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    db_display = C.DB_URL[:50] + "..." if len(C.DB_URL) > 50 else C.DB_URL
    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║         ⚡ MonitorPro GOD LEVEL v4.0 ⚡                          ║
╠══════════════════════════════════════════════════════════════════╣
║  🌐 URL:        http://localhost:{port}                             ║
║  🔑 SuperAdmin: {C.SUPERADMIN_USER} / {C.SUPERADMIN_PASS}                       ║
║  📚 API Docs:   http://localhost:{port}/docs                        ║
║  💾 Database:   {db_display:<48} ║
║  🚀 Features:   70+ Admin | SSL Track | Telegram | Discord      ║
║  🎨 Frontend:   Cyberpunk Glassmorphism Mobile-First             ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    uvicorn.run(app, host=C.HOST, port=port, log_level="info", access_log=True)