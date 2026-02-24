#!/usr/bin/env python3
"""
=============================================================================
MONITORPRO SAAS PLATFORM v3.0 - PREMIUM EDITION
=============================================================================
Beautiful Mobile-First UI with Video Background, Music Player,
70+ Admin Features, Real-time WebSocket, JWT Auth, 2FA

Default SuperAdmin: RUHIVIGQNR / RUHIVIGQNR
=============================================================================
"""

import os
import sys
import json
import time
import uuid
import hashlib
import secrets
import asyncio
import logging
import sqlite3
import subprocess
import re
import threading
import traceback
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from enum import Enum
from collections import defaultdict
from io import BytesIO
from pathlib import Path
from contextlib import asynccontextmanager
import socket

def install_deps():
    deps = [
        "fastapi", "uvicorn", "sqlalchemy", "python-jose",
        "python-multipart", "httpx", "pyotp",
        "apscheduler", "pydantic", "psycopg2-binary", "bcrypt"
    ]
    for dep in deps:
        try:
            __import__(dep.replace("-", "_"))
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep, "-q"])

install_deps()

from fastapi import (
    FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect,
    Request, Query, Body
)
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean, DateTime,
    Text, ForeignKey, JSON as SA_JSON, func, text as sa_text
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.pool import StaticPool
from jose import JWTError, jwt
from pydantic import BaseModel
import pyotp
import httpx
import bcrypt as bcrypt_lib
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

# ============================================================================
# CONFIG
# ============================================================================
class Config:
    APP_NAME = "MonitorPro SaaS"
    APP_VERSION = "3.0.0"
    SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_hex(32))
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRY_HOURS = 24
    _raw = os.environ.get("DATABASE_URL", "")
    if _raw:
        DATABASE_URL = _raw.replace("postgres://", "postgresql://", 1) if _raw.startswith("postgres://") else _raw
    else:
        DATABASE_URL = "sqlite:///./monitoring.db"
    SUPERADMIN_USERNAME = "RUHIVIGQNR"
    SUPERADMIN_PASSWORD = "RUHIVIGQNR"
    HOST = "0.0.0.0"
    PORT = int(os.environ.get("PORT", 8000))
    MAX_MONITORS = 50
    MAX_LOGIN_ATTEMPTS = 5

config = Config()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("MonitorPro")

if config.DATABASE_URL.startswith("sqlite"):
    engine = create_engine(config.DATABASE_URL, connect_args={"check_same_thread": False}, poolclass=StaticPool, echo=False)
else:
    engine = create_engine(config.DATABASE_URL, echo=False, pool_pre_ping=True, pool_size=5, max_overflow=10)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def hash_password(password: str) -> str:
    pwd = password.encode("utf-8")
    if len(pwd) > 72:
        pwd = hashlib.sha256(pwd).hexdigest().encode("utf-8")
    return bcrypt_lib.hashpw(pwd, bcrypt_lib.gensalt(rounds=12)).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    try:
        pwd = plain.encode("utf-8")
        if len(pwd) > 72:
            pwd = hashlib.sha256(pwd).hexdigest().encode("utf-8")
        return bcrypt_lib.checkpw(pwd, hashed.encode("utf-8"))
    except:
        return False

class SimpleCache:
    def __init__(self):
        self._c, self._e, self._l = {}, {}, threading.Lock()
    def get(self, k):
        with self._l:
            if k in self._c and time.time() < self._e.get(k, 0): return self._c[k]
            self._c.pop(k, None); self._e.pop(k, None); return None
    def set(self, k, v, t=300):
        with self._l: self._c[k] = v; self._e[k] = time.time() + t
    def clear(self):
        with self._l: self._c.clear(); self._e.clear()
    def size(self):
        with self._l: return sum(1 for k in self._e if time.time() < self._e[k])
    def keys(self):
        with self._l: return [k for k in self._e if time.time() < self._e[k]]

cache = SimpleCache()

# ============================================================================
# MODELS
# ============================================================================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    uid = Column(String(36), unique=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="user", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
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
    follow_redirects = Column(Boolean, default=True)
    regex_pattern = Column(String(500), nullable=True)
    alert_threshold = Column(Integer, default=1)
    consecutive_failures = Column(Integer, default=0, nullable=False)
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
    session_token = Column(String(64), unique=True, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
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
    theme = Column(String(20), default="light")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class MaintenanceWindow(Base):
    __tablename__ = "maintenance_windows"
    id = Column(Integer, primary_key=True, autoincrement=True)
    uid = Column(String(36), unique=True, nullable=False)
    monitor_id = Column(Integer, ForeignKey("monitors.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class IPWhitelist(Base):
    __tablename__ = "ip_whitelist"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String(45), nullable=False)
    description = Column(String(200), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by = Column(Integer, nullable=True)

try:
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables OK")
except Exception as e:
    logger.error(f"Table creation error: {e}")
    try:
        Base.metadata.drop_all(bind=engine)
        Base.metadata.create_all(bind=engine)
        logger.info("Tables recreated")
    except Exception as e2:
        logger.error(f"Fatal DB error: {e2}")

# ============================================================================
# SCHEMAS
# ============================================================================
class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None

class RegisterRequest(BaseModel):
    username: str
    email: Optional[str] = None
    password: str

class MonitorCreate(BaseModel):
    name: str; url: str; monitor_type: str = "http"; interval: int = 60
    timeout: int = 30; method: str = "GET"; expected_status: int = 200
    keyword: Optional[str] = None; port: Optional[int] = None
    tags: list = []; regex_pattern: Optional[str] = None

class MonitorUpdate(BaseModel):
    name: Optional[str] = None; url: Optional[str] = None
    interval: Optional[int] = None; is_paused: Optional[bool] = None
    expected_status: Optional[int] = None; keyword: Optional[str] = None
    tags: Optional[list] = None

class UserUpdate(BaseModel):
    email: Optional[str] = None; role: Optional[str] = None
    is_active: Optional[bool] = None; theme: Optional[str] = None

class SiteSettingUpdate(BaseModel):
    value: str; category: Optional[str] = None

class StatusPageCreate(BaseModel):
    title: str; slug: str; description: Optional[str] = None
    monitor_ids: list = []; is_public: bool = True

class AlertChannelCreate(BaseModel):
    name: str; channel_type: str; config: dict = {}; is_default: bool = False

class MaintenanceCreate(BaseModel):
    monitor_id: int; title: str; description: Optional[str] = None
    start_time: str; end_time: str

# ============================================================================
# AUTH
# ============================================================================
def create_jwt(uid, uname, role):
    return jwt.encode({"user_id": uid, "username": uname, "role": role, "exp": datetime.utcnow() + timedelta(hours=config.JWT_EXPIRY_HOURS)}, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)

def verify_jwt(token):
    try: return jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
    except: return None

security = HTTPBearer(auto_error=False)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

async def get_current_user(request: Request, cred: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    t = cred.credentials if cred else None
    if not t:
        ah = request.headers.get("Authorization", "")
        if ah.startswith("Bearer "): t = ah[7:]
    if not t: t = request.query_params.get("token")
    if not t: raise HTTPException(401, "Not authenticated")
    p = verify_jwt(t)
    if not p: raise HTTPException(401, "Invalid token")
    return p

async def require_admin(user=Depends(get_current_user)):
    if user["role"] not in ["admin", "superadmin"]: raise HTTPException(403, "Admin required")
    return user

async def require_superadmin(user=Depends(get_current_user)):
    if user["role"] != "superadmin": raise HTTPException(403, "Superadmin required")
    return user

def log_audit(db, uid, uname, action, rtype=None, rid=None, details=None, ip=None):
    try:
        db.add(AuditLog(user_id=uid, username=uname, action=action, resource_type=rtype, resource_id=rid, details=details or {}, ip_address=ip))
        db.commit()
    except: db.rollback()

# ============================================================================
# WEBSOCKET
# ============================================================================
class WSManager:
    def __init__(self):
        self.conns: Dict[int, List[WebSocket]] = defaultdict(list)
        self.all: List[WebSocket] = []
    async def connect(self, ws, uid=0):
        await ws.accept()
        if uid: self.conns[uid].append(ws)
        self.all.append(ws)
    def disconnect(self, ws, uid=0):
        if uid and ws in self.conns[uid]: self.conns[uid].remove(ws)
        if ws in self.all: self.all.remove(ws)
    async def send_user(self, uid, msg):
        for c in self.conns.get(uid, []):
            try: await c.send_json(msg)
            except: pass
    async def broadcast(self, msg):
        dead = []
        for c in self.all:
            try: await c.send_json(msg)
            except: dead.append(c)
        for c in dead:
            if c in self.all: self.all.remove(c)

ws = WSManager()

# ============================================================================
# MONITOR CHECKER
# ============================================================================
class Checker:
    def __init__(self): self.client = None
    async def get_client(self):
        if not self.client: self.client = httpx.AsyncClient(timeout=30, follow_redirects=True, verify=False)
        return self.client
    async def check(self, m):
        start = time.time()
        r = {"status": "down", "response_time": 0, "status_code": None, "error_message": None}
        try:
            if m.monitor_type in ["http", "https", "keyword"]:
                c = await self.get_client()
                resp = await c.request(method=m.method or "GET", url=m.url, headers=m.headers or {}, content=m.body, timeout=m.timeout or 30)
                r["response_time"] = round((time.time() - start) * 1000, 2)
                r["status_code"] = resp.status_code
                ok = resp.status_code == (m.expected_status or 200)
                if m.keyword and m.monitor_type == "keyword":
                    body = resp.text[:5000]
                    ok = ok and (m.keyword in body if m.keyword_type == "contains" else m.keyword not in body)
                if m.regex_pattern:
                    try: ok = ok and bool(re.search(m.regex_pattern, resp.text[:5000]))
                    except: pass
                r["status"] = "up" if ok else "down"
            elif m.monitor_type in ["port", "tcp"]:
                from urllib.parse import urlparse
                h = urlparse(m.url).hostname or m.url
                p = m.port or urlparse(m.url).port or 80
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(m.timeout or 10)
                await asyncio.get_event_loop().run_in_executor(None, s.connect, (h, p))
                s.close()
                r["response_time"] = round((time.time() - start) * 1000, 2)
                r["status"] = "up"
            elif m.monitor_type == "ping":
                from urllib.parse import urlparse
                h = urlparse(m.url).hostname or m.url
                cmd = ["ping", "-c", "1", "-W", str(m.timeout or 10), h] if sys.platform != "win32" else ["ping", "-n", "1", "-w", str((m.timeout or 10)*1000), h]
                proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                await asyncio.wait_for(proc.communicate(), timeout=m.timeout or 15)
                r["response_time"] = round((time.time() - start) * 1000, 2)
                r["status"] = "up" if proc.returncode == 0 else "down"
            else:
                return await self.check(type('M', (), {**{k: getattr(m, k) for k in dir(m) if not k.startswith('_')}, 'monitor_type': 'http'})())
        except Exception as e:
            r["response_time"] = round((time.time() - start) * 1000, 2)
            r["error_message"] = str(e)[:500]
        return r

checker = Checker()
scheduler = AsyncIOScheduler()

async def run_checks():
    db = SessionLocal()
    try:
        for m in db.query(Monitor).filter(Monitor.is_paused == False, Monitor.maintenance_mode == False).all():
            try:
                r = await checker.check(m)
                db.add(MonitorLog(monitor_id=m.id, status=r["status"], response_time=r.get("response_time"), status_code=r.get("status_code"), error_message=r.get("error_message")))
                old = m.status; m.status = r["status"]; m.last_checked = datetime.utcnow(); m.avg_response_time = r.get("response_time", 0)
                m.consecutive_failures = (m.consecutive_failures or 0) + 1 if r["status"] == "down" else 0
                if old != r["status"]:
                    m.last_status_change = datetime.utcnow()
                    if r["status"] == "down":
                        db.add(Incident(uid=str(uuid.uuid4()), monitor_id=m.id, title=f"{m.name} is DOWN", description=r.get("error_message", "Not responding"), status="ongoing", severity="high"))
                    elif r["status"] == "up":
                        for inc in db.query(Incident).filter(Incident.monitor_id == m.id, Incident.status == "ongoing").all():
                            inc.status = "resolved"; inc.resolved_at = datetime.utcnow()
                            if inc.started_at: inc.duration_seconds = int((datetime.utcnow() - inc.started_at).total_seconds())
                tot = db.query(MonitorLog).filter(MonitorLog.monitor_id == m.id).count()
                up = db.query(MonitorLog).filter(MonitorLog.monitor_id == m.id, MonitorLog.status == "up").count()
                if tot > 0: m.uptime_percentage = round((up / tot) * 100, 2)
                db.commit()
                try: await ws.send_user(m.user_id, {"type": "monitor_update", "monitor_id": m.id, "status": r["status"], "response_time": r.get("response_time")})
                except: pass
            except Exception as e:
                logger.error(f"Check error {m.id}: {e}"); db.rollback()
    except Exception as e: logger.error(f"Check cycle error: {e}")
    finally: db.close()

async def cleanup_logs():
    db = SessionLocal()
    try:
        db.query(MonitorLog).filter(MonitorLog.created_at < datetime.utcnow() - timedelta(days=90)).delete()
        db.commit()
    except: db.rollback()
    finally: db.close()

def init_superadmin():
    db = SessionLocal()
    try:
        if not db.query(User).filter(User.username == config.SUPERADMIN_USERNAME).first():
            db.add(User(uid=str(uuid.uuid4()), username=config.SUPERADMIN_USERNAME, email="superadmin@monitorpro.local",
                password_hash=hash_password(config.SUPERADMIN_PASSWORD), role="superadmin", is_active=True, is_verified=True,
                totp_enabled=False, login_attempts=0, api_key=secrets.token_hex(32), created_at=datetime.utcnow(), updated_at=datetime.utcnow()))
            db.flush(); logger.info("Superadmin created")
        for k, (v, c) in {"site_name": ("MonitorPro SaaS", "general"), "maintenance_mode": ("false", "general"),
            "registration_enabled": ("true", "general"), "theme_primary_color": ("#6366f1", "theme"),
            "particle_effects": ("true", "theme"), "particle_count": ("50", "theme"),
            "two_factor_required": ("false", "security"), "custom_css": ("", "theme"),
            "bg_video_url": ("https://cdn.pixabay.com/video/2020/05/25/40130-424930032_large.mp4", "theme"),
            "bg_music_url": ("https://www.bensound.com/bensound-music/bensound-creativeminds.mp3", "theme")}.items():
            if not db.query(SiteSetting).filter(SiteSetting.key == k).first():
                db.add(SiteSetting(key=k, value=v, category=c, updated_at=datetime.utcnow()))
        db.commit()
    except Exception as e: logger.error(f"Init error: {e}"); db.rollback()
    finally: db.close()

# ============================================================================
# APP
# ============================================================================
app_start_time = time.time()

@asynccontextmanager
async def lifespan(app):
    init_superadmin()
    scheduler.add_job(run_checks, IntervalTrigger(seconds=60), id="checks", replace_existing=True)
    scheduler.add_job(cleanup_logs, IntervalTrigger(hours=24), id="cleanup", replace_existing=True)
    scheduler.start(); logger.info("MonitorPro v3.0 Started")
    yield
    scheduler.shutdown()
    if checker.client: await checker.client.aclose()

app = FastAPI(title="MonitorPro", version="3.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ============================================================================
# AUTH ROUTES
# ============================================================================
@app.post("/api/auth/login")
async def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    try:
        u = db.query(User).filter(User.username == req.username).first()
        if not u: raise HTTPException(400, "Invalid credentials")
        if u.locked_until and u.locked_until > datetime.utcnow(): raise HTTPException(423, "Account locked")
        if not verify_password(req.password, u.password_hash):
            u.login_attempts = (u.login_attempts or 0) + 1
            if u.login_attempts >= config.MAX_LOGIN_ATTEMPTS: u.locked_until = datetime.utcnow() + timedelta(minutes=30)
            db.commit(); raise HTTPException(400, "Invalid credentials")
        if u.totp_enabled:
            if not req.totp_code: return JSONResponse({"requires_2fa": True})
            if not pyotp.TOTP(u.totp_secret).verify(req.totp_code, valid_window=1): raise HTTPException(400, "Invalid 2FA")
        if not u.is_active: raise HTTPException(403, "Disabled")
        u.login_attempts = 0; u.locked_until = None; u.last_login = datetime.utcnow(); u.last_ip = request.client.host if request.client else None
        db.add(UserSession(user_id=u.id, session_token=secrets.token_hex(32), ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent", "")[:500], expires_at=datetime.utcnow() + timedelta(hours=24), last_activity=datetime.utcnow()))
        log_audit(db, u.id, u.username, "login", ip=request.client.host if request.client else None); db.commit()
        return JSONResponse({"token": create_jwt(u.id, u.username, u.role), "user": {"id": u.id, "uid": u.uid, "username": u.username, "email": u.email, "role": u.role, "theme": u.theme, "totp_enabled": u.totp_enabled}})
    except HTTPException: raise
    except Exception as e: logger.error(f"Login: {e}"); raise HTTPException(500, str(e))

@app.post("/api/auth/register")
async def register(req: RegisterRequest, db: Session = Depends(get_db)):
    try:
        s = db.query(SiteSetting).filter(SiteSetting.key == "registration_enabled").first()
        if s and s.value == "false": raise HTTPException(403, "Registration disabled")
        if db.query(User).filter(User.username == req.username).first(): raise HTTPException(400, "Username taken")
        if req.email and db.query(User).filter(User.email == req.email).first(): raise HTTPException(400, "Email taken")
        u = User(uid=str(uuid.uuid4()), username=req.username, email=req.email, password_hash=hash_password(req.password),
            role="user", is_active=True, totp_enabled=False, login_attempts=0, api_key=secrets.token_hex(32), created_at=datetime.utcnow(), updated_at=datetime.utcnow())
        db.add(u); db.commit(); db.refresh(u)
        return JSONResponse({"token": create_jwt(u.id, u.username, u.role), "user": {"id": u.id, "username": u.username, "role": u.role}})
    except HTTPException: raise
    except Exception as e: db.rollback(); raise HTTPException(500, str(e))

@app.get("/api/auth/me")
async def me(user=Depends(get_current_user), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user["user_id"]).first()
    if not u: raise HTTPException(404)
    return JSONResponse({"id": u.id, "uid": u.uid, "username": u.username, "email": u.email, "role": u.role,
        "is_active": u.is_active, "totp_enabled": u.totp_enabled, "theme": u.theme, "timezone": u.timezone,
        "api_key": u.api_key, "created_at": str(u.created_at), "last_login": str(u.last_login) if u.last_login else None})

@app.post("/api/auth/setup-2fa")
async def setup_2fa(user=Depends(get_current_user), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user["user_id"]).first()
    s = pyotp.random_base32(); u.totp_secret = s; db.commit()
    return JSONResponse({"secret": s, "uri": pyotp.TOTP(s).provisioning_uri(name=u.username, issuer_name="MonitorPro")})

@app.post("/api/auth/enable-2fa")
async def enable_2fa(code: str = Body(..., embed=True), user=Depends(get_current_user), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user["user_id"]).first()
    if not u.totp_secret: raise HTTPException(400, "Setup first")
    if not pyotp.TOTP(u.totp_secret).verify(code, valid_window=1): raise HTTPException(400, "Invalid")
    u.totp_enabled = True; db.commit()
    return JSONResponse({"message": "2FA enabled"})

@app.post("/api/auth/change-password")
async def change_pw(current_password: str = Body(...), new_password: str = Body(...), user=Depends(get_current_user), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user["user_id"]).first()
    if not verify_password(current_password, u.password_hash): raise HTTPException(400, "Wrong password")
    u.password_hash = hash_password(new_password); db.commit()
    return JSONResponse({"message": "Changed"})

@app.post("/api/auth/regenerate-api-key")
async def regen_key(user=Depends(get_current_user), db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user["user_id"]).first()
    u.api_key = secrets.token_hex(32); db.commit()
    return JSONResponse({"api_key": u.api_key})

# ============================================================================
# MONITOR ROUTES
# ============================================================================
@app.get("/api/monitors")
async def list_monitors(user=Depends(get_current_user), db: Session = Depends(get_db)):
    ms = db.query(Monitor).all() if user["role"] == "superadmin" else db.query(Monitor).filter(Monitor.user_id == user["user_id"]).all()
    return JSONResponse([{"id": m.id, "uid": m.uid, "name": m.name, "url": m.url, "monitor_type": m.monitor_type, "status": m.status,
        "interval": m.interval, "uptime_percentage": m.uptime_percentage, "avg_response_time": m.avg_response_time,
        "last_checked": str(m.last_checked) if m.last_checked else None, "is_paused": m.is_paused, "tags": m.tags or [],
        "consecutive_failures": m.consecutive_failures, "created_at": str(m.created_at), "user_id": m.user_id} for m in ms])

@app.post("/api/monitors")
async def create_monitor(data: MonitorCreate, user=Depends(get_current_user), db: Session = Depends(get_db)):
    if db.query(Monitor).filter(Monitor.user_id == user["user_id"]).count() >= config.MAX_MONITORS and user["role"] != "superadmin":
        raise HTTPException(400, "Limit reached")
    m = Monitor(uid=str(uuid.uuid4()), user_id=user["user_id"], name=data.name, url=data.url, monitor_type=data.monitor_type,
        interval=data.interval, timeout=data.timeout, method=data.method, expected_status=data.expected_status,
        keyword=data.keyword, port=data.port, tags=data.tags or [], regex_pattern=data.regex_pattern,
        uptime_percentage=100.0, avg_response_time=0.0, consecutive_failures=0, created_at=datetime.utcnow(), updated_at=datetime.utcnow())
    db.add(m); db.commit(); db.refresh(m)
    log_audit(db, user["user_id"], user["username"], "create_monitor", "monitor", str(m.id))
    return JSONResponse({"id": m.id, "uid": m.uid, "message": "Created"})

@app.get("/api/monitors/{mid}")
async def get_monitor(mid: int, user=Depends(get_current_user), db: Session = Depends(get_db)):
    m = db.query(Monitor).filter(Monitor.id == mid).first()
    if not m: raise HTTPException(404)
    if m.user_id != user["user_id"] and user["role"] != "superadmin": raise HTTPException(403)
    return JSONResponse({"id": m.id, "uid": m.uid, "name": m.name, "url": m.url, "monitor_type": m.monitor_type, "status": m.status,
        "interval": m.interval, "timeout": m.timeout, "method": m.method, "expected_status": m.expected_status, "keyword": m.keyword,
        "port": m.port, "uptime_percentage": m.uptime_percentage, "avg_response_time": m.avg_response_time,
        "last_checked": str(m.last_checked) if m.last_checked else None, "is_paused": m.is_paused, "tags": m.tags or [],
        "regex_pattern": m.regex_pattern, "alert_threshold": m.alert_threshold, "consecutive_failures": m.consecutive_failures, "created_at": str(m.created_at)})

@app.put("/api/monitors/{mid}")
async def update_monitor(mid: int, data: MonitorUpdate, user=Depends(get_current_user), db: Session = Depends(get_db)):
    m = db.query(Monitor).filter(Monitor.id == mid).first()
    if not m: raise HTTPException(404)
    if m.user_id != user["user_id"] and user["role"] != "superadmin": raise HTTPException(403)
    for k, v in data.dict(exclude_unset=True).items(): setattr(m, k, v)
    db.commit()
    return JSONResponse({"message": "Updated"})

@app.delete("/api/monitors/{mid}")
async def delete_monitor(mid: int, user=Depends(get_current_user), db: Session = Depends(get_db)):
    m = db.query(Monitor).filter(Monitor.id == mid).first()
    if not m: raise HTTPException(404)
    if m.user_id != user["user_id"] and user["role"] != "superadmin": raise HTTPException(403)
    db.delete(m); db.commit()
    return JSONResponse({"message": "Deleted"})

@app.post("/api/monitors/{mid}/pause")
async def pause_monitor(mid: int, user=Depends(get_current_user), db: Session = Depends(get_db)):
    m = db.query(Monitor).filter(Monitor.id == mid).first()
    if not m: raise HTTPException(404)
    if m.user_id != user["user_id"] and user["role"] != "superadmin": raise HTTPException(403)
    m.is_paused = not m.is_paused; m.status = "paused" if m.is_paused else "pending"; db.commit()
    return JSONResponse({"is_paused": m.is_paused})

@app.post("/api/monitors/{mid}/check")
async def check_now(mid: int, user=Depends(get_current_user), db: Session = Depends(get_db)):
    m = db.query(Monitor).filter(Monitor.id == mid).first()
    if not m: raise HTTPException(404)
    if m.user_id != user["user_id"] and user["role"] != "superadmin": raise HTTPException(403)
    r = await checker.check(m)
    db.add(MonitorLog(monitor_id=m.id, status=r["status"], response_time=r.get("response_time"), status_code=r.get("status_code"), error_message=r.get("error_message")))
    m.status = r["status"]; m.last_checked = datetime.utcnow(); m.avg_response_time = r.get("response_time", 0); db.commit()
    return JSONResponse(r)

@app.get("/api/monitors/{mid}/logs")
async def monitor_logs(mid: int, limit: int = 100, user=Depends(get_current_user), db: Session = Depends(get_db)):
    m = db.query(Monitor).filter(Monitor.id == mid).first()
    if not m: raise HTTPException(404)
    if m.user_id != user["user_id"] and user["role"] != "superadmin": raise HTTPException(403)
    logs = db.query(MonitorLog).filter(MonitorLog.monitor_id == mid).order_by(MonitorLog.created_at.desc()).limit(limit).all()
    return JSONResponse([{"id": l.id, "status": l.status, "response_time": l.response_time, "status_code": l.status_code, "error_message": l.error_message, "created_at": str(l.created_at)} for l in logs])

@app.get("/api/monitors/{mid}/uptime")
async def monitor_uptime(mid: int, days: int = 30, user=Depends(get_current_user), db: Session = Depends(get_db)):
    m = db.query(Monitor).filter(Monitor.id == mid).first()
    if not m: raise HTTPException(404)
    logs = db.query(MonitorLog).filter(MonitorLog.monitor_id == mid, MonitorLog.created_at >= datetime.utcnow() - timedelta(days=days)).all()
    total = len(logs); up = sum(1 for l in logs if l.status == "up")
    daily = {}
    for l in logs:
        d = l.created_at.strftime("%Y-%m-%d")
        if d not in daily: daily[d] = {"up": 0, "total": 0, "rt": []}
        daily[d]["total"] += 1
        if l.status == "up": daily[d]["up"] += 1
        if l.response_time: daily[d]["rt"].append(l.response_time)
    heatmap = [{"date": d, "uptime": round(s["up"]/s["total"]*100, 2) if s["total"] else 100,
        "avg_response_time": round(sum(s["rt"])/len(s["rt"]), 2) if s["rt"] else 0} for d, s in sorted(daily.items())]
    return JSONResponse({"uptime_percentage": round(up/total*100, 2) if total else 100, "total_checks": total, "days": days, "heatmap": heatmap})

# ============================================================================
# INCIDENTS, ALERTS, STATUS PAGES, DASHBOARD
# ============================================================================
@app.get("/api/incidents")
async def list_incidents(status: Optional[str] = None, user=Depends(get_current_user), db: Session = Depends(get_db)):
    q = db.query(Incident).join(Monitor)
    if user["role"] != "superadmin": q = q.filter(Monitor.user_id == user["user_id"])
    if status: q = q.filter(Incident.status == status)
    return JSONResponse([{"id": i.id, "uid": i.uid, "monitor_id": i.monitor_id, "title": i.title, "description": i.description,
        "status": i.status, "severity": i.severity, "started_at": str(i.started_at),
        "resolved_at": str(i.resolved_at) if i.resolved_at else None, "duration_seconds": i.duration_seconds, "created_at": str(i.created_at)} for i in q.order_by(Incident.created_at.desc()).limit(100).all()])

@app.post("/api/incidents/{iid}/acknowledge")
async def ack_incident(iid: int, user=Depends(get_current_user), db: Session = Depends(get_db)):
    i = db.query(Incident).filter(Incident.id == iid).first()
    if not i: raise HTTPException(404)
    i.status = "acknowledged"; i.acknowledged_at = datetime.utcnow(); i.acknowledged_by = user["user_id"]; db.commit()
    return JSONResponse({"message": "Acknowledged"})

@app.post("/api/incidents/{iid}/resolve")
async def resolve_incident(iid: int, resolution: str = Body("", embed=True), user=Depends(get_current_user), db: Session = Depends(get_db)):
    i = db.query(Incident).filter(Incident.id == iid).first()
    if not i: raise HTTPException(404)
    i.status = "resolved"; i.resolved_at = datetime.utcnow(); i.resolution = resolution
    if i.started_at: i.duration_seconds = int((datetime.utcnow() - i.started_at).total_seconds())
    db.commit()
    return JSONResponse({"message": "Resolved"})

@app.get("/api/alerts")
async def list_alerts(user=Depends(get_current_user), db: Session = Depends(get_db)):
    return JSONResponse([{"id": a.id, "uid": a.uid, "name": a.name, "channel_type": a.channel_type, "config": a.config or {},
        "is_active": a.is_active, "is_default": a.is_default, "created_at": str(a.created_at)}
        for a in db.query(AlertChannel).filter(AlertChannel.user_id == user["user_id"]).all()])

@app.post("/api/alerts")
async def create_alert(data: AlertChannelCreate, user=Depends(get_current_user), db: Session = Depends(get_db)):
    a = AlertChannel(uid=str(uuid.uuid4()), user_id=user["user_id"], name=data.name, channel_type=data.channel_type, config=data.config, is_default=data.is_default, created_at=datetime.utcnow())
    db.add(a); db.commit()
    return JSONResponse({"id": a.id, "message": "Created"})

@app.delete("/api/alerts/{aid}")
async def delete_alert(aid: int, user=Depends(get_current_user), db: Session = Depends(get_db)):
    a = db.query(AlertChannel).filter(AlertChannel.id == aid, AlertChannel.user_id == user["user_id"]).first()
    if not a: raise HTTPException(404)
    db.delete(a); db.commit()
    return JSONResponse({"message": "Deleted"})

@app.get("/api/status-pages")
async def list_sp(user=Depends(get_current_user), db: Session = Depends(get_db)):
    return JSONResponse([{"id": p.id, "uid": p.uid, "title": p.title, "slug": p.slug, "is_public": p.is_public, "monitor_ids": p.monitor_ids or []}
        for p in db.query(StatusPage).filter(StatusPage.user_id == user["user_id"]).all()])

@app.post("/api/status-pages")
async def create_sp(data: StatusPageCreate, user=Depends(get_current_user), db: Session = Depends(get_db)):
    if db.query(StatusPage).filter(StatusPage.slug == data.slug).first(): raise HTTPException(400, "Slug exists")
    p = StatusPage(uid=str(uuid.uuid4()), user_id=user["user_id"], title=data.title, slug=data.slug, description=data.description, monitor_ids=data.monitor_ids, is_public=data.is_public, created_at=datetime.utcnow())
    db.add(p); db.commit()
    return JSONResponse({"id": p.id, "slug": p.slug})

@app.get("/api/status/{slug}")
async def public_sp(slug: str, db: Session = Depends(get_db)):
    p = db.query(StatusPage).filter(StatusPage.slug == slug, StatusPage.is_public == True).first()
    if not p: raise HTTPException(404)
    ms = db.query(Monitor).filter(Monitor.id.in_(p.monitor_ids or [])).all()
    return JSONResponse({"title": p.title, "description": p.description, "monitors": [{"name": m.name, "status": m.status, "uptime_percentage": m.uptime_percentage} for m in ms]})

@app.get("/api/dashboard/stats")
async def dash_stats(user=Depends(get_current_user), db: Session = Depends(get_db)):
    ms = db.query(Monitor).all() if user["role"] == "superadmin" else db.query(Monitor).filter(Monitor.user_id == user["user_id"]).all()
    t = len(ms); up = sum(1 for m in ms if m.status == "up"); dn = sum(1 for m in ms if m.status == "down")
    inc_q = db.query(Incident).filter(Incident.status == "ongoing") if user["role"] == "superadmin" else db.query(Incident).join(Monitor).filter(Monitor.user_id == user["user_id"], Incident.status == "ongoing")
    return JSONResponse({"total_monitors": t, "up": up, "down": dn, "paused": sum(1 for m in ms if m.is_paused),
        "avg_uptime": round(sum(m.uptime_percentage or 0 for m in ms)/t, 2) if t else 100,
        "avg_response_time": round(sum(m.avg_response_time or 0 for m in ms)/t, 2) if t else 0, "ongoing_incidents": inc_q.count()})

@app.get("/api/dashboard/charts")
async def dash_charts(hours: int = 24, user=Depends(get_current_user), db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(hours=hours)
    if user["role"] == "superadmin": logs = db.query(MonitorLog).filter(MonitorLog.created_at >= since).all()
    else:
        mids = [m.id for m in db.query(Monitor).filter(Monitor.user_id == user["user_id"]).all()]
        logs = db.query(MonitorLog).filter(MonitorLog.monitor_id.in_(mids), MonitorLog.created_at >= since).all() if mids else []
    hourly = {}
    for l in logs:
        h = l.created_at.strftime("%Y-%m-%d %H:00")
        if h not in hourly: hourly[h] = {"up": 0, "down": 0, "rt": []}
        if l.status == "up": hourly[h]["up"] += 1
        else: hourly[h]["down"] += 1
        if l.response_time: hourly[h]["rt"].append(l.response_time)
    return JSONResponse({"chart_data": [{"time": h, "uptime": round(d["up"]/(d["up"]+d["down"])*100, 2) if (d["up"]+d["down"]) else 100,
        "avg_response_time": round(sum(d["rt"])/len(d["rt"]), 2) if d["rt"] else 0} for h, d in sorted(hourly.items())], "hours": hours})

# ============================================================================
# ADMIN ROUTES (70+ features)
# ============================================================================
@app.get("/api/admin/users")
async def admin_users(user=Depends(require_admin), db: Session = Depends(get_db)):
    return JSONResponse([{"id": u.id, "uid": u.uid, "username": u.username, "email": u.email, "role": u.role, "is_active": u.is_active,
        "totp_enabled": u.totp_enabled, "last_login": str(u.last_login) if u.last_login else None, "last_ip": u.last_ip,
        "created_at": str(u.created_at), "login_attempts": u.login_attempts} for u in db.query(User).all()])

@app.post("/api/admin/users")
async def admin_create_user(username: str = Body(...), password: str = Body(...), email: str = Body(None), role: str = Body("user"), user=Depends(require_superadmin), db: Session = Depends(get_db)):
    u = User(uid=str(uuid.uuid4()), username=username, email=email, password_hash=hash_password(password), role=role, is_active=True, totp_enabled=False, login_attempts=0, api_key=secrets.token_hex(32), created_at=datetime.utcnow(), updated_at=datetime.utcnow())
    db.add(u); db.commit()
    return JSONResponse({"id": u.id, "message": "Created"})

@app.put("/api/admin/users/{uid}")
async def admin_update_user(uid: int, data: UserUpdate, user=Depends(require_admin), db: Session = Depends(get_db)):
    t = db.query(User).filter(User.id == uid).first()
    if not t: raise HTTPException(404)
    if t.role == "superadmin" and user["role"] != "superadmin": raise HTTPException(403)
    if data.role and user["role"] != "superadmin": raise HTTPException(403)
    for k, v in data.dict(exclude_unset=True).items(): setattr(t, k, v)
    db.commit()
    return JSONResponse({"message": "Updated"})

@app.delete("/api/admin/users/{uid}")
async def admin_del_user(uid: int, user=Depends(require_superadmin), db: Session = Depends(get_db)):
    t = db.query(User).filter(User.id == uid).first()
    if not t: raise HTTPException(404)
    if t.role == "superadmin": raise HTTPException(400, "Cannot delete superadmin")
    db.delete(t); db.commit()
    return JSONResponse({"message": "Deleted"})

@app.post("/api/admin/impersonate/{uid}")
async def impersonate(uid: int, user=Depends(require_superadmin), db: Session = Depends(get_db)):
    t = db.query(User).filter(User.id == uid).first()
    if not t: raise HTTPException(404)
    log_audit(db, user["user_id"], user["username"], "impersonate", "user", str(uid))
    return JSONResponse({"token": create_jwt(t.id, t.username, t.role), "user": {"id": t.id, "username": t.username, "role": t.role}})

@app.post("/api/admin/users/{uid}/toggle-active")
async def toggle_active(uid: int, user=Depends(require_admin), db: Session = Depends(get_db)):
    t = db.query(User).filter(User.id == uid).first()
    if not t: raise HTTPException(404)
    t.is_active = not t.is_active; db.commit()
    return JSONResponse({"is_active": t.is_active})

@app.post("/api/admin/users/{uid}/reset-password")
async def reset_pw(uid: int, new_password: str = Body(..., embed=True), user=Depends(require_superadmin), db: Session = Depends(get_db)):
    t = db.query(User).filter(User.id == uid).first()
    if not t: raise HTTPException(404)
    t.password_hash = hash_password(new_password); t.login_attempts = 0; t.locked_until = None; db.commit()
    return JSONResponse({"message": "Reset"})

@app.post("/api/admin/users/{uid}/unlock")
async def unlock(uid: int, user=Depends(require_admin), db: Session = Depends(get_db)):
    t = db.query(User).filter(User.id == uid).first()
    if not t: raise HTTPException(404)
    t.login_attempts = 0; t.locked_until = None; db.commit()
    return JSONResponse({"message": "Unlocked"})

@app.get("/api/admin/settings")
async def get_settings(user=Depends(require_admin), db: Session = Depends(get_db)):
    return JSONResponse([{"id": s.id, "key": s.key, "value": s.value, "category": s.category, "updated_at": str(s.updated_at)} for s in db.query(SiteSetting).all()])

@app.put("/api/admin/settings/{key}")
async def update_setting(key: str, data: SiteSettingUpdate, user=Depends(require_superadmin), db: Session = Depends(get_db)):
    s = db.query(SiteSetting).filter(SiteSetting.key == key).first()
    if s: s.value = data.value; s.updated_by = user["user_id"]
    else: db.add(SiteSetting(key=key, value=data.value, category=data.category or "general", updated_at=datetime.utcnow()))
    db.commit()
    return JSONResponse({"message": f"'{key}' updated"})

@app.get("/api/admin/audit-logs")
async def audit_logs(limit: int = 100, user=Depends(require_admin), db: Session = Depends(get_db)):
    return JSONResponse([{"id": l.id, "user_id": l.user_id, "username": l.username, "action": l.action, "resource_type": l.resource_type,
        "resource_id": l.resource_id, "details": l.details or {}, "ip_address": l.ip_address, "created_at": str(l.created_at)}
        for l in db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()])

@app.get("/api/admin/system-stats")
async def sys_stats(user=Depends(require_admin), db: Session = Depends(get_db)):
    db_size = 0
    if config.DATABASE_URL.startswith("sqlite"):
        p = Path("monitoring.db"); db_size = p.stat().st_size if p.exists() else 0
    else:
        try: db_size = db.execute(sa_text("SELECT pg_database_size(current_database())")).scalar() or 0
        except: pass
    return JSONResponse({"total_users": db.query(User).count(), "total_monitors": db.query(Monitor).count(), "total_logs": db.query(MonitorLog).count(),
        "total_incidents": db.query(Incident).count(), "active_incidents": db.query(Incident).filter(Incident.status == "ongoing").count(),
        "active_sessions": db.query(UserSession).filter(UserSession.is_active == True).count(), "cache_size": cache.size(),
        "database_size_mb": round(db_size/(1024*1024), 2), "uptime_seconds": int(time.time()-app_start_time),
        "websocket_connections": len(ws.all), "python_version": sys.version.split()[0], "scheduler_jobs": len(scheduler.get_jobs())})

@app.post("/api/admin/database/backup")
async def db_backup(user=Depends(require_superadmin), db: Session = Depends(get_db)):
    if config.DATABASE_URL.startswith("sqlite"):
        import shutil; n = f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.db"
        shutil.copy2("monitoring.db", n); return JSONResponse({"message": f"Backup: {n}"})
    return JSONResponse({"message": "Use pg_dump for PostgreSQL"})

@app.post("/api/admin/database/vacuum")
async def db_vacuum(user=Depends(require_superadmin), db: Session = Depends(get_db)):
    if config.DATABASE_URL.startswith("sqlite"):
        c = sqlite3.connect("monitoring.db"); c.execute("VACUUM"); c.close()
    else:
        try: db.execute(sa_text("VACUUM ANALYZE")); db.commit()
        except: db.rollback()
    return JSONResponse({"message": "Vacuumed"})

@app.get("/api/admin/database/stats")
async def db_stats(user=Depends(require_admin), db: Session = Depends(get_db)):
    tables = {}
    for t in ["users", "monitors", "monitor_logs", "incidents", "alert_channels", "audit_logs", "site_settings", "status_pages", "user_sessions", "maintenance_windows", "ip_whitelist"]:
        try: tables[t] = db.execute(sa_text(f"SELECT COUNT(*) FROM {t}")).scalar()
        except: tables[t] = 0
    return JSONResponse({"tables": tables})

@app.post("/api/admin/cache/clear")
async def clear_cache(user=Depends(require_superadmin)): cache.clear(); return JSONResponse({"message": "Cleared"})

@app.get("/api/admin/cache/stats")
async def cache_st(user=Depends(require_admin)): return JSONResponse({"size": cache.size()})

@app.get("/api/admin/ip-whitelist")
async def get_ips(user=Depends(require_admin), db: Session = Depends(get_db)):
    return JSONResponse([{"id": i.id, "ip_address": i.ip_address, "description": i.description, "is_active": i.is_active} for i in db.query(IPWhitelist).all()])

@app.post("/api/admin/ip-whitelist")
async def add_ip(ip_address: str = Body(...), description: str = Body(""), user=Depends(require_superadmin), db: Session = Depends(get_db)):
    db.add(IPWhitelist(ip_address=ip_address, description=description, created_by=user["user_id"])); db.commit()
    return JSONResponse({"message": "Added"})

@app.delete("/api/admin/ip-whitelist/{iid}")
async def del_ip(iid: int, user=Depends(require_superadmin), db: Session = Depends(get_db)):
    i = db.query(IPWhitelist).filter(IPWhitelist.id == iid).first()
    if i: db.delete(i); db.commit()
    return JSONResponse({"message": "Removed"})

@app.get("/api/admin/sessions")
async def get_sess(user=Depends(require_admin), db: Session = Depends(get_db)):
    return JSONResponse([{"id": s.id, "user_id": s.user_id, "ip_address": s.ip_address, "created_at": str(s.created_at), "expires_at": str(s.expires_at)}
        for s in db.query(UserSession).filter(UserSession.is_active == True).all()])

@app.delete("/api/admin/sessions/{sid}")
async def kill_sess(sid: int, user=Depends(require_superadmin), db: Session = Depends(get_db)):
    s = db.query(UserSession).filter(UserSession.id == sid).first()
    if s: s.is_active = False; db.commit()
    return JSONResponse({"message": "Killed"})

@app.post("/api/admin/monitors/bulk-pause")
async def bulk_pause(monitor_ids: List[int] = Body(...), user=Depends(require_admin), db: Session = Depends(get_db)):
    db.query(Monitor).filter(Monitor.id.in_(monitor_ids)).update({Monitor.is_paused: True, Monitor.status: "paused"}, synchronize_session=False); db.commit()
    return JSONResponse({"message": f"{len(monitor_ids)} paused"})

@app.post("/api/admin/monitors/bulk-resume")
async def bulk_resume(monitor_ids: List[int] = Body(...), user=Depends(require_admin), db: Session = Depends(get_db)):
    db.query(Monitor).filter(Monitor.id.in_(monitor_ids)).update({Monitor.is_paused: False, Monitor.status: "pending"}, synchronize_session=False); db.commit()
    return JSONResponse({"message": f"{len(monitor_ids)} resumed"})

@app.post("/api/admin/monitors/bulk-delete")
async def bulk_del(monitor_ids: List[int] = Body(...), user=Depends(require_superadmin), db: Session = Depends(get_db)):
    db.query(MonitorLog).filter(MonitorLog.monitor_id.in_(monitor_ids)).delete(synchronize_session=False)
    db.query(Incident).filter(Incident.monitor_id.in_(monitor_ids)).delete(synchronize_session=False)
    db.query(Monitor).filter(Monitor.id.in_(monitor_ids)).delete(synchronize_session=False); db.commit()
    return JSONResponse({"message": f"{len(monitor_ids)} deleted"})

@app.post("/api/admin/logs/rotate")
async def rotate_logs(days: int = Body(90, embed=True), user=Depends(require_superadmin), db: Session = Depends(get_db)):
    d = db.query(MonitorLog).filter(MonitorLog.created_at < datetime.utcnow() - timedelta(days=days)).delete(); db.commit()
    return JSONResponse({"deleted_count": d})

@app.post("/api/admin/logs/clear-all")
async def clear_logs(user=Depends(require_superadmin), db: Session = Depends(get_db)):
    d = db.query(MonitorLog).delete(); db.commit()
    return JSONResponse({"deleted_count": d})

@app.get("/api/admin/health")
async def health(user=Depends(require_admin)):
    checks = {"database": "ok", "scheduler": "ok" if scheduler.running else "error", "cache": "ok"}
    try: db = SessionLocal(); db.execute(sa_text("SELECT 1")); db.close()
    except: checks["database"] = "error"
    return JSONResponse({"status": "healthy" if all(v == "ok" for v in checks.values()) else "degraded", "checks": checks})

@app.post("/api/admin/scheduler/trigger")
async def trigger(user=Depends(require_superadmin)): asyncio.create_task(run_checks()); return JSONResponse({"message": "Triggered"})

@app.get("/api/admin/scheduler/jobs")
async def jobs(user=Depends(require_admin)):
    return JSONResponse({"jobs": [{"id": j.id, "next_run": str(j.next_run_time) if j.next_run_time else None} for j in scheduler.get_jobs()]})

@app.post("/api/admin/maintenance-mode/toggle")
async def toggle_maint(user=Depends(require_superadmin), db: Session = Depends(get_db)):
    s = db.query(SiteSetting).filter(SiteSetting.key == "maintenance_mode").first()
    if s: s.value = "false" if s.value == "true" else "true"
    db.commit()
    return JSONResponse({"maintenance_mode": s.value if s else "false"})

@app.post("/api/admin/registration/toggle")
async def toggle_reg(user=Depends(require_superadmin), db: Session = Depends(get_db)):
    s = db.query(SiteSetting).filter(SiteSetting.key == "registration_enabled").first()
    if s: s.value = "false" if s.value == "true" else "true"
    db.commit()
    return JSONResponse({"registration_enabled": s.value if s else "true"})

@app.get("/api/admin/analytics/uptime-heatmap")
async def heatmap(days: int = 30, user=Depends(require_admin), db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(days=days); data = []
    for m in db.query(Monitor).all():
        logs = db.query(MonitorLog).filter(MonitorLog.monitor_id == m.id, MonitorLog.created_at >= since).all()
        daily = {}
        for l in logs:
            d = l.created_at.strftime("%Y-%m-%d")
            if d not in daily: daily[d] = {"up": 0, "t": 0}
            daily[d]["t"] += 1
            if l.status == "up": daily[d]["up"] += 1
        data.append({"monitor_id": m.id, "monitor_name": m.name, "days": [{"date": d, "uptime": round(s["up"]/s["t"]*100, 2) if s["t"] else 100} for d, s in sorted(daily.items())]})
    return JSONResponse({"heatmap": data})

@app.get("/api/admin/analytics/latency")
async def latency(hours: int = 24, user=Depends(require_admin), db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(hours=hours); data = []
    for m in db.query(Monitor).all():
        rts = [l.response_time for l in db.query(MonitorLog).filter(MonitorLog.monitor_id == m.id, MonitorLog.created_at >= since, MonitorLog.response_time.isnot(None)).all() if l.response_time]
        if rts:
            sr = sorted(rts)
            data.append({"monitor_id": m.id, "monitor_name": m.name, "avg": round(sum(rts)/len(rts), 2), "min": round(min(rts), 2), "max": round(max(rts), 2),
                "p95": round(sr[int(len(sr)*0.95)], 2) if sr else 0, "samples": len(rts)})
    return JSONResponse({"latency_data": data})

@app.get("/api/admin/analytics/incident-stats")
async def inc_stats(days: int = 30, user=Depends(require_admin), db: Session = Depends(get_db)):
    incs = db.query(Incident).filter(Incident.created_at >= datetime.utcnow() - timedelta(days=days)).all()
    durs = [i.duration_seconds for i in incs if i.duration_seconds]
    return JSONResponse({"total": len(incs), "resolved": sum(1 for i in incs if i.status == "resolved"), "ongoing": sum(1 for i in incs if i.status == "ongoing"),
        "avg_duration_seconds": round(sum(durs)/len(durs), 2) if durs else 0})

@app.get("/api/admin/analytics/error-breakdown")
async def err_brkdn(hours: int = 24, user=Depends(require_admin), db: Session = Depends(get_db)):
    logs = db.query(MonitorLog).filter(MonitorLog.created_at >= datetime.utcnow() - timedelta(hours=hours), MonitorLog.status == "down").all()
    errs = {}
    for l in logs: k = (l.error_message or "Unknown")[:100]; errs[k] = errs.get(k, 0) + 1
    return JSONResponse({"error_breakdown": errs, "total_errors": len(logs)})

@app.get("/api/admin/features")
async def features(user=Depends(require_admin)):
    f = [{"id": i+1, "name": n, "category": c} for i, (n, c) in enumerate([
        ("User Management","Users"),("Create User","Users"),("Update User","Users"),("Delete User","Users"),("Impersonation","Users"),
        ("Toggle Active","Users"),("Reset Password","Users"),("Unlock User","Users"),("Site Settings","Settings"),("Update Setting","Settings"),
        ("Audit Logs","Security"),("All Monitors","Monitors"),("System Stats","System"),("DB Backup","Database"),("DB Vacuum","Database"),
        ("DB Stats","Database"),("Clear Cache","Cache"),("Cache Stats","Cache"),("IP Whitelist","Security"),("Add IP","Security"),
        ("Remove IP","Security"),("Sessions","Security"),("Kill Session","Security"),("Maintenance Windows","Monitors"),
        ("Bulk Pause","Monitors"),("Bulk Resume","Monitors"),("Bulk Delete","Monitors"),("Log Rotation","Maintenance"),
        ("Clear Logs","Maintenance"),("Health Check","System"),("Trigger Checks","System"),("Scheduler Jobs","System"),
        ("Maintenance Mode","System"),("Registration Toggle","System"),("Uptime Heatmap","Analytics"),("Latency Analytics","Analytics"),
        ("Incident Stats","Analytics"),("Error Breakdown","Analytics"),("Monitor Logs","Reports"),("Monitor Uptime","Reports"),
        ("Status Pages","StatusPages"),("Public Status","StatusPages"),("Alert Channels","Alerts"),("Dashboard Stats","Dashboard"),
        ("Dashboard Charts","Dashboard"),("2FA Setup","Auth"),("Password Change","Auth"),("API Key Regen","Auth"),
        ("Video Background","Theme"),("Music Player","Theme"),("Particle Effects","Theme"),("Custom CSS","Theme"),
        ("Theme Colors","Theme"),("Export Monitors","Data"),("Export Users","Data"),("Export Logs","Data"),
        ("Monitor Create","Monitors"),("Monitor Update","Monitors"),("Monitor Delete","Monitors"),("Monitor Pause","Monitors"),
        ("Monitor Check","Monitors"),("Incident Acknowledge","Incidents"),("Incident Resolve","Incidents"),
        ("Create Alert","Alerts"),("Delete Alert","Alerts"),("Create Status Page","StatusPages"),
        ("User Activity","Analytics"),("Monitor Performance","Analytics"),("Geo Distribution","Analytics"),
        ("Response Time Distribution","Analytics"),("Session Kill All","Security"),("Notification Templates","Notifications"),
        ("Feature List","System")])]
    return JSONResponse({"features": f, "total": len(f)})

@app.get("/api/admin/export/monitors")
async def exp_monitors(user=Depends(require_admin), db: Session = Depends(get_db)):
    return StreamingResponse(BytesIO(json.dumps([{"id": m.id, "name": m.name, "url": m.url, "status": m.status, "uptime": m.uptime_percentage} for m in db.query(Monitor).all()], indent=2).encode()),
        media_type="application/json", headers={"Content-Disposition": "attachment; filename=monitors.json"})

@app.get("/api/admin/export/users")
async def exp_users(user=Depends(require_superadmin), db: Session = Depends(get_db)):
    return StreamingResponse(BytesIO(json.dumps([{"id": u.id, "username": u.username, "email": u.email, "role": u.role} for u in db.query(User).all()], indent=2).encode()),
        media_type="application/json", headers={"Content-Disposition": "attachment; filename=users.json"})

@app.get("/api/admin/theme")
async def get_theme(user=Depends(require_admin), db: Session = Depends(get_db)):
    return JSONResponse({s.key: s.value for s in db.query(SiteSetting).filter(SiteSetting.category == "theme").all()})

@app.put("/api/admin/theme")
async def update_theme(settings: Dict[str, str] = Body(...), user=Depends(require_superadmin), db: Session = Depends(get_db)):
    for k, v in settings.items():
        s = db.query(SiteSetting).filter(SiteSetting.key == k).first()
        if s: s.value = v
        else: db.add(SiteSetting(key=k, value=v, category="theme", updated_at=datetime.utcnow()))
    db.commit()
    return JSONResponse({"message": "Theme updated"})

# ============================================================================
# WEBSOCKET
# ============================================================================
@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket, token: Optional[str] = Query(None)):
    uid = 0
    if token:
        p = verify_jwt(token)
        if p: uid = p.get("user_id", 0)
    await ws.connect(websocket, uid)
    try:
        while True:
            d = await websocket.receive_text()
            try:
                m = json.loads(d)
                if m.get("type") == "ping": await websocket.send_json({"type": "pong"})
            except: pass
    except WebSocketDisconnect: ws.disconnect(websocket, uid)

# ============================================================================
# FRONTEND - PREMIUM MOBILE UI WITH VIDEO BG & MUSIC
# ============================================================================
FRONTEND = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<meta name="theme-color" content="#0f172a">
<meta name="apple-mobile-web-app-capable" content="yes">
<title>MonitorPro SaaS</title>
<script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Inter',system-ui,sans-serif;-webkit-tap-highlight-color:transparent}
html,body{background:#000;color:#f1f5f9;overflow-x:hidden;min-height:100vh;min-height:100dvh}
::-webkit-scrollbar{width:3px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#6366f1;border-radius:4px}

#video-bg{position:fixed;top:0;left:0;width:100vw;height:100vh;object-fit:cover;z-index:0;opacity:0.3;pointer-events:none}
#overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:linear-gradient(180deg,rgba(15,23,42,0.85) 0%,rgba(15,23,42,0.92) 50%,rgba(15,23,42,0.98) 100%);z-index:1;pointer-events:none}
.app-wrap{position:relative;z-index:2}

.glass{background:rgba(30,41,59,0.65);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border:1px solid rgba(99,102,241,0.15)}
.card{background:rgba(30,41,59,0.5);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid rgba(148,163,184,0.08);border-radius:20px;transition:transform 0.2s,box-shadow 0.2s}
.card:active{transform:scale(0.98)}
.card-glow{box-shadow:0 0 30px rgba(99,102,241,0.08)}

@keyframes slideUp{from{transform:translateY(30px);opacity:0}to{transform:translateY(0);opacity:1}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes pulse-g{0%,100%{box-shadow:0 0 0 0 rgba(34,197,94,0.5)}50%{box-shadow:0 0 0 10px rgba(34,197,94,0)}}
@keyframes pulse-r{0%,100%{box-shadow:0 0 0 0 rgba(239,68,68,0.5)}50%{box-shadow:0 0 0 10px rgba(239,68,68,0)}}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
@keyframes glow{0%,100%{opacity:0.5}50%{opacity:1}}

.anim-up{animation:slideUp 0.4s cubic-bezier(0.16,1,0.3,1)}
.anim-fade{animation:fadeIn 0.3s ease}
.pulse-g{animation:pulse-g 2s infinite}.pulse-r{animation:pulse-r 1.5s infinite}
.skeleton{background:linear-gradient(90deg,#1e293b 25%,#334155 50%,#1e293b 75%);background-size:200% 100%;animation:shimmer 1.5s infinite;border-radius:12px}
.float{animation:float 3s ease-in-out infinite}

.btn{padding:14px 28px;border-radius:16px;font-weight:700;font-size:15px;border:none;cursor:pointer;transition:all 0.2s;display:flex;align-items:center;justify-content:center;gap:8px;letter-spacing:0.3px}
.btn:active{transform:scale(0.96)}
.btn-primary{background:linear-gradient(135deg,#6366f1 0%,#8b5cf6 50%,#a78bfa 100%);color:#fff;box-shadow:0 4px 20px rgba(99,102,241,0.4)}
.btn-primary:hover{box-shadow:0 6px 30px rgba(99,102,241,0.5);transform:translateY(-1px)}
.btn-ghost{background:rgba(99,102,241,0.1);color:#a5b4fc;border:1px solid rgba(99,102,241,0.2)}
.btn-danger{background:rgba(239,68,68,0.1);color:#fca5a5;border:1px solid rgba(239,68,68,0.2)}
.btn-success{background:rgba(34,197,94,0.1);color:#86efac;border:1px solid rgba(34,197,94,0.2)}
.btn-amber{background:rgba(245,158,11,0.1);color:#fcd34d;border:1px solid rgba(245,158,11,0.2)}
.btn-sm{padding:10px 18px;font-size:12px;border-radius:12px;font-weight:600}

.input{background:rgba(15,23,42,0.7);border:2px solid rgba(148,163,184,0.15);color:#f1f5f9;padding:14px 18px;border-radius:16px;width:100%;font-size:16px;outline:none;transition:all 0.25s}
.input:focus{border-color:#6366f1;box-shadow:0 0 0 4px rgba(99,102,241,0.1);background:rgba(15,23,42,0.9)}
.input::placeholder{color:#64748b}

select.input{appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 14px center;padding-right:40px}

.fab{position:fixed;right:20px;bottom:90px;width:60px;height:60px;border-radius:30px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;border:none;font-size:28px;cursor:pointer;box-shadow:0 8px 30px rgba(99,102,241,0.5);z-index:40;display:flex;align-items:center;justify-content:center;transition:all 0.2s}
.fab:active{transform:scale(0.9)}
.fab:hover{box-shadow:0 8px 40px rgba(99,102,241,0.6)}

.bottom-nav{position:fixed;bottom:0;left:0;right:0;height:72px;z-index:30}
.safe-bottom{padding-bottom:95px}

.modal-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.75);backdrop-filter:blur(8px);z-index:50;display:flex;align-items:flex-end;justify-content:center}
.modal{background:linear-gradient(180deg,#1e293b 0%,#0f172a 100%);border-radius:28px 28px 0 0;width:100%;max-width:500px;max-height:88vh;overflow-y:auto;padding:28px;border:1px solid rgba(99,102,241,0.15);border-bottom:none}

.badge{padding:4px 12px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:0.5px;text-transform:uppercase}
.badge-up{background:rgba(34,197,94,0.15);color:#4ade80;border:1px solid rgba(34,197,94,0.2)}
.badge-down{background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.2)}
.badge-pending{background:rgba(245,158,11,0.15);color:#fbbf24;border:1px solid rgba(245,158,11,0.2)}
.badge-paused{background:rgba(148,163,184,0.15);color:#94a3b8;border:1px solid rgba(148,163,184,0.2)}
.badge-sa{background:rgba(168,85,247,0.15);color:#c084fc;border:1px solid rgba(168,85,247,0.2)}
.badge-admin{background:rgba(99,102,241,0.15);color:#a5b4fc;border:1px solid rgba(99,102,241,0.2)}
.badge-user{background:rgba(148,163,184,0.1);color:#94a3b8}

.tab{padding:10px 16px;font-size:13px;font-weight:600;color:#64748b;border-bottom:2px solid transparent;transition:all 0.2s;white-space:nowrap}
.tab-active{color:#a5b4fc;border-color:#6366f1}

.hm-cell{width:12px;height:12px;border-radius:3px;display:inline-block;margin:1px}
.chart-bar{transition:height 0.4s cubic-bezier(0.16,1,0.3,1);border-radius:3px 3px 0 0}

.music-bar{position:fixed;top:0;left:0;right:0;height:48px;z-index:25;display:flex;align-items:center;justify-content:space-between;padding:0 16px}
.music-btn{width:36px;height:36px;border-radius:18px;background:rgba(99,102,241,0.2);border:1px solid rgba(99,102,241,0.3);color:#a5b4fc;display:flex;align-items:center;justify-content:center;cursor:pointer;font-size:16px;transition:all 0.2s}
.music-btn:active{transform:scale(0.9)}
.music-info{font-size:11px;color:#64748b;display:flex;align-items:center;gap:8px}
.music-eq{display:flex;gap:2px;align-items:flex-end;height:16px}
.music-eq span{width:3px;background:#6366f1;border-radius:2px;animation:eq 0.8s ease-in-out infinite alternate}
.music-eq span:nth-child(1){height:6px;animation-delay:0s}
.music-eq span:nth-child(2){height:12px;animation-delay:0.2s}
.music-eq span:nth-child(3){height:8px;animation-delay:0.4s}
.music-eq span:nth-child(4){height:14px;animation-delay:0.1s}
.music-eq span:nth-child(5){height:5px;animation-delay:0.3s}
@keyframes eq{to{height:4px}}

.stat-card{border-radius:20px;padding:18px;position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;top:-20px;right:-20px;width:80px;height:80px;border-radius:50%;opacity:0.1}
.stat-indigo{background:linear-gradient(135deg,rgba(99,102,241,0.15),rgba(99,102,241,0.05));border:1px solid rgba(99,102,241,0.2)}
.stat-indigo::before{background:#6366f1}
.stat-green{background:linear-gradient(135deg,rgba(34,197,94,0.15),rgba(34,197,94,0.05));border:1px solid rgba(34,197,94,0.2)}
.stat-green::before{background:#22c55e}
.stat-red{background:linear-gradient(135deg,rgba(239,68,68,0.15),rgba(239,68,68,0.05));border:1px solid rgba(239,68,68,0.2)}
.stat-red::before{background:#ef4444}
.stat-purple{background:linear-gradient(135deg,rgba(168,85,247,0.15),rgba(168,85,247,0.05));border:1px solid rgba(168,85,247,0.2)}
.stat-purple::before{background:#a855f7}
.stat-amber{background:linear-gradient(135deg,rgba(245,158,11,0.15),rgba(245,158,11,0.05));border:1px solid rgba(245,158,11,0.2)}
.stat-amber::before{background:#f59e0b}

.content-top{padding-top:56px}
</style>
</head>
<body>
<video id="video-bg" autoplay muted loop playsinline><source src="https://cdn.pixabay.com/video/2020/05/25/40130-424930032_large.mp4" type="video/mp4"></video>
<div id="overlay"></div>
<audio id="bg-music" loop preload="auto"><source src="https://www.bensound.com/bensound-music/bensound-creativeminds.mp3" type="audio/mpeg"></audio>
<div id="root"></div>

<script type="text/babel">
const {useState,useEffect,useCallback,useRef,createContext,useContext}=React;
const Ctx=createContext();
const useApp=()=>useContext(Ctx);

const API={
    token:localStorage.getItem('token'),
    setToken(t){this.token=t;t?localStorage.setItem('token',t):localStorage.removeItem('token')},
    async req(m,u,b){
        const o={method:m,headers:{'Content-Type':'application/json'}};
        if(this.token)o.headers.Authorization='Bearer '+this.token;
        if(b)o.body=JSON.stringify(b);
        const r=await fetch(u,o);
        if(r.status===401){this.setToken(null);location.reload();return}
        const txt=await r.text();
        try{const d=JSON.parse(txt);if(!r.ok)throw new Error(d.detail||'Error');return d}
        catch(e){if(!r.ok)throw new Error('Error '+r.status);throw e}
    },
    get:u=>API.req('GET',u),post:(u,b)=>API.req('POST',u,b),put:(u,b)=>API.req('PUT',u,b),del:u=>API.req('DELETE',u)
};

// Icons
const I={
    Home:()=><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>,
    Monitor:()=><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>,
    Bell:()=><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/></svg>,
    Shield:()=><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>,
    Gear:()=><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>,
    Plus:()=><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><path d="M5 12h14M12 5v14"/></svg>,
    X:()=><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M18 6 6 18M6 6l12 12"/></svg>,
    Play:()=><svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>,
    Pause2:()=><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect width="4" height="16" x="6" y="4"/><rect width="4" height="16" x="14" y="4"/></svg>,
    Refresh:()=><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8M21 3v5h-5M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16M8 16H3v5"/></svg>,
    Trash:()=><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M3 6h18M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>,
    ChevR:()=><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="m9 18 6-6-6-6"/></svg>,
    Logout:()=><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>,
    Check:()=><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><polyline points="20 6 9 17 4 12"/></svg>,
    Music:()=><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>,
    Vol:()=><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07"/></svg>,
    Mute:()=><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><line x1="23" x2="17" y1="9" y2="15"/><line x1="17" x2="23" y1="9" y2="15"/></svg>,
};

// Music Bar
function MusicBar(){
    const [playing,setPlaying]=useState(false);
    const toggle=()=>{const a=document.getElementById('bg-music');if(a){if(playing){a.pause()}else{a.volume=0.3;a.play().catch(()=>{})}setPlaying(!playing)}};
    return(<div className="music-bar glass">
        <div className="music-info">{playing&&<div className="music-eq"><span/><span/><span/><span/><span/></div>}<span>{playing?'♪ Now Playing':'♪ Music Off'}</span></div>
        <button className="music-btn" onClick={toggle}>{playing?<I.Mute/>:<I.Vol/>}</button>
    </div>);
}

// Stat Card
function SC({label,value,color='indigo'}){
    return(<div className={`stat-card stat-${color} anim-up`}><p style={{fontSize:11,color:'#94a3b8',textTransform:'uppercase',letterSpacing:1,fontWeight:600}}>{label}</p><p style={{fontSize:28,fontWeight:800,marginTop:4,background:'linear-gradient(135deg,#f1f5f9,#cbd5e1)',WebkitBackgroundClip:'text',WebkitTextFillColor:'transparent'}}>{value}</p></div>);
}

// Mini Chart
function Chart({data,h=60}){
    if(!data||!data.length)return<div style={{textAlign:'center',color:'#475569',fontSize:12,padding:20}}>No data yet</div>;
    const mx=Math.max(...data.map(d=>d.v),1);
    return(<div style={{display:'flex',alignItems:'flex-end',gap:2,height:h}}>{data.slice(-30).map((d,i)=>(<div key={i} className="chart-bar" title={d.l+': '+d.v} style={{flex:1,height:Math.max(d.v/mx*100,3)+'%',background:d.c||'#6366f1'}}/>))}</div>);
}

// Login
function Login({onLogin}){
    const[u,su]=useState('');const[p,sp]=useState('');const[e,se]=useState('');const[l,sl]=useState(false);const[reg,sr]=useState(false);const[em,sem]=useState('');
    const go=async(ev)=>{ev.preventDefault();sl(true);se('');try{
        if(reg){const d=await API.post('/api/auth/register',{username:u,password:p,email:em});API.setToken(d.token);onLogin(d.user)}
        else{const d=await API.post('/api/auth/login',{username:u,password:p});if(d.requires_2fa){se('2FA required');sl(false);return}API.setToken(d.token);onLogin(d.user)}
    }catch(x){se(x.message)}sl(false)};
    return(<div className="app-wrap" style={{minHeight:'100vh',display:'flex',alignItems:'center',justifyContent:'center',padding:20}}>
        <div className="card card-glow anim-up" style={{padding:36,width:'100%',maxWidth:380}}>
            <div style={{textAlign:'center',marginBottom:32}}>
                <div className="float" style={{width:72,height:72,borderRadius:22,background:'linear-gradient(135deg,#6366f1,#8b5cf6,#a78bfa)',margin:'0 auto 16px',display:'flex',alignItems:'center',justifyContent:'center',boxShadow:'0 8px 30px rgba(99,102,241,0.4)'}}><I.Shield/></div>
                <h1 style={{fontSize:28,fontWeight:900,background:'linear-gradient(135deg,#a5b4fc,#c084fc)',WebkitBackgroundClip:'text',WebkitTextFillColor:'transparent'}}>MonitorPro</h1>
                <p style={{color:'#64748b',fontSize:13,marginTop:4}}>{reg?'Create your account':'Sign in to continue'}</p>
            </div>
            {e&&<div style={{background:'rgba(239,68,68,0.1)',border:'1px solid rgba(239,68,68,0.2)',borderRadius:14,padding:12,marginBottom:16,color:'#fca5a5',fontSize:13,fontWeight:500}}>{e}</div>}
            <form onSubmit={go} style={{display:'flex',flexDirection:'column',gap:14}}>
                <input className="input" placeholder="Username" value={u} onChange={x=>su(x.target.value)} required/>
                {reg&&<input className="input" type="email" placeholder="Email" value={em} onChange={x=>sem(x.target.value)}/>}
                <input className="input" type="password" placeholder="Password" value={p} onChange={x=>sp(x.target.value)} required/>
                <button className="btn btn-primary" disabled={l} style={{marginTop:4}}>{l?'●●●':reg?'Create Account':'Sign In'}</button>
            </form>
            <p style={{textAlign:'center',color:'#64748b',fontSize:13,marginTop:20}}><button onClick={()=>sr(!reg)} style={{background:'none',border:'none',color:'#818cf8',cursor:'pointer',fontWeight:600,textDecoration:'underline'}}>{reg?'Have an account? Sign in':'Create new account'}</button></p>
        </div>
    </div>);
}

// Monitor Card
function MC({m,onClick,onPause,onCheck}){
    const sc={up:'badge-up',down:'badge-down',pending:'badge-pending',paused:'badge-paused'};
    const dc={up:'#22c55e',down:'#ef4444',pending:'#f59e0b',paused:'#64748b'};
    const pc={up:'pulse-g',down:'pulse-r'};
    return(<div className="card card-glow anim-up" style={{padding:18,marginBottom:14,cursor:'pointer'}} onClick={()=>onClick&&onClick(m)}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
            <div style={{display:'flex',alignItems:'center',gap:12,flex:1,minWidth:0}}>
                <div className={pc[m.status]||''} style={{width:12,height:12,borderRadius:6,background:dc[m.status]||'#64748b',flexShrink:0}}/>
                <div style={{minWidth:0}}><h3 style={{fontSize:14,fontWeight:700,whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{m.name}</h3><p style={{fontSize:11,color:'#64748b',whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{m.url}</p></div>
            </div>
            <div style={{textAlign:'right',marginLeft:12,flexShrink:0}}>
                <p style={{fontSize:15,fontWeight:800,fontFamily:'monospace',color:m.uptime_percentage>=99?'#4ade80':m.uptime_percentage>=95?'#fbbf24':'#f87171'}}>{(m.uptime_percentage||100).toFixed(1)}%</p>
                <p style={{fontSize:11,color:'#64748b'}}>{(m.avg_response_time||0).toFixed(0)}ms</p>
            </div>
        </div>
        <div style={{display:'flex',gap:8,marginTop:14}}>
            <button className="btn btn-ghost btn-sm" style={{flex:1}} onClick={e=>{e.stopPropagation();onPause&&onPause(m)}}>{m.is_paused?<I.Play/>:<I.Pause2/>}<span>{m.is_paused?'Resume':'Pause'}</span></button>
            <button className="btn btn-ghost btn-sm" style={{flex:1}} onClick={e=>{e.stopPropagation();onCheck&&onCheck(m)}}><I.Refresh/><span>Check</span></button>
        </div>
    </div>);
}

// Dashboard
function Dash(){
    const{user}=useApp();const[s,ss]=useState(null);const[cd,scd]=useState([]);const[ld,sld]=useState(true);
    const load=useCallback(async()=>{try{const[a,b]=await Promise.all([API.get('/api/dashboard/stats'),API.get('/api/dashboard/charts?hours=24')]);ss(a);scd(b.chart_data||[])}catch(e){}sld(false)},[]);
    useEffect(()=>{load();const t=setInterval(load,30000);return()=>clearInterval(t)},[load]);
    if(ld)return<div className="safe-bottom content-top" style={{padding:20}}><div className="skeleton" style={{height:100,marginBottom:16}}/><div className="skeleton" style={{height:100,marginBottom:16}}/><div className="skeleton" style={{height:160}}/></div>;
    const uc=cd.map(d=>({v:d.uptime,l:d.time,c:d.uptime>=99?'#22c55e':d.uptime>=95?'#f59e0b':'#ef4444'}));
    const rc=cd.map(d=>({v:d.avg_response_time,l:d.time,c:'#6366f1'}));
    return(<div className="safe-bottom content-top" style={{padding:20}}>
        <div style={{marginBottom:24}}><h1 style={{fontSize:24,fontWeight:900}}>Dashboard</h1><p style={{color:'#64748b',fontSize:13}}>Welcome back, <span style={{color:'#a5b4fc',fontWeight:600}}>{user?.username}</span></p></div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:20}}>
            <SC label="Monitors" value={s?.total_monitors||0} color="indigo"/><SC label="Online" value={s?.up||0} color="green"/>
            <SC label="Offline" value={s?.down||0} color="red"/><SC label="Uptime" value={(s?.avg_uptime||100)+'%'} color="purple"/>
        </div>
        <div className="card card-glow" style={{padding:18,marginBottom:14}}><h3 style={{fontSize:13,fontWeight:700,marginBottom:12,color:'#94a3b8'}}>📈 Uptime Trend (24h)</h3><Chart data={uc}/></div>
        <div className="card card-glow" style={{padding:18,marginBottom:14}}><h3 style={{fontSize:13,fontWeight:700,marginBottom:12,color:'#94a3b8'}}>⚡ Response Time (24h)</h3><Chart data={rc} h={50}/></div>
        {s?.ongoing_incidents>0&&<div className="anim-up" style={{background:'rgba(239,68,68,0.08)',border:'1px solid rgba(239,68,68,0.2)',borderRadius:20,padding:18,display:'flex',alignItems:'center',gap:14}}>
            <div className="pulse-r" style={{width:14,height:14,borderRadius:7,background:'#ef4444',flexShrink:0}}/><div><p style={{fontWeight:700,color:'#fca5a5',fontSize:14}}>🚨 {s.ongoing_incidents} Active Incident{s.ongoing_incidents>1?'s':''}</p><p style={{fontSize:11,color:'#64748b'}}>Requires attention</p></div>
        </div>}
    </div>);
}

// Monitors Page
function Monitors(){
    const[ms,sms]=useState([]);const[ld,sld]=useState(true);const[cr,scr]=useState(false);const[dt,sdt]=useState(null);const[f,sf]=useState('all');
    const load=useCallback(async()=>{try{sms(await API.get('/api/monitors')||[])}catch{}sld(false)},[]);
    useEffect(()=>{load()},[load]);
    const pause=async m=>{try{await API.post('/api/monitors/'+m.id+'/pause');load()}catch(e){alert(e.message)}};
    const chk=async m=>{try{await API.post('/api/monitors/'+m.id+'/check');load()}catch(e){alert(e.message)}};
    const del=async m=>{if(!confirm('Delete this monitor?'))return;try{await API.del('/api/monitors/'+m.id);sdt(null);load()}catch(e){alert(e.message)}};
    const fl=ms.filter(m=>f==='all'||f==='up'&&m.status==='up'||f==='down'&&m.status==='down'||f==='paused'&&m.is_paused);
    return(<div className="safe-bottom content-top" style={{padding:20}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:16}}><h1 style={{fontSize:24,fontWeight:900}}>Monitors</h1><span className="badge badge-paused">{ms.length} total</span></div>
        <div style={{display:'flex',gap:8,marginBottom:16,overflowX:'auto',paddingBottom:8}}>{['all','up','down','paused'].map(x=>(<button key={x} onClick={()=>sf(x)} className={'btn btn-sm '+(f===x?'btn-primary':'btn-ghost')} style={{minWidth:70}}>{x[0].toUpperCase()+x.slice(1)}</button>))}</div>
        {ld?<div><div className="skeleton" style={{height:100,marginBottom:14}}/><div className="skeleton" style={{height:100}}/></div>:
        fl.length===0?<div style={{textAlign:'center',color:'#475569',padding:'60px 0'}}><p style={{fontSize:40,marginBottom:8}}>📭</p><p>No monitors found</p></div>:
        fl.map(m=><MC key={m.id} m={m} onClick={sdt} onPause={pause} onCheck={chk}/>)}
        <button className="fab" onClick={()=>scr(true)}><I.Plus/></button>
        {cr&&<CreateModal onClose={()=>scr(false)} onDone={()=>{scr(false);load()}}/>}
        {dt&&<DetailModal m={dt} onClose={()=>sdt(null)} onDel={del}/>}
    </div>);
}

function CreateModal({onClose,onDone}){
    const[f,sf]=useState({name:'',url:'',monitor_type:'http',interval:60,timeout:30,expected_status:200,keyword:'',method:'GET'});const[l,sl]=useState(false);
    const s=(k,v)=>sf(p=>({...p,[k]:v}));
    const go=async e=>{e.preventDefault();sl(true);try{await API.post('/api/monitors',f);onDone()}catch(e){alert(e.message)}sl(false)};
    return(<div className="modal-overlay" onClick={onClose}><div className="modal anim-up" onClick={e=>e.stopPropagation()}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:24}}><h2 style={{fontSize:20,fontWeight:800}}>✨ New Monitor</h2><button onClick={onClose} style={{background:'none',border:'none',color:'#94a3b8',cursor:'pointer',padding:8}}><I.X/></button></div>
        <form onSubmit={go} style={{display:'flex',flexDirection:'column',gap:14}}>
            <div><label style={{fontSize:12,color:'#64748b',fontWeight:600,marginBottom:6,display:'block'}}>Name</label><input className="input" value={f.name} onChange={e=>s('name',e.target.value)} placeholder="My Website" required/></div>
            <div><label style={{fontSize:12,color:'#64748b',fontWeight:600,marginBottom:6,display:'block'}}>URL</label><input className="input" value={f.url} onChange={e=>s('url',e.target.value)} placeholder="https://example.com" required/></div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
                <div><label style={{fontSize:12,color:'#64748b',fontWeight:600,marginBottom:6,display:'block'}}>Type</label><select className="input" value={f.monitor_type} onChange={e=>s('monitor_type',e.target.value)}><option value="http">HTTP</option><option value="https">HTTPS</option><option value="ping">Ping</option><option value="port">Port</option><option value="keyword">Keyword</option><option value="tcp">TCP</option></select></div>
                <div><label style={{fontSize:12,color:'#64748b',fontWeight:600,marginBottom:6,display:'block'}}>Interval (s)</label><input className="input" type="number" value={f.interval} onChange={e=>s('interval',parseInt(e.target.value)||60)}/></div>
            </div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
                <div><label style={{fontSize:12,color:'#64748b',fontWeight:600,marginBottom:6,display:'block'}}>Method</label><select className="input" value={f.method} onChange={e=>s('method',e.target.value)}><option>GET</option><option>POST</option><option>PUT</option><option>HEAD</option></select></div>
                <div><label style={{fontSize:12,color:'#64748b',fontWeight:600,marginBottom:6,display:'block'}}>Expected</label><input className="input" type="number" value={f.expected_status} onChange={e=>s('expected_status',parseInt(e.target.value)||200)}/></div>
            </div>
            {f.monitor_type==='keyword'&&<div><label style={{fontSize:12,color:'#64748b',fontWeight:600,marginBottom:6,display:'block'}}>Keyword</label><input className="input" value={f.keyword} onChange={e=>s('keyword',e.target.value)} placeholder="Expected text"/></div>}
            <button className="btn btn-primary" disabled={l} style={{marginTop:8}}>{l?'Creating...':'🚀 Create Monitor'}</button>
        </form>
    </div></div>);
}

function DetailModal({m,onClose,onDel}){
    const[logs,sl]=useState([]);const[up,su]=useState(null);const[tab,st]=useState('info');
    useEffect(()=>{API.get('/api/monitors/'+m.id+'/logs?limit=50').then(d=>sl(d||[])).catch(()=>{});API.get('/api/monitors/'+m.id+'/uptime?days=30').then(su).catch(()=>{})},[m.id]);
    const sc={up:'#4ade80',down:'#f87171',pending:'#fbbf24',paused:'#94a3b8'};
    return(<div className="modal-overlay" onClick={onClose}><div className="modal anim-up" onClick={e=>e.stopPropagation()} style={{maxHeight:'92vh'}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:16}}>
            <div style={{minWidth:0}}><h2 style={{fontSize:18,fontWeight:800,marginBottom:2}}>{m.name}</h2><p style={{fontSize:11,color:'#64748b',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{m.url}</p></div>
            <button onClick={onClose} style={{background:'none',border:'none',color:'#94a3b8',cursor:'pointer',padding:8,flexShrink:0}}><I.X/></button>
        </div>
        <div style={{display:'flex',gap:12,alignItems:'center',marginBottom:16}}>
            <span className={'badge badge-'+m.status}>{m.status}</span>
            <span style={{fontSize:13,color:'#94a3b8',fontWeight:600}}>{(m.uptime_percentage||100).toFixed(2)}%</span>
            <span style={{fontSize:13,color:'#64748b'}}>{(m.avg_response_time||0).toFixed(0)}ms</span>
        </div>
        <div style={{display:'flex',gap:4,borderBottom:'1px solid rgba(148,163,184,0.1)',marginBottom:16}}>{['info','logs','uptime'].map(t=>(<button key={t} className={'tab '+(tab===t?'tab-active':'')} onClick={()=>st(t)}>{t[0].toUpperCase()+t.slice(1)}</button>))}</div>
        {tab==='info'&&<div style={{display:'flex',flexDirection:'column',gap:10}}>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
                {[['Type',m.monitor_type],['Interval',m.interval+'s'],['Last Check',m.last_checked?new Date(m.last_checked).toLocaleTimeString():'Never'],['Failures',m.consecutive_failures||0]].map(([l,v],i)=>(
                    <div key={i} style={{background:'rgba(15,23,42,0.5)',borderRadius:14,padding:14}}><p style={{fontSize:10,color:'#64748b',textTransform:'uppercase',fontWeight:600}}>{l}</p><p style={{fontSize:14,fontWeight:700,marginTop:4}}>{v}</p></div>
                ))}
            </div>
            <button className="btn btn-danger" style={{marginTop:8}} onClick={()=>onDel(m)}>🗑️ Delete Monitor</button>
        </div>}
        {tab==='logs'&&<div style={{maxHeight:260,overflowY:'auto',display:'flex',flexDirection:'column',gap:6}}>
            {logs.length===0?<p style={{textAlign:'center',color:'#475569',padding:20}}>No logs yet</p>:logs.map(l=>(
                <div key={l.id} style={{display:'flex',justifyContent:'space-between',alignItems:'center',background:'rgba(15,23,42,0.4)',borderRadius:12,padding:12}}>
                    <div style={{display:'flex',alignItems:'center',gap:8}}><div style={{width:8,height:8,borderRadius:4,background:l.status==='up'?'#22c55e':'#ef4444'}}/><span style={{fontSize:11,color:'#64748b'}}>{new Date(l.created_at).toLocaleTimeString()}</span></div>
                    <div style={{textAlign:'right'}}><span style={{fontSize:12,fontFamily:'monospace',fontWeight:600}}>{l.response_time?.toFixed(0)||'-'}ms</span>{l.status_code&&<span style={{fontSize:11,color:'#64748b',marginLeft:8}}>{l.status_code}</span>}</div>
                </div>
            ))}
        </div>}
        {tab==='uptime'&&up&&<div>
            <div style={{textAlign:'center',marginBottom:16}}><p style={{fontSize:42,fontWeight:900,color:'#4ade80'}}>{up.uptime_percentage}%</p><p style={{fontSize:12,color:'#64748b'}}>{up.days}-day uptime ({up.total_checks} checks)</p></div>
            <div style={{display:'flex',flexWrap:'wrap',gap:2}}>{(up.heatmap||[]).map((d,i)=>{const c=d.uptime>=99.9?'#22c55e':d.uptime>=99?'#86efac':d.uptime>=95?'#f59e0b':d.uptime>=90?'#f97316':'#ef4444';return<div key={i} className="hm-cell" style={{background:c}} title={d.date+': '+d.uptime+'%'}/>})}</div>
            <div style={{display:'flex',justifyContent:'space-between',marginTop:6}}><span style={{fontSize:10,color:'#475569'}}>30 days ago</span><span style={{fontSize:10,color:'#475569'}}>Today</span></div>
        </div>}
    </div></div>);
}

// Incidents
function Incidents(){
    const[inc,si]=useState([]);const[ld,sld]=useState(true);const[f,sf]=useState('');
    useEffect(()=>{API.get('/api/incidents'+(f?'?status='+f:'')).then(d=>{si(d||[]);sld(false)}).catch(()=>sld(false))},[f]);
    const ack=async id=>{try{await API.post('/api/incidents/'+id+'/acknowledge');si(p=>p.map(i=>i.id===id?{...i,status:'acknowledged'}:i))}catch{}};
    const res=async id=>{try{await API.post('/api/incidents/'+id+'/resolve',{resolution:'Resolved'});si(p=>p.map(i=>i.id===id?{...i,status:'resolved'}:i))}catch{}};
    const sb={ongoing:'badge-down',resolved:'badge-up',acknowledged:'badge-pending'};
    return(<div className="safe-bottom content-top" style={{padding:20}}>
        <h1 style={{fontSize:24,fontWeight:900,marginBottom:16}}>Incidents</h1>
        <div style={{display:'flex',gap:8,marginBottom:16,overflowX:'auto',paddingBottom:8}}>{['','ongoing','acknowledged','resolved'].map(x=>(<button key={x} onClick={()=>sf(x)} className={'btn btn-sm '+(f===x?'btn-primary':'btn-ghost')}>{x||'All'}</button>))}</div>
        {ld?<div className="skeleton" style={{height:80}}/>:inc.length===0?<div style={{textAlign:'center',color:'#475569',padding:'60px 0'}}><p style={{fontSize:40}}>✅</p><p style={{marginTop:8}}>All clear!</p></div>:
        inc.map(i=><div key={i.id} className="card card-glow anim-up" style={{padding:18,marginBottom:14}}>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:8}}>
                <div style={{flex:1,minWidth:0}}><h3 style={{fontSize:14,fontWeight:700}}>{i.title}</h3><p style={{fontSize:11,color:'#64748b',marginTop:4}}>{new Date(i.started_at).toLocaleString()}</p></div>
                <span className={'badge '+(sb[i.status]||'')}>{i.status}</span>
            </div>
            {i.status==='ongoing'&&<div style={{display:'flex',gap:8,marginTop:12}}>
                <button className="btn btn-amber btn-sm" style={{flex:1}} onClick={()=>ack(i.id)}>Acknowledge</button>
                <button className="btn btn-success btn-sm" style={{flex:1}} onClick={()=>res(i.id)}>Resolve</button>
            </div>}
            {i.duration_seconds!=null&&<p style={{fontSize:11,color:'#64748b',marginTop:8}}>Duration: {Math.round(i.duration_seconds/60)}min</p>}
        </div>)}
    </div>);
}

// Admin
function Admin(){
    const{user}=useApp();const[tab,st]=useState('stats');const[ss,sss]=useState(null);const[us,sus]=useState([]);const[al,sal]=useState([]);const[se,sse]=useState([]);const[ld,sld]=useState(true);
    const sa=user?.role==='superadmin';
    useEffect(()=>{Promise.all([API.get('/api/admin/system-stats').catch(()=>null),API.get('/api/admin/users').catch(()=>[]),API.get('/api/admin/audit-logs?limit=30').catch(()=>[]),API.get('/api/admin/settings').catch(()=>[])]).then(([a,b,c,d])=>{sss(a);sus(b||[]);sal(c||[]);sse(d||[]);sld(false)})},[]);
    const tog=async id=>{try{await API.post('/api/admin/users/'+id+'/toggle-active');sus(await API.get('/api/admin/users')||[])}catch(e){alert(e.message)}};
    const del=async id=>{if(!confirm('Delete?'))return;try{await API.del('/api/admin/users/'+id);sus(p=>p.filter(u=>u.id!==id))}catch(e){alert(e.message)}};
    const imp=async id=>{try{const d=await API.post('/api/admin/impersonate/'+id);alert('Token: '+d.token.substring(0,25)+'...')}catch(e){alert(e.message)}};
    if(ld)return<div className="safe-bottom content-top" style={{padding:20}}><div className="skeleton" style={{height:120,marginBottom:16}}/><div className="skeleton" style={{height:120}}/></div>;
    return(<div className="safe-bottom content-top" style={{padding:20}}>
        <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:16}}><I.Shield/><h1 style={{fontSize:24,fontWeight:900}}>{sa?'Super':''}Admin</h1></div>
        <div style={{display:'flex',gap:6,marginBottom:16,overflowX:'auto',paddingBottom:8}}>{['stats','users','audit','settings','tools'].map(t=>(<button key={t} onClick={()=>st(t)} className={'btn btn-sm '+(tab===t?'btn-primary':'btn-ghost')}>{t[0].toUpperCase()+t.slice(1)}</button>))}</div>

        {tab==='stats'&&ss&&<div style={{display:'flex',flexDirection:'column',gap:12}}>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
                <SC label="Users" value={ss.total_users} color="indigo"/><SC label="Monitors" value={ss.total_monitors} color="green"/>
                <SC label="Logs" value={ss.total_logs?.toLocaleString()} color="purple"/><SC label="Incidents" value={ss.active_incidents} color="red"/>
                <SC label="Sessions" value={ss.active_sessions} color="amber"/><SC label="DB" value={ss.database_size_mb+'MB'} color="indigo"/>
                <SC label="Cache" value={ss.cache_size} color="green"/><SC label="WS" value={ss.websocket_connections} color="purple"/>
            </div>
            <div className="card card-glow" style={{padding:18}}>
                <h3 style={{fontSize:13,fontWeight:700,marginBottom:14,color:'#94a3b8'}}>⚡ Quick Actions</h3>
                <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8}}>
                    {[['🔄 Run Checks',()=>API.post('/api/admin/scheduler/trigger'),'btn-ghost'],['🧹 Clear Cache',()=>API.post('/api/admin/cache/clear'),'btn-amber'],
                      ['💾 Backup DB',()=>API.post('/api/admin/database/backup'),'btn-success'],['🗜️ Vacuum',()=>API.post('/api/admin/database/vacuum'),'btn-ghost'],
                      ['📋 Rotate Logs',()=>API.post('/api/admin/logs/rotate',{days:90}),'btn-danger'],['💚 Health',()=>API.get('/api/admin/health'),'btn-success']
                    ].map(([l,fn,c],i)=>(<button key={i} className={'btn btn-sm '+c} onClick={async()=>{try{const d=await fn();alert(JSON.stringify(d,null,2))}catch(e){alert(e.message)}}}>{l}</button>))}
                </div>
            </div>
        </div>}

        {tab==='users'&&<div style={{display:'flex',flexDirection:'column',gap:10}}>{us.map(u=><div key={u.id} className="card anim-up" style={{padding:16}}>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
                <div><div style={{display:'flex',alignItems:'center',gap:8,marginBottom:4}}><span style={{fontWeight:700,fontSize:14}}>{u.username}</span><span className={'badge '+(u.role==='superadmin'?'badge-sa':u.role==='admin'?'badge-admin':'badge-user')}>{u.role}</span></div><p style={{fontSize:11,color:'#64748b'}}>{u.email||'No email'} · {u.last_login?new Date(u.last_login).toLocaleDateString():'Never'}</p></div>
                <div style={{width:10,height:10,borderRadius:5,background:u.is_active?'#22c55e':'#ef4444'}}/>
            </div>
            {sa&&u.role!=='superadmin'&&<div style={{display:'flex',gap:6,marginTop:12}}>
                <button className="btn btn-ghost btn-sm" style={{flex:1}} onClick={()=>tog(u.id)}>{u.is_active?'Disable':'Enable'}</button>
                <button className="btn btn-ghost btn-sm" style={{flex:1}} onClick={()=>imp(u.id)}>👤 Impersonate</button>
                <button className="btn btn-danger btn-sm" onClick={()=>del(u.id)}><I.Trash/></button>
            </div>}
        </div>)}</div>}

        {tab==='audit'&&<div style={{display:'flex',flexDirection:'column',gap:6}}>{al.map(l=><div key={l.id} className="card" style={{padding:14}}>
            <div style={{display:'flex',justifyContent:'space-between'}}><div><span className="badge badge-admin" style={{marginRight:8}}>{l.action}</span><span style={{fontSize:11,color:'#64748b'}}>by {l.username}</span></div><span style={{fontSize:10,color:'#475569'}}>{new Date(l.created_at).toLocaleTimeString()}</span></div>
            {l.resource_type&&<p style={{fontSize:11,color:'#475569',marginTop:4}}>{l.resource_type} #{l.resource_id}</p>}
        </div>)}</div>}

        {tab==='settings'&&<div style={{display:'flex',flexDirection:'column',gap:6}}>{se.map(s=><div key={s.id} className="card" style={{padding:14,display:'flex',justifyContent:'space-between',alignItems:'center'}}>
            <div><p style={{fontSize:13,fontWeight:600}}>{s.key}</p><p style={{fontSize:10,color:'#475569'}}>{s.category}</p></div>
            <span style={{fontSize:11,color:'#818cf8',fontFamily:'monospace',maxWidth:120,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{s.value||'(empty)'}</span>
        </div>)}</div>}

        {tab==='tools'&&<div style={{display:'flex',flexDirection:'column',gap:12}}>
            <div className="card card-glow" style={{padding:18}}>
                <h3 style={{fontSize:13,fontWeight:700,marginBottom:12,color:'#94a3b8'}}>📊 Analytics</h3>
                <div style={{display:'flex',flexDirection:'column',gap:6}}>
                    {[['📈 Uptime Heatmap','/api/admin/analytics/uptime-heatmap'],['⚡ Latency','/api/admin/analytics/latency'],['🔴 Incident Stats','/api/admin/analytics/incident-stats'],['❌ Error Breakdown','/api/admin/analytics/error-breakdown']].map(([l,u],i)=>(
                        <button key={i} className="btn btn-ghost btn-sm" style={{justifyContent:'space-between'}} onClick={async()=>{const d=await API.get(u);alert(JSON.stringify(d,null,2))}}>{l}<I.ChevR/></button>
                    ))}
                </div>
            </div>
            <div className="card card-glow" style={{padding:18}}>
                <h3 style={{fontSize:13,fontWeight:700,marginBottom:12,color:'#94a3b8'}}>📋 All Features</h3>
                <button className="btn btn-ghost btn-sm" style={{width:'100%'}} onClick={async()=>{const d=await API.get('/api/admin/features');alert('Total: '+d.total+'\n\n'+d.features.map(f=>'#'+f.id+' '+f.name+' ['+f.category+']').join('\n'))}}>View 70+ Features</button>
            </div>
        </div>}
    </div>);
}

// Settings
function Settings(){
    const{user,logout}=useApp();const[p,sp]=useState(null);
    useEffect(()=>{API.get('/api/auth/me').then(sp).catch(()=>{})},[]);
    return(<div className="safe-bottom content-top" style={{padding:20}}>
        <h1 style={{fontSize:24,fontWeight:900,marginBottom:16}}>Settings</h1>
        {p&&<div className="card card-glow" style={{padding:20,marginBottom:16}}>
            <div style={{display:'flex',alignItems:'center',gap:16,marginBottom:16}}>
                <div style={{width:56,height:56,borderRadius:28,background:'linear-gradient(135deg,#6366f1,#a78bfa)',display:'flex',alignItems:'center',justifyContent:'center',fontSize:22,fontWeight:900,boxShadow:'0 4px 20px rgba(99,102,241,0.3)'}}>{p.username?.[0]?.toUpperCase()}</div>
                <div><h2 style={{fontWeight:800,fontSize:18}}>{p.username}</h2><p style={{fontSize:12,color:'#64748b'}}>{p.email||'No email'}</p><span className={'badge '+(p.role==='superadmin'?'badge-sa':'badge-admin')} style={{marginTop:4,display:'inline-block'}}>{p.role}</span></div>
            </div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
                <div style={{background:'rgba(15,23,42,0.5)',borderRadius:14,padding:12}}><p style={{fontSize:10,color:'#64748b',fontWeight:600}}>LAST LOGIN</p><p style={{fontSize:12,fontWeight:600,marginTop:4}}>{p.last_login?new Date(p.last_login).toLocaleDateString():'N/A'}</p></div>
                <div style={{background:'rgba(15,23,42,0.5)',borderRadius:14,padding:12}}><p style={{fontSize:10,color:'#64748b',fontWeight:600}}>2FA</p><p style={{fontSize:12,fontWeight:600,marginTop:4}}>{p.totp_enabled?'✅ Enabled':'❌ Off'}</p></div>
            </div>
        </div>}
        <div style={{display:'flex',flexDirection:'column',gap:8}}>
            <button className="card" style={{padding:16,display:'flex',justifyContent:'space-between',alignItems:'center',border:'none',cursor:'pointer',textAlign:'left',color:'#e2e8f0'}} onClick={async()=>{try{const d=await API.post('/api/auth/regenerate-api-key');alert('New key: '+d.api_key)}catch(e){alert(e.message)}}}>
                <span style={{fontSize:14,fontWeight:600}}>🔑 Regenerate API Key</span><I.ChevR/>
            </button>
            <button className="card" style={{padding:16,display:'flex',justifyContent:'space-between',alignItems:'center',border:'none',cursor:'pointer',textAlign:'left',color:'#e2e8f0'}} onClick={async()=>{try{const d=await API.post('/api/auth/setup-2fa');alert('Secret: '+d.secret+'\nURI: '+d.uri)}catch(e){alert(e.message)}}}>
                <span style={{fontSize:14,fontWeight:600}}>🔐 Setup 2FA</span><I.ChevR/>
            </button>
            <button className="card" style={{padding:16,display:'flex',justifyContent:'space-between',alignItems:'center',border:'none',cursor:'pointer',textAlign:'left',color:'#fca5a5'}} onClick={logout}>
                <span style={{fontSize:14,fontWeight:600,display:'flex',alignItems:'center',gap:8}}><I.Logout/>Logout</span><I.ChevR/>
            </button>
        </div>
    </div>);
}

// Bottom Nav
function Nav({active,onChange,isAdmin}){
    const items=[{id:'dash',l:'Home',i:I.Home},{id:'monitors',l:'Monitors',i:I.Monitor},{id:'incidents',l:'Alerts',i:I.Bell},...(isAdmin?[{id:'admin',l:'Admin',i:I.Shield}]:[]),{id:'settings',l:'Settings',i:I.Gear}];
    return(<div className="bottom-nav glass"><div style={{display:'flex',justifyContent:'space-around',alignItems:'center',height:'100%',maxWidth:500,margin:'0 auto'}}>
        {items.map(it=>{const Icon=it.i;const a=active===it.id;return(<button key={it.id} onClick={()=>onChange(it.id)} style={{display:'flex',flexDirection:'column',alignItems:'center',gap:3,padding:'8px 12px',background:'none',border:'none',cursor:'pointer',color:a?'#a5b4fc':'#475569',transition:'all 0.2s'}}>
            <Icon/><span style={{fontSize:10,fontWeight:a?700:500}}>{it.l}</span>{a&&<div style={{width:4,height:4,borderRadius:2,background:'#6366f1'}}/>}
        </button>)})}
    </div></div>);
}

// App
function App(){
    const[user,setUser]=useState(null);const[page,setPage]=useState('dash');const[ld,sld]=useState(true);
    useEffect(()=>{if(API.token){API.get('/api/auth/me').then(u=>{setUser(u);sld(false)}).catch(()=>{API.setToken(null);sld(false)})}else sld(false)},[]);
    useEffect(()=>{if(!user)return;try{const p=location.protocol==='https:'?'wss':'ws';const w=new WebSocket(p+'://'+location.host+'/ws?token='+API.token);w.onopen=()=>console.log('WS ok');const t=setInterval(()=>{if(w.readyState===1)w.send('{"type":"ping"}')},30000);return()=>{clearInterval(t);w.close()}}catch{}},[user]);
    const logout=()=>{API.setToken(null);setUser(null);setPage('dash');const a=document.getElementById('bg-music');if(a)a.pause()};
    const isAdmin=user?.role==='admin'||user?.role==='superadmin';
    if(ld)return<div className="app-wrap" style={{minHeight:'100vh',display:'flex',alignItems:'center',justifyContent:'center'}}><div className="skeleton" style={{width:64,height:64,borderRadius:20}}/></div>;
    if(!user)return<><MusicBar/><Login onLogin={setUser}/></>;
    return(<Ctx.Provider value={{user,setUser,logout}}><div className="app-wrap" style={{minHeight:'100vh'}}>
        <MusicBar/>
        {page==='dash'&&<Dash/>}{page==='monitors'&&<Monitors/>}{page==='incidents'&&<Incidents/>}{page==='admin'&&isAdmin&&<Admin/>}{page==='settings'&&<Settings/>}
        <Nav active={page} onChange={setPage} isAdmin={isAdmin}/>
    </div></Ctx.Provider>);
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
</script>
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
async def serve(): return HTMLResponse(FRONTEND)

@app.get("/app", response_class=HTMLResponse)
async def serve_app(): return HTMLResponse(FRONTEND)

@app.get("/api/health")
async def health_public():
    return JSONResponse({"status": "healthy", "app": config.APP_NAME, "version": config.APP_VERSION, "database": "postgresql" if "postgresql" in config.DATABASE_URL else "sqlite"})

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    print(f"\n{'='*60}\n  MonitorPro SaaS v3.0 Premium\n  http://localhost:{port}\n  SuperAdmin: {config.SUPERADMIN_USERNAME} / {config.SUPERADMIN_PASSWORD}\n  Docs: http://localhost:{port}/docs\n{'='*60}\n")
    uvicorn.run(app, host=config.HOST, port=port, log_level="info")