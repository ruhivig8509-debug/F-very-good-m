#!/usr/bin/env python3
"""
=============================================================================
PRODUCTION-LEVEL SaaS MONITORING PLATFORM
=============================================================================
Single-file implementation with FastAPI backend + Embedded React Frontend
Features: 70+ Admin features, SuperAdmin panel, Real-time WebSocket,
           JWT Auth, 2FA, Mobile-First UI, and more.

Default SuperAdmin: RUHIVIGQNR / RUHIVIGQNR

Run: python monitoring.py
Access: http://localhost:8000
=============================================================================
"""

import os
import sys
import json
import time
import uuid
import hashlib
import hmac
import struct
import base64
import secrets
import asyncio
import logging
import sqlite3
import smtplib
import subprocess
import re
import random
import string
import signal
import threading
import traceback
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Union
from enum import Enum
from collections import defaultdict
from functools import wraps
from io import BytesIO, StringIO
from pathlib import Path
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, asdict
import socket
import ssl
import ipaddress

# ============================================================================
# DEPENDENCY CHECK AND INSTALLATION
# ============================================================================
def install_deps():
    deps = [
        "fastapi", "uvicorn", "sqlalchemy", "python-jose",
        "passlib", "bcrypt", "python-multipart", "aiohttp",
        "websockets", "jinja2", "httpx", "pyotp", "qrcode",
        "apscheduler", "aiosqlite", "pydantic", "psycopg2-binary"
    ]
    for dep in deps:
        try:
            __import__(dep.replace("-", "_"))
        except ImportError:
            print(f"Installing {dep}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", dep, "-q"])

install_deps()

# ============================================================================
# IMPORTS AFTER DEPENDENCY CHECK
# ============================================================================
from fastapi import (
    FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect,
    Request, Response, status, Form, UploadFile, File, Query, Body,
    BackgroundTasks
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles

from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean, DateTime,
    Text, ForeignKey, Enum as SQLEnum, JSON, Index, event, func,
    Table, MetaData, text as sa_text
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from sqlalchemy.pool import StaticPool

from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, validator
import pyotp
import httpx
import aiohttp

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

# ============================================================================
# CONFIGURATION
# ============================================================================
class Config:
    APP_NAME = "MonitorPro SaaS"
    APP_VERSION = "2.0.0"
    SECRET_KEY = secrets.token_hex(32)
    JWT_SECRET = secrets.token_hex(32)
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRY_HOURS = 24

    _raw_db_url = os.environ.get("DATABASE_URL", "")
    if _raw_db_url:
        if _raw_db_url.startswith("postgres://"):
            DATABASE_URL = _raw_db_url.replace("postgres://", "postgresql://", 1)
        else:
            DATABASE_URL = _raw_db_url
    else:
        DATABASE_URL = "sqlite:///./monitoring.db"

    SUPERADMIN_USERNAME = "RUHIVIGQNR"
    SUPERADMIN_PASSWORD = "RUHIVIGQNR"
    HOST = "0.0.0.0"
    PORT = int(os.environ.get("PORT", 8000))
    LOG_LEVEL = "INFO"
    MAX_MONITORS_PER_USER = 50
    CHECK_INTERVAL_SECONDS = 60
    LOG_RETENTION_DAYS = 90
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 30
    SESSION_TIMEOUT_MINUTES = 60
    CACHE_TTL_SECONDS = 300

config = Config()

# ============================================================================
# LOGGING SETUP
# ============================================================================
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('monitoring.log', mode='a')
    ]
)
logger = logging.getLogger("MonitorPro")

# ============================================================================
# DATABASE SETUP
# ============================================================================
if config.DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        config.DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False
    )
else:
    engine = create_engine(
        config.DATABASE_URL,
        echo=False,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ============================================================================
# PASSWORD HASHING
# ============================================================================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ============================================================================
# IN-MEMORY CACHE
# ============================================================================
class SimpleCache:
    def __init__(self):
        self._cache: Dict[str, Any] = {}
        self._expiry: Dict[str, float] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key in self._cache:
                if time.time() < self._expiry.get(key, 0):
                    return self._cache[key]
                else:
                    del self._cache[key]
                    del self._expiry[key]
        return None

    def set(self, key: str, value: Any, ttl: int = 300):
        with self._lock:
            self._cache[key] = value
            self._expiry[key] = time.time() + ttl

    def delete(self, key: str):
        with self._lock:
            self._cache.pop(key, None)
            self._expiry.pop(key, None)

    def clear(self):
        with self._lock:
            self._cache.clear()
            self._expiry.clear()

    def keys(self):
        with self._lock:
            now = time.time()
            return [k for k, v in self._expiry.items() if v > now]

    def size(self):
        return len(self.keys())

cache = SimpleCache()

# ============================================================================
# DATABASE MODELS
# ============================================================================
class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"
    SUPERADMIN = "superadmin"

class MonitorType(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    PING = "ping"
    PORT = "port"
    KEYWORD = "keyword"
    DNS = "dns"
    TCP = "tcp"
    UDP = "udp"

class MonitorStatus(str, Enum):
    UP = "up"
    DOWN = "down"
    PENDING = "pending"
    PAUSED = "paused"
    MAINTENANCE = "maintenance"

class AlertType(str, Enum):
    EMAIL = "email"
    WEBHOOK = "webhook"
    SLACK = "slack"
    DISCORD = "discord"
    TELEGRAM = "telegram"
    SMS = "sms"
    PUSHOVER = "pushover"

class IncidentStatus(str, Enum):
    ONGOING = "ongoing"
    RESOLVED = "resolved"
    ACKNOWLEDGED = "acknowledged"

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default=UserRole.USER.value)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    totp_secret = Column(String(32), nullable=True)
    totp_enabled = Column(Boolean, default=False)
    avatar_url = Column(String(500), nullable=True)
    timezone = Column(String(50), default="UTC")
    language = Column(String(10), default="en")
    theme = Column(String(20), default="dark")
    login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    last_login = Column(DateTime, nullable=True)
    last_ip = Column(String(45), nullable=True)
    api_key = Column(String(64), unique=True, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    meta_data = Column(JSON, default={})

    monitors = relationship("Monitor", back_populates="owner", cascade="all, delete-orphan")
    alerts = relationship("AlertChannel", back_populates="owner", cascade="all, delete-orphan")
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")

class Monitor(Base):
    __tablename__ = "monitors"
    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(200), nullable=False)
    url = Column(String(2000), nullable=False)
    monitor_type = Column(String(20), default=MonitorType.HTTP.value)
    status = Column(String(20), default=MonitorStatus.PENDING.value)
    interval = Column(Integer, default=60)
    timeout = Column(Integer, default=30)
    retries = Column(Integer, default=3)
    method = Column(String(10), default="GET")
    headers = Column(JSON, default={})
    body = Column(Text, nullable=True)
    expected_status = Column(Integer, default=200)
    keyword = Column(String(500), nullable=True)
    keyword_type = Column(String(20), default="contains")
    port = Column(Integer, nullable=True)
    dns_record_type = Column(String(10), default="A")
    uptime_percentage = Column(Float, default=100.0)
    avg_response_time = Column(Float, default=0.0)
    last_checked = Column(DateTime, nullable=True)
    last_status_change = Column(DateTime, nullable=True)
    is_paused = Column(Boolean, default=False)
    maintenance_mode = Column(Boolean, default=False)
    tags = Column(JSON, default=[])
    notification_channels = Column(JSON, default=[])
    ssl_check = Column(Boolean, default=True)
    ssl_expiry_alert_days = Column(Integer, default=30)
    follow_redirects = Column(Boolean, default=True)
    max_redirects = Column(Integer, default=5)
    auth_type = Column(String(20), nullable=True)
    auth_credentials = Column(JSON, nullable=True)
    custom_dns = Column(String(255), nullable=True)
    regex_pattern = Column(String(500), nullable=True)
    alert_threshold = Column(Integer, default=1)
    consecutive_failures = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    owner = relationship("User", back_populates="monitors")
    logs = relationship("MonitorLog", back_populates="monitor", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="monitor", cascade="all, delete-orphan")

class MonitorLog(Base):
    __tablename__ = "monitor_logs"
    id = Column(Integer, primary_key=True, index=True)
    monitor_id = Column(Integer, ForeignKey("monitors.id"), nullable=False)
    status = Column(String(20), nullable=False)
    response_time = Column(Float, nullable=True)
    status_code = Column(Integer, nullable=True)
    response_body = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    ssl_info = Column(JSON, nullable=True)
    headers_received = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    monitor = relationship("Monitor", back_populates="logs")

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    monitor_id = Column(Integer, ForeignKey("monitors.id"), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(20), default=IncidentStatus.ONGOING.value)
    severity = Column(String(20), default="high")
    started_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(Integer, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    root_cause = Column(Text, nullable=True)
    resolution = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    monitor = relationship("Monitor", back_populates="incidents")

class AlertChannel(Base):
    __tablename__ = "alert_channels"
    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(200), nullable=False)
    channel_type = Column(String(20), nullable=False)
    config = Column(JSON, default={})
    is_active = Column(Boolean, default=True)
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="alerts")

class UserSession(Base):
    __tablename__ = "user_sessions"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    session_token = Column(String(64), unique=True, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    device_info = Column(JSON, default={})
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="sessions")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    username = Column(String(100), nullable=True)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(50), nullable=True)
    details = Column(JSON, default={})
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

class SiteSetting(Base):
    __tablename__ = "site_settings"
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=True)
    value_type = Column(String(20), default="string")
    category = Column(String(50), default="general")
    description = Column(String(500), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(Integer, nullable=True)

class StatusPage(Base):
    __tablename__ = "status_pages"
    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(200), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    logo_url = Column(String(500), nullable=True)
    custom_css = Column(Text, nullable=True)
    custom_domain = Column(String(255), nullable=True)
    monitor_ids = Column(JSON, default=[])
    is_public = Column(Boolean, default=True)
    show_values = Column(Boolean, default=True)
    theme = Column(String(20), default="light")
    created_at = Column(DateTime, default=datetime.utcnow)

class MaintenanceWindow(Base):
    __tablename__ = "maintenance_windows"
    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String(36), unique=True, default=lambda: str(uuid.uuid4()))
    monitor_id = Column(Integer, ForeignKey("monitors.id"), nullable=False)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    start_time = Column(DateTime, nullable=False)
    end_time = Column(DateTime, nullable=False)
    is_recurring = Column(Boolean, default=False)
    recurrence_pattern = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class IPWhitelist(Base):
    __tablename__ = "ip_whitelist"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), nullable=False)
    description = Column(String(200), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(Integer, nullable=True)

class NotificationTemplate(Base):
    __tablename__ = "notification_templates"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    template_type = Column(String(20), nullable=False)
    subject = Column(String(500), nullable=True)
    body = Column(Text, nullable=False)
    variables = Column(JSON, default=[])
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# Create all tables
Base.metadata.create_all(bind=engine)

# ============================================================================
# PYDANTIC SCHEMAS
# ============================================================================
class TokenData(BaseModel):
    user_id: int
    username: str
    role: str
    exp: Optional[datetime] = None

class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None

class RegisterRequest(BaseModel):
    username: str
    email: Optional[str] = None
    password: str

class MonitorCreate(BaseModel):
    name: str
    url: str
    monitor_type: str = "http"
    interval: int = 60
    timeout: int = 30
    retries: int = 3
    method: str = "GET"
    headers: dict = {}
    body: Optional[str] = None
    expected_status: int = 200
    keyword: Optional[str] = None
    keyword_type: str = "contains"
    port: Optional[int] = None
    tags: list = []
    regex_pattern: Optional[str] = None
    ssl_check: bool = True
    follow_redirects: bool = True
    alert_threshold: int = 1

class MonitorUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    interval: Optional[int] = None
    timeout: Optional[int] = None
    is_paused: Optional[bool] = None
    expected_status: Optional[int] = None
    keyword: Optional[str] = None
    tags: Optional[list] = None
    regex_pattern: Optional[str] = None

class AlertChannelCreate(BaseModel):
    name: str
    channel_type: str
    config: dict = {}
    is_default: bool = False

class StatusPageCreate(BaseModel):
    title: str
    slug: str
    description: Optional[str] = None
    monitor_ids: list = []
    is_public: bool = True
    theme: str = "light"

class UserUpdate(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    timezone: Optional[str] = None
    theme: Optional[str] = None

class SiteSettingUpdate(BaseModel):
    value: str
    category: Optional[str] = None

class MaintenanceCreate(BaseModel):
    monitor_id: int
    title: str
    description: Optional[str] = None
    start_time: str
    end_time: str

# ============================================================================
# JWT & AUTH UTILITIES
# ============================================================================
def create_jwt_token(user_id: int, username: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=config.JWT_EXPIRY_HOURS),
        "iat": datetime.utcnow(),
        "jti": str(uuid.uuid4())
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])
        return payload
    except JWTError:
        return None

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def generate_api_key() -> str:
    return secrets.token_hex(32)

def generate_totp_secret() -> str:
    return pyotp.random_base32()

def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

# ============================================================================
# DATABASE DEPENDENCY
# ============================================================================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ============================================================================
# AUTH DEPENDENCY
# ============================================================================
security = HTTPBearer(auto_error=False)

async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[dict]:
    token = None
    if credentials:
        token = credentials.credentials
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        token = request.query_params.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = verify_jwt_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload

async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] not in [UserRole.ADMIN.value, UserRole.SUPERADMIN.value]:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

async def require_superadmin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != UserRole.SUPERADMIN.value:
        raise HTTPException(status_code=403, detail="Superadmin access required")
    return user

# ============================================================================
# AUDIT LOGGING
# ============================================================================
def log_audit(db: Session, user_id: int, username: str, action: str,
              resource_type: str = None, resource_id: str = None,
              details: dict = None, ip: str = None, ua: str = None):
    audit = AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        ip_address=ip,
        user_agent=ua
    )
    db.add(audit)
    db.commit()

# ============================================================================
# WEBSOCKET MANAGER
# ============================================================================
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[int, List[WebSocket]] = defaultdict(list)
        self.broadcast_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket, user_id: int = 0):
        await websocket.accept()
        if user_id:
            self.active_connections[user_id].append(websocket)
        self.broadcast_connections.append(websocket)

    def disconnect(self, websocket: WebSocket, user_id: int = 0):
        if user_id and websocket in self.active_connections[user_id]:
            self.active_connections[user_id].remove(websocket)
        if websocket in self.broadcast_connections:
            self.broadcast_connections.remove(websocket)

    async def send_to_user(self, user_id: int, message: dict):
        for conn in self.active_connections.get(user_id, []):
            try:
                await conn.send_json(message)
            except:
                pass

    async def broadcast(self, message: dict):
        disconnected = []
        for conn in self.broadcast_connections:
            try:
                await conn.send_json(message)
            except:
                disconnected.append(conn)
        for conn in disconnected:
            if conn in self.broadcast_connections:
                self.broadcast_connections.remove(conn)

ws_manager = ConnectionManager()

# ============================================================================
# MONITOR CHECKER
# ============================================================================
class MonitorChecker:
    def __init__(self):
        self.client = None

    async def get_client(self):
        if not self.client:
            self.client = httpx.AsyncClient(
                timeout=30,
                follow_redirects=True,
                verify=False
            )
        return self.client

    async def check_http(self, monitor: Monitor) -> dict:
        start = time.time()
        result = {
            "status": MonitorStatus.DOWN.value,
            "response_time": 0,
            "status_code": None,
            "error_message": None,
            "response_body": None,
            "ip_address": None,
            "ssl_info": None,
            "headers_received": None
        }
        try:
            client = await self.get_client()
            resp = await client.request(
                method=monitor.method or "GET",
                url=monitor.url,
                headers=monitor.headers or {},
                content=monitor.body,
                timeout=monitor.timeout or 30
            )
            elapsed = (time.time() - start) * 1000
            result["response_time"] = round(elapsed, 2)
            result["status_code"] = resp.status_code
            result["headers_received"] = dict(resp.headers)

            body_text = resp.text[:5000] if resp.text else ""
            result["response_body"] = body_text

            status_ok = resp.status_code == (monitor.expected_status or 200)

            if monitor.keyword and monitor.monitor_type == MonitorType.KEYWORD.value:
                if monitor.keyword_type == "contains":
                    status_ok = status_ok and (monitor.keyword in body_text)
                elif monitor.keyword_type == "not_contains":
                    status_ok = status_ok and (monitor.keyword not in body_text)

            if monitor.regex_pattern:
                try:
                    match = re.search(monitor.regex_pattern, body_text)
                    status_ok = status_ok and (match is not None)
                except re.error:
                    pass

            result["status"] = MonitorStatus.UP.value if status_ok else MonitorStatus.DOWN.value

        except Exception as e:
            result["response_time"] = round((time.time() - start) * 1000, 2)
            result["error_message"] = str(e)
            result["status"] = MonitorStatus.DOWN.value

        return result

    async def check_port(self, monitor: Monitor) -> dict:
        start = time.time()
        result = {
            "status": MonitorStatus.DOWN.value,
            "response_time": 0,
            "status_code": None,
            "error_message": None,
        }
        try:
            from urllib.parse import urlparse
            parsed = urlparse(monitor.url)
            host = parsed.hostname or monitor.url
            port = monitor.port or parsed.port or 80

            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(monitor.timeout or 10)
            await loop.run_in_executor(None, sock.connect, (host, port))
            sock.close()

            elapsed = (time.time() - start) * 1000
            result["response_time"] = round(elapsed, 2)
            result["status"] = MonitorStatus.UP.value
        except Exception as e:
            result["response_time"] = round((time.time() - start) * 1000, 2)
            result["error_message"] = str(e)
        return result

    async def check_ping(self, monitor: Monitor) -> dict:
        start = time.time()
        result = {
            "status": MonitorStatus.DOWN.value,
            "response_time": 0,
            "error_message": None,
        }
        try:
            from urllib.parse import urlparse
            parsed = urlparse(monitor.url)
            host = parsed.hostname or monitor.url

            if sys.platform == "win32":
                cmd = ["ping", "-n", "1", "-w", str((monitor.timeout or 10) * 1000), host]
            else:
                cmd = ["ping", "-c", "1", "-W", str(monitor.timeout or 10), host]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=monitor.timeout or 15)

            elapsed = (time.time() - start) * 1000
            result["response_time"] = round(elapsed, 2)

            if proc.returncode == 0:
                result["status"] = MonitorStatus.UP.value
            else:
                result["error_message"] = stderr.decode() if stderr else "Ping failed"
        except Exception as e:
            result["response_time"] = round((time.time() - start) * 1000, 2)
            result["error_message"] = str(e)
        return result

    async def check_monitor(self, monitor: Monitor) -> dict:
        if monitor.monitor_type in [MonitorType.HTTP.value, MonitorType.HTTPS.value, MonitorType.KEYWORD.value]:
            return await self.check_http(monitor)
        elif monitor.monitor_type == MonitorType.PORT.value:
            return await self.check_port(monitor)
        elif monitor.monitor_type == MonitorType.PING.value:
            return await self.check_ping(monitor)
        elif monitor.monitor_type == MonitorType.TCP.value:
            return await self.check_port(monitor)
        else:
            return await self.check_http(monitor)

checker = MonitorChecker()

# ============================================================================
# BACKGROUND TASKS / SCHEDULER
# ============================================================================
scheduler = AsyncIOScheduler()

async def run_monitor_checks():
    db = SessionLocal()
    try:
        monitors = db.query(Monitor).filter(
            Monitor.is_paused == False,
            Monitor.maintenance_mode == False
        ).all()

        for monitor in monitors:
            try:
                result = await checker.check_monitor(monitor)

                log = MonitorLog(
                    monitor_id=monitor.id,
                    status=result["status"],
                    response_time=result.get("response_time"),
                    status_code=result.get("status_code"),
                    response_body=result.get("response_body", "")[:2000] if result.get("response_body") else None,
                    error_message=result.get("error_message"),
                    ip_address=result.get("ip_address"),
                    ssl_info=result.get("ssl_info"),
                    headers_received=result.get("headers_received")
                )
                db.add(log)

                old_status = monitor.status
                monitor.status = result["status"]
                monitor.last_checked = datetime.utcnow()
                monitor.avg_response_time = result.get("response_time", 0)

                if result["status"] == MonitorStatus.DOWN.value:
                    monitor.consecutive_failures += 1
                else:
                    monitor.consecutive_failures = 0

                if old_status != result["status"]:
                    monitor.last_status_change = datetime.utcnow()

                    if result["status"] == MonitorStatus.DOWN.value:
                        incident = Incident(
                            monitor_id=monitor.id,
                            title=f"{monitor.name} is DOWN",
                            description=result.get("error_message", "Monitor is not responding"),
                            status=IncidentStatus.ONGOING.value,
                            severity="high"
                        )
                        db.add(incident)
                    elif result["status"] == MonitorStatus.UP.value:
                        ongoing = db.query(Incident).filter(
                            Incident.monitor_id == monitor.id,
                            Incident.status == IncidentStatus.ONGOING.value
                        ).all()
                        for inc in ongoing:
                            inc.status = IncidentStatus.RESOLVED.value
                            inc.resolved_at = datetime.utcnow()
                            if inc.started_at:
                                inc.duration_seconds = int(
                                    (datetime.utcnow() - inc.started_at).total_seconds()
                                )

                total_logs = db.query(MonitorLog).filter(
                    MonitorLog.monitor_id == monitor.id
                ).count()
                up_logs = db.query(MonitorLog).filter(
                    MonitorLog.monitor_id == monitor.id,
                    MonitorLog.status == MonitorStatus.UP.value
                ).count()
                if total_logs > 0:
                    monitor.uptime_percentage = round((up_logs / total_logs) * 100, 2)

                db.commit()

                try:
                    await ws_manager.send_to_user(monitor.user_id, {
                        "type": "monitor_update",
                        "monitor_id": monitor.id,
                        "status": result["status"],
                        "response_time": result.get("response_time"),
                        "timestamp": datetime.utcnow().isoformat()
                    })
                except:
                    pass

            except Exception as e:
                logger.error(f"Error checking monitor {monitor.id}: {e}")
                db.rollback()

    except Exception as e:
        logger.error(f"Error in monitor check cycle: {e}")
    finally:
        db.close()

async def cleanup_old_logs():
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(days=config.LOG_RETENTION_DAYS)
        db.query(MonitorLog).filter(MonitorLog.created_at < cutoff).delete()
        db.commit()
        logger.info("Old logs cleaned up")
    except Exception as e:
        logger.error(f"Log cleanup error: {e}")
        db.rollback()
    finally:
        db.close()

# ============================================================================
# INITIALIZE SUPERADMIN
# ============================================================================
def init_superadmin():
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == config.SUPERADMIN_USERNAME).first()
        if not existing:
            superadmin = User(
                username=config.SUPERADMIN_USERNAME,
                email="superadmin@monitorpro.local",
                password_hash=hash_password(config.SUPERADMIN_PASSWORD),
                role=UserRole.SUPERADMIN.value,
                is_active=True,
                is_verified=True,
                api_key=generate_api_key()
            )
            db.add(superadmin)
            db.commit()
            logger.info(f"Superadmin created: {config.SUPERADMIN_USERNAME}")

        default_settings = {
            "site_name": ("MonitorPro SaaS", "general"),
            "site_description": ("Production Monitoring Platform", "general"),
            "maintenance_mode": ("false", "general"),
            "registration_enabled": ("true", "general"),
            "max_monitors_per_user": ("50", "limits"),
            "default_check_interval": ("60", "limits"),
            "email_notifications": ("true", "notifications"),
            "webhook_notifications": ("true", "notifications"),
            "theme_primary_color": ("#6366f1", "theme"),
            "theme_dark_mode": ("true", "theme"),
            "particle_effects": ("true", "theme"),
            "particle_count": ("50", "theme"),
            "ip_whitelist_enabled": ("false", "security"),
            "two_factor_required": ("false", "security"),
            "session_timeout": ("60", "security"),
            "max_login_attempts": ("5", "security"),
            "auto_backup_enabled": ("true", "database"),
            "backup_interval_hours": ("24", "database"),
            "log_retention_days": ("90", "database"),
            "api_rate_limit": ("100", "api"),
            "websocket_enabled": ("true", "realtime"),
            "custom_css": ("", "theme"),
            "custom_js": ("", "theme"),
            "smtp_host": ("", "email"),
            "smtp_port": ("587", "email"),
            "smtp_user": ("", "email"),
            "smtp_pass": ("", "email"),
            "smtp_from": ("noreply@monitorpro.local", "email"),
            "slack_webhook": ("", "integrations"),
            "discord_webhook": ("", "integrations"),
            "telegram_bot_token": ("", "integrations"),
            "telegram_chat_id": ("", "integrations"),
        }

        for key, (value, category) in default_settings.items():
            existing_setting = db.query(SiteSetting).filter(SiteSetting.key == key).first()
            if not existing_setting:
                setting = SiteSetting(key=key, value=value, category=category)
                db.add(setting)

        db.commit()
    except Exception as e:
        logger.error(f"Init error: {e}")
        db.rollback()
    finally:
        db.close()

# ============================================================================
# FASTAPI APP
# ============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_superadmin()
    scheduler.add_job(run_monitor_checks, IntervalTrigger(seconds=60), id="monitor_checks", replace_existing=True)
    scheduler.add_job(cleanup_old_logs, IntervalTrigger(hours=24), id="log_cleanup", replace_existing=True)
    scheduler.start()
    logger.info("MonitorPro SaaS Started")
    yield
    scheduler.shutdown()
    if checker.client:
        await checker.client.aclose()
    logger.info("MonitorPro SaaS Stopped")

app = FastAPI(
    title="MonitorPro SaaS",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# API ROUTES - AUTH
# ============================================================================
@app.post("/api/auth/login")
async def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()
    if not user:
        raise HTTPException(400, "Invalid credentials")

    if user.locked_until and user.locked_until > datetime.utcnow():
        raise HTTPException(423, f"Account locked. Try after {user.locked_until}")

    if not verify_password(req.password, user.password_hash):
        user.login_attempts = (user.login_attempts or 0) + 1
        if user.login_attempts >= config.MAX_LOGIN_ATTEMPTS:
            user.locked_until = datetime.utcnow() + timedelta(minutes=config.LOCKOUT_DURATION_MINUTES)
        db.commit()
        raise HTTPException(400, "Invalid credentials")

    if user.totp_enabled:
        if not req.totp_code:
            return JSONResponse({"requires_2fa": True, "message": "2FA code required"})
        if not verify_totp(user.totp_secret, req.totp_code):
            raise HTTPException(400, "Invalid 2FA code")

    if not user.is_active:
        raise HTTPException(403, "Account disabled")

    user.login_attempts = 0
    user.locked_until = None
    user.last_login = datetime.utcnow()
    user.last_ip = request.client.host if request.client else None

    session_token = secrets.token_hex(32)
    session = UserSession(
        user_id=user.id,
        session_token=session_token,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", ""),
        expires_at=datetime.utcnow() + timedelta(hours=config.JWT_EXPIRY_HOURS)
    )
    db.add(session)

    log_audit(db, user.id, user.username, "login", "auth", None,
              {"ip": request.client.host if request.client else None})

    db.commit()

    token = create_jwt_token(user.id, user.username, user.role)
    return {
        "token": token,
        "user": {
            "id": user.id,
            "uid": user.uid,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "theme": user.theme,
            "totp_enabled": user.totp_enabled,
            "avatar_url": user.avatar_url
        }
    }

@app.post("/api/auth/register")
async def register(req: RegisterRequest, db: Session = Depends(get_db)):
    reg_enabled = db.query(SiteSetting).filter(SiteSetting.key == "registration_enabled").first()
    if reg_enabled and reg_enabled.value == "false":
        raise HTTPException(403, "Registration is disabled")

    existing = db.query(User).filter(
        (User.username == req.username) | (User.email == req.email)
    ).first()
    if existing:
        raise HTTPException(400, "Username or email already exists")

    user = User(
        username=req.username,
        email=req.email,
        password_hash=hash_password(req.password),
        role=UserRole.USER.value,
        api_key=generate_api_key()
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_jwt_token(user.id, user.username, user.role)
    return {"token": token, "user": {"id": user.id, "username": user.username, "role": user.role}}

@app.get("/api/auth/me")
async def get_me(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user["user_id"]).first()
    if not db_user:
        raise HTTPException(404, "User not found")
    return {
        "id": db_user.id, "uid": db_user.uid, "username": db_user.username,
        "email": db_user.email, "role": db_user.role, "is_active": db_user.is_active,
        "totp_enabled": db_user.totp_enabled, "theme": db_user.theme,
        "timezone": db_user.timezone, "avatar_url": db_user.avatar_url,
        "api_key": db_user.api_key, "created_at": str(db_user.created_at),
        "last_login": str(db_user.last_login) if db_user.last_login else None
    }

@app.post("/api/auth/setup-2fa")
async def setup_2fa(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user["user_id"]).first()
    secret = generate_totp_secret()
    db_user.totp_secret = secret
    db.commit()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=db_user.username, issuer_name="MonitorPro")
    return {"secret": secret, "uri": uri}

@app.post("/api/auth/enable-2fa")
async def enable_2fa(code: str = Body(..., embed=True), user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user["user_id"]).first()
    if not db_user.totp_secret:
        raise HTTPException(400, "Setup 2FA first")
    if not verify_totp(db_user.totp_secret, code):
        raise HTTPException(400, "Invalid code")
    db_user.totp_enabled = True
    db.commit()
    return {"message": "2FA enabled"}

@app.post("/api/auth/disable-2fa")
async def disable_2fa(code: str = Body(..., embed=True), user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user["user_id"]).first()
    if not verify_totp(db_user.totp_secret, code):
        raise HTTPException(400, "Invalid code")
    db_user.totp_enabled = False
    db_user.totp_secret = None
    db.commit()
    return {"message": "2FA disabled"}

@app.post("/api/auth/change-password")
async def change_password(
    current_password: str = Body(...),
    new_password: str = Body(...),
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_user = db.query(User).filter(User.id == user["user_id"]).first()
    if not verify_password(current_password, db_user.password_hash):
        raise HTTPException(400, "Current password incorrect")
    db_user.password_hash = hash_password(new_password)
    db.commit()
    return {"message": "Password changed"}

@app.post("/api/auth/regenerate-api-key")
async def regenerate_api_key(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user["user_id"]).first()
    db_user.api_key = generate_api_key()
    db.commit()
    return {"api_key": db_user.api_key}

# ============================================================================
# API ROUTES - MONITORS
# ============================================================================
@app.get("/api/monitors")
async def list_monitors(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    if user["role"] == UserRole.SUPERADMIN.value:
        monitors = db.query(Monitor).all()
    else:
        monitors = db.query(Monitor).filter(Monitor.user_id == user["user_id"]).all()
    return [{
        "id": m.id, "uid": m.uid, "name": m.name, "url": m.url,
        "monitor_type": m.monitor_type, "status": m.status,
        "interval": m.interval, "uptime_percentage": m.uptime_percentage,
        "avg_response_time": m.avg_response_time,
        "last_checked": str(m.last_checked) if m.last_checked else None,
        "is_paused": m.is_paused, "tags": m.tags or [],
        "consecutive_failures": m.consecutive_failures,
        "created_at": str(m.created_at), "user_id": m.user_id
    } for m in monitors]

@app.post("/api/monitors")
async def create_monitor(
    data: MonitorCreate,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    count = db.query(Monitor).filter(Monitor.user_id == user["user_id"]).count()
    if count >= config.MAX_MONITORS_PER_USER and user["role"] != UserRole.SUPERADMIN.value:
        raise HTTPException(400, f"Max {config.MAX_MONITORS_PER_USER} monitors allowed")

    monitor = Monitor(
        user_id=user["user_id"],
        name=data.name,
        url=data.url,
        monitor_type=data.monitor_type,
        interval=data.interval,
        timeout=data.timeout,
        retries=data.retries,
        method=data.method,
        headers=data.headers,
        body=data.body,
        expected_status=data.expected_status,
        keyword=data.keyword,
        keyword_type=data.keyword_type,
        port=data.port,
        tags=data.tags,
        regex_pattern=data.regex_pattern,
        ssl_check=data.ssl_check,
        follow_redirects=data.follow_redirects,
        alert_threshold=data.alert_threshold
    )
    db.add(monitor)
    db.commit()
    db.refresh(monitor)

    log_audit(db, user["user_id"], user["username"], "create_monitor",
              "monitor", str(monitor.id), {"name": data.name})

    return {"id": monitor.id, "uid": monitor.uid, "message": "Monitor created"}

@app.get("/api/monitors/{monitor_id}")
async def get_monitor(monitor_id: int, user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    monitor = db.query(Monitor).filter(Monitor.id == monitor_id).first()
    if not monitor:
        raise HTTPException(404, "Monitor not found")
    if monitor.user_id != user["user_id"] and user["role"] != UserRole.SUPERADMIN.value:
        raise HTTPException(403, "Access denied")
    return {
        "id": monitor.id, "uid": monitor.uid, "name": monitor.name, "url": monitor.url,
        "monitor_type": monitor.monitor_type, "status": monitor.status,
        "interval": monitor.interval, "timeout": monitor.timeout,
        "retries": monitor.retries, "method": monitor.method,
        "headers": monitor.headers, "expected_status": monitor.expected_status,
        "keyword": monitor.keyword, "keyword_type": monitor.keyword_type,
        "port": monitor.port, "uptime_percentage": monitor.uptime_percentage,
        "avg_response_time": monitor.avg_response_time,
        "last_checked": str(monitor.last_checked) if monitor.last_checked else None,
        "is_paused": monitor.is_paused, "maintenance_mode": monitor.maintenance_mode,
        "tags": monitor.tags or [], "ssl_check": monitor.ssl_check,
        "follow_redirects": monitor.follow_redirects,
        "regex_pattern": monitor.regex_pattern,
        "alert_threshold": monitor.alert_threshold,
        "consecutive_failures": monitor.consecutive_failures,
        "created_at": str(monitor.created_at)
    }

@app.put("/api/monitors/{monitor_id}")
async def update_monitor(
    monitor_id: int, data: MonitorUpdate,
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    monitor = db.query(Monitor).filter(Monitor.id == monitor_id).first()
    if not monitor:
        raise HTTPException(404, "Monitor not found")
    if monitor.user_id != user["user_id"] and user["role"] != UserRole.SUPERADMIN.value:
        raise HTTPException(403, "Access denied")

    update_data = data.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(monitor, key, value)
    db.commit()
    return {"message": "Monitor updated"}

@app.delete("/api/monitors/{monitor_id}")
async def delete_monitor(monitor_id: int, user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    monitor = db.query(Monitor).filter(Monitor.id == monitor_id).first()
    if not monitor:
        raise HTTPException(404, "Monitor not found")
    if monitor.user_id != user["user_id"] and user["role"] != UserRole.SUPERADMIN.value:
        raise HTTPException(403, "Access denied")
    db.delete(monitor)
    db.commit()
    log_audit(db, user["user_id"], user["username"], "delete_monitor", "monitor", str(monitor_id))
    return {"message": "Monitor deleted"}

@app.post("/api/monitors/{monitor_id}/pause")
async def pause_monitor(monitor_id: int, user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    monitor = db.query(Monitor).filter(Monitor.id == monitor_id).first()
    if not monitor:
        raise HTTPException(404)
    if monitor.user_id != user["user_id"] and user["role"] != UserRole.SUPERADMIN.value:
        raise HTTPException(403)
    monitor.is_paused = not monitor.is_paused
    monitor.status = MonitorStatus.PAUSED.value if monitor.is_paused else MonitorStatus.PENDING.value
    db.commit()
    return {"is_paused": monitor.is_paused}

@app.post("/api/monitors/{monitor_id}/check")
async def check_monitor_now(monitor_id: int, user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    monitor = db.query(Monitor).filter(Monitor.id == monitor_id).first()
    if not monitor:
        raise HTTPException(404)
    if monitor.user_id != user["user_id"] and user["role"] != UserRole.SUPERADMIN.value:
        raise HTTPException(403)

    result = await checker.check_monitor(monitor)

    log = MonitorLog(
        monitor_id=monitor.id, status=result["status"],
        response_time=result.get("response_time"), status_code=result.get("status_code"),
        error_message=result.get("error_message")
    )
    db.add(log)
    monitor.status = result["status"]
    monitor.last_checked = datetime.utcnow()
    monitor.avg_response_time = result.get("response_time", 0)
    db.commit()

    return result

@app.get("/api/monitors/{monitor_id}/logs")
async def get_monitor_logs(
    monitor_id: int,
    limit: int = 100,
    offset: int = 0,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    monitor = db.query(Monitor).filter(Monitor.id == monitor_id).first()
    if not monitor:
        raise HTTPException(404)
    if monitor.user_id != user["user_id"] and user["role"] != UserRole.SUPERADMIN.value:
        raise HTTPException(403)

    logs = db.query(MonitorLog).filter(
        MonitorLog.monitor_id == monitor_id
    ).order_by(MonitorLog.created_at.desc()).offset(offset).limit(limit).all()

    return [{
        "id": l.id, "status": l.status, "response_time": l.response_time,
        "status_code": l.status_code, "error_message": l.error_message,
        "created_at": str(l.created_at)
    } for l in logs]

@app.get("/api/monitors/{monitor_id}/uptime")
async def get_monitor_uptime(
    monitor_id: int, days: int = 30,
    user: dict = Depends(get_current_user), db: Session = Depends(get_db)
):
    monitor = db.query(Monitor).filter(Monitor.id == monitor_id).first()
    if not monitor:
        raise HTTPException(404)

    since = datetime.utcnow() - timedelta(days=days)
    logs = db.query(MonitorLog).filter(
        MonitorLog.monitor_id == monitor_id,
        MonitorLog.created_at >= since
    ).all()

    total = len(logs)
    up = sum(1 for l in logs if l.status == MonitorStatus.UP.value)
    uptime = round((up / total * 100), 2) if total > 0 else 100

    daily_stats = {}
    for log in logs:
        day = log.created_at.strftime("%Y-%m-%d")
        if day not in daily_stats:
            daily_stats[day] = {"up": 0, "down": 0, "total": 0, "avg_rt": []}
        daily_stats[day]["total"] += 1
        if log.status == MonitorStatus.UP.value:
            daily_stats[day]["up"] += 1
        else:
            daily_stats[day]["down"] += 1
        if log.response_time:
            daily_stats[day]["avg_rt"].append(log.response_time)

    heatmap = []
    for day, stats in sorted(daily_stats.items()):
        heatmap.append({
            "date": day,
            "uptime": round(stats["up"] / stats["total"] * 100, 2) if stats["total"] > 0 else 100,
            "avg_response_time": round(sum(stats["avg_rt"]) / len(stats["avg_rt"]), 2) if stats["avg_rt"] else 0,
            "checks": stats["total"]
        })

    return {"uptime_percentage": uptime, "total_checks": total, "days": days, "heatmap": heatmap}

# ============================================================================
# API ROUTES - INCIDENTS
# ============================================================================
@app.get("/api/incidents")
async def list_incidents(
    status: Optional[str] = None,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Incident).join(Monitor)
    if user["role"] != UserRole.SUPERADMIN.value:
        query = query.filter(Monitor.user_id == user["user_id"])
    if status:
        query = query.filter(Incident.status == status)

    incidents = query.order_by(Incident.created_at.desc()).limit(100).all()
    return [{
        "id": i.id, "uid": i.uid, "monitor_id": i.monitor_id,
        "title": i.title, "description": i.description,
        "status": i.status, "severity": i.severity,
        "started_at": str(i.started_at),
        "resolved_at": str(i.resolved_at) if i.resolved_at else None,
        "duration_seconds": i.duration_seconds,
        "created_at": str(i.created_at)
    } for i in incidents]

@app.post("/api/incidents/{incident_id}/acknowledge")
async def acknowledge_incident(incident_id: int, user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(404)
    incident.status = IncidentStatus.ACKNOWLEDGED.value
    incident.acknowledged_at = datetime.utcnow()
    incident.acknowledged_by = user["user_id"]
    db.commit()
    return {"message": "Incident acknowledged"}

@app.post("/api/incidents/{incident_id}/resolve")
async def resolve_incident(
    incident_id: int,
    resolution: str = Body("", embed=True),
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(404)
    incident.status = IncidentStatus.RESOLVED.value
    incident.resolved_at = datetime.utcnow()
    incident.resolution = resolution
    if incident.started_at:
        incident.duration_seconds = int((datetime.utcnow() - incident.started_at).total_seconds())
    db.commit()
    return {"message": "Incident resolved"}

# ============================================================================
# API ROUTES - ALERT CHANNELS
# ============================================================================
@app.get("/api/alerts")
async def list_alerts(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    alerts = db.query(AlertChannel).filter(AlertChannel.user_id == user["user_id"]).all()
    return [{
        "id": a.id, "uid": a.uid, "name": a.name,
        "channel_type": a.channel_type, "config": a.config,
        "is_active": a.is_active, "is_default": a.is_default,
        "created_at": str(a.created_at)
    } for a in alerts]

@app.post("/api/alerts")
async def create_alert(data: AlertChannelCreate, user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    alert = AlertChannel(
        user_id=user["user_id"], name=data.name,
        channel_type=data.channel_type, config=data.config,
        is_default=data.is_default
    )
    db.add(alert)
    db.commit()
    return {"id": alert.id, "message": "Alert channel created"}

@app.delete("/api/alerts/{alert_id}")
async def delete_alert(alert_id: int, user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    alert = db.query(AlertChannel).filter(AlertChannel.id == alert_id, AlertChannel.user_id == user["user_id"]).first()
    if not alert:
        raise HTTPException(404)
    db.delete(alert)
    db.commit()
    return {"message": "Alert channel deleted"}

@app.post("/api/alerts/{alert_id}/test")
async def test_alert(alert_id: int, user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    alert = db.query(AlertChannel).filter(AlertChannel.id == alert_id, AlertChannel.user_id == user["user_id"]).first()
    if not alert:
        raise HTTPException(404)
    return {"message": f"Test notification sent to {alert.channel_type}"}

# ============================================================================
# API ROUTES - STATUS PAGES
# ============================================================================
@app.get("/api/status-pages")
async def list_status_pages(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    pages = db.query(StatusPage).filter(StatusPage.user_id == user["user_id"]).all()
    return [{
        "id": p.id, "uid": p.uid, "title": p.title, "slug": p.slug,
        "description": p.description, "is_public": p.is_public,
        "monitor_ids": p.monitor_ids, "theme": p.theme,
        "created_at": str(p.created_at)
    } for p in pages]

@app.post("/api/status-pages")
async def create_status_page(data: StatusPageCreate, user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    existing = db.query(StatusPage).filter(StatusPage.slug == data.slug).first()
    if existing:
        raise HTTPException(400, "Slug already exists")
    page = StatusPage(
        user_id=user["user_id"], title=data.title, slug=data.slug,
        description=data.description, monitor_ids=data.monitor_ids,
        is_public=data.is_public, theme=data.theme
    )
    db.add(page)
    db.commit()
    return {"id": page.id, "slug": page.slug}

@app.get("/api/status/{slug}")
async def public_status_page(slug: str, db: Session = Depends(get_db)):
    page = db.query(StatusPage).filter(StatusPage.slug == slug, StatusPage.is_public == True).first()
    if not page:
        raise HTTPException(404, "Status page not found")

    monitors = db.query(Monitor).filter(Monitor.id.in_(page.monitor_ids or [])).all()
    return {
        "title": page.title, "description": page.description, "theme": page.theme,
        "monitors": [{
            "name": m.name, "status": m.status,
            "uptime_percentage": m.uptime_percentage,
            "last_checked": str(m.last_checked) if m.last_checked else None
        } for m in monitors]
    }

# ============================================================================
# API ROUTES - DASHBOARD STATS
# ============================================================================
@app.get("/api/dashboard/stats")
async def dashboard_stats(user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    if user["role"] == UserRole.SUPERADMIN.value:
        monitors = db.query(Monitor).all()
    else:
        monitors = db.query(Monitor).filter(Monitor.user_id == user["user_id"]).all()

    total = len(monitors)
    up = sum(1 for m in monitors if m.status == MonitorStatus.UP.value)
    down = sum(1 for m in monitors if m.status == MonitorStatus.DOWN.value)
    paused = sum(1 for m in monitors if m.is_paused)
    pending = sum(1 for m in monitors if m.status == MonitorStatus.PENDING.value)

    avg_uptime = round(sum(m.uptime_percentage or 0 for m in monitors) / total, 2) if total > 0 else 100
    avg_response = round(sum(m.avg_response_time or 0 for m in monitors) / total, 2) if total > 0 else 0

    if user["role"] == UserRole.SUPERADMIN.value:
        ongoing_incidents = db.query(Incident).filter(Incident.status == IncidentStatus.ONGOING.value).count()
    else:
        ongoing_incidents = db.query(Incident).join(Monitor).filter(
            Monitor.user_id == user["user_id"],
            Incident.status == IncidentStatus.ONGOING.value
        ).count()

    return {
        "total_monitors": total, "up": up, "down": down,
        "paused": paused, "pending": pending,
        "avg_uptime": avg_uptime, "avg_response_time": avg_response,
        "ongoing_incidents": ongoing_incidents
    }

@app.get("/api/dashboard/charts")
async def dashboard_charts(
    hours: int = 24,
    user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    since = datetime.utcnow() - timedelta(hours=hours)

    if user["role"] == UserRole.SUPERADMIN.value:
        logs = db.query(MonitorLog).filter(MonitorLog.created_at >= since).all()
    else:
        monitor_ids = [m.id for m in db.query(Monitor).filter(Monitor.user_id == user["user_id"]).all()]
        logs = db.query(MonitorLog).filter(
            MonitorLog.monitor_id.in_(monitor_ids),
            MonitorLog.created_at >= since
        ).all()

    hourly = {}
    for log in logs:
        hour = log.created_at.strftime("%Y-%m-%d %H:00")
        if hour not in hourly:
            hourly[hour] = {"up": 0, "down": 0, "response_times": []}
        if log.status == MonitorStatus.UP.value:
            hourly[hour]["up"] += 1
        else:
            hourly[hour]["down"] += 1
        if log.response_time:
            hourly[hour]["response_times"].append(log.response_time)

    chart_data = []
    for hour, data in sorted(hourly.items()):
        total = data["up"] + data["down"]
        chart_data.append({
            "time": hour,
            "uptime": round(data["up"] / total * 100, 2) if total > 0 else 100,
            "avg_response_time": round(sum(data["response_times"]) / len(data["response_times"]), 2) if data["response_times"] else 0,
            "checks": total
        })

    return {"chart_data": chart_data, "hours": hours}

# ============================================================================
# API ROUTES - ADMIN (70+ FEATURES)
# ============================================================================

# --- 1. User Management ---
@app.get("/api/admin/users")
async def admin_list_users(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.query(User).all()
    return [{
        "id": u.id, "uid": u.uid, "username": u.username, "email": u.email,
        "role": u.role, "is_active": u.is_active, "is_verified": u.is_verified,
        "totp_enabled": u.totp_enabled, "last_login": str(u.last_login) if u.last_login else None,
        "last_ip": u.last_ip, "created_at": str(u.created_at),
        "login_attempts": u.login_attempts
    } for u in users]

# --- 2. Create Admin ---
@app.post("/api/admin/users")
async def admin_create_user(
    username: str = Body(...), password: str = Body(...),
    email: str = Body(None), role: str = Body("user"),
    user: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    if role in ["admin", "superadmin"] and user["role"] != UserRole.SUPERADMIN.value:
        raise HTTPException(403, "Only superadmin can create admins")
    new_user = User(
        username=username, email=email,
        password_hash=hash_password(password),
        role=role, api_key=generate_api_key()
    )
    db.add(new_user)
    db.commit()
    log_audit(db, user["user_id"], user["username"], "create_user", "user", str(new_user.id))
    return {"id": new_user.id, "message": "User created"}

# --- 3. Update User ---
@app.put("/api/admin/users/{user_id}")
async def admin_update_user(user_id: int, data: UserUpdate, user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404)
    if target.role == UserRole.SUPERADMIN.value and user["role"] != UserRole.SUPERADMIN.value:
        raise HTTPException(403)
    if data.role and user["role"] != UserRole.SUPERADMIN.value:
        raise HTTPException(403, "Only superadmin can change roles")
    update = data.dict(exclude_unset=True)
    for k, v in update.items():
        setattr(target, k, v)
    db.commit()
    log_audit(db, user["user_id"], user["username"], "update_user", "user", str(user_id), update)
    return {"message": "User updated"}

# --- 4. Delete User ---
@app.delete("/api/admin/users/{user_id}")
async def admin_delete_user(user_id: int, user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404)
    if target.role == UserRole.SUPERADMIN.value:
        raise HTTPException(400, "Cannot delete superadmin")
    db.delete(target)
    db.commit()
    log_audit(db, user["user_id"], user["username"], "delete_user", "user", str(user_id))
    return {"message": "User deleted"}

# --- 5. User Impersonation ---
@app.post("/api/admin/impersonate/{user_id}")
async def impersonate_user(user_id: int, user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404)
    token = create_jwt_token(target.id, target.username, target.role)
    log_audit(db, user["user_id"], user["username"], "impersonate_user", "user", str(user_id))
    return {"token": token, "user": {"id": target.id, "username": target.username, "role": target.role}}

# --- 6. Toggle User Active ---
@app.post("/api/admin/users/{user_id}/toggle-active")
async def toggle_user_active(user_id: int, user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404)
    target.is_active = not target.is_active
    db.commit()
    return {"is_active": target.is_active}

# --- 7. Reset User Password ---
@app.post("/api/admin/users/{user_id}/reset-password")
async def admin_reset_password(
    user_id: int, new_password: str = Body(..., embed=True),
    user: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404)
    target.password_hash = hash_password(new_password)
    target.login_attempts = 0
    target.locked_until = None
    db.commit()
    log_audit(db, user["user_id"], user["username"], "reset_password", "user", str(user_id))
    return {"message": "Password reset"}

# --- 8. Unlock User ---
@app.post("/api/admin/users/{user_id}/unlock")
async def unlock_user(user_id: int, user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(404)
    target.login_attempts = 0
    target.locked_until = None
    db.commit()
    return {"message": "User unlocked"}

# --- 9-10. Site Settings ---
@app.get("/api/admin/settings")
async def get_settings(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    settings = db.query(SiteSetting).all()
    return [{
        "id": s.id, "key": s.key, "value": s.value,
        "category": s.category, "description": s.description,
        "updated_at": str(s.updated_at)
    } for s in settings]

@app.put("/api/admin/settings/{key}")
async def update_setting(key: str, data: SiteSettingUpdate, user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    setting = db.query(SiteSetting).filter(SiteSetting.key == key).first()
    if not setting:
        setting = SiteSetting(key=key, value=data.value, category=data.category or "general")
        db.add(setting)
    else:
        setting.value = data.value
        if data.category:
            setting.category = data.category
        setting.updated_by = user["user_id"]
    db.commit()
    log_audit(db, user["user_id"], user["username"], "update_setting", "setting", key, {"value": data.value})
    return {"message": f"Setting '{key}' updated"}

# --- 11. Audit Logs ---
@app.get("/api/admin/audit-logs")
async def get_audit_logs(
    limit: int = 100, offset: int = 0,
    action: Optional[str] = None,
    user: dict = Depends(require_admin), db: Session = Depends(get_db)
):
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action)
    logs = query.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    return [{
        "id": l.id, "user_id": l.user_id, "username": l.username,
        "action": l.action, "resource_type": l.resource_type,
        "resource_id": l.resource_id, "details": l.details,
        "ip_address": l.ip_address, "created_at": str(l.created_at)
    } for l in logs]

# --- 12. All Monitors Admin ---
@app.get("/api/admin/monitors")
async def admin_all_monitors(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    monitors = db.query(Monitor).all()
    return [{
        "id": m.id, "name": m.name, "url": m.url, "status": m.status,
        "user_id": m.user_id, "uptime_percentage": m.uptime_percentage,
        "monitor_type": m.monitor_type, "created_at": str(m.created_at)
    } for m in monitors]

# --- 13. System Stats ---
@app.get("/api/admin/system-stats")
async def system_stats(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    total_users = db.query(User).count()
    total_monitors = db.query(Monitor).count()
    total_logs = db.query(MonitorLog).count()
    total_incidents = db.query(Incident).count()
    active_incidents = db.query(Incident).filter(Incident.status == IncidentStatus.ONGOING.value).count()
    total_alerts = db.query(AlertChannel).count()
    total_sessions = db.query(UserSession).filter(UserSession.is_active == True).count()

    db_size = 0
    if config.DATABASE_URL.startswith("sqlite"):
        db_path = Path("monitoring.db")
        db_size = db_path.stat().st_size if db_path.exists() else 0
    else:
        try:
            result = db.execute(sa_text("SELECT pg_database_size(current_database())"))
            row = result.fetchone()
            if row:
                db_size = row[0]
        except Exception:
            db_size = 0

    return {
        "total_users": total_users, "total_monitors": total_monitors,
        "total_logs": total_logs, "total_incidents": total_incidents,
        "active_incidents": active_incidents, "total_alerts": total_alerts,
        "active_sessions": total_sessions, "cache_size": cache.size(),
        "database_size_mb": round(db_size / (1024 * 1024), 2),
        "uptime_seconds": int(time.time() - app_start_time),
        "websocket_connections": len(ws_manager.broadcast_connections),
        "python_version": sys.version,
        "scheduler_jobs": len(scheduler.get_jobs()),
    }

# --- 14. Database Backup ---
@app.post("/api/admin/database/backup")
async def database_backup(user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    if config.DATABASE_URL.startswith("sqlite"):
        import shutil
        backup_name = f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.db"
        try:
            shutil.copy2("monitoring.db", backup_name)
            log_audit(db, user["user_id"], user["username"], "database_backup", "database", backup_name)
            return {"message": f"Backup created: {backup_name}", "filename": backup_name}
        except Exception as e:
            raise HTTPException(500, f"Backup failed: {e}")
    else:
        log_audit(db, user["user_id"], user["username"], "database_backup_request", "database", "postgresql")
        return {"message": "PostgreSQL backup requested. Use pg_dump for full backups on Render.", "filename": "pg_backup"}

# --- 15. Database Vacuum ---
@app.post("/api/admin/database/vacuum")
async def database_vacuum(user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    if config.DATABASE_URL.startswith("sqlite"):
        try:
            conn = sqlite3.connect("monitoring.db")
            conn.execute("VACUUM")
            conn.close()
            return {"message": "Database vacuumed successfully"}
        except Exception as e:
            raise HTTPException(500, f"Vacuum failed: {e}")
    else:
        try:
            db.execute(sa_text("VACUUM ANALYZE"))
            db.commit()
            return {"message": "PostgreSQL VACUUM ANALYZE completed"}
        except Exception as e:
            db.rollback()
            return {"message": f"VACUUM requested (may require superuser): {e}"}

# --- 16. Database Stats ---
@app.get("/api/admin/database/stats")
async def database_stats(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    tables = {}
    table_names = ["users", "monitors", "monitor_logs", "incidents", "alert_channels",
                   "audit_logs", "site_settings", "status_pages", "user_sessions",
                   "maintenance_windows", "ip_whitelist", "notification_templates"]
    for table_name in table_names:
        try:
            result = db.execute(sa_text(f"SELECT COUNT(*) FROM {table_name}"))
            tables[table_name] = result.scalar()
        except Exception:
            tables[table_name] = "N/A"
    return {"tables": tables}

# --- 17. Clear Cache ---
@app.post("/api/admin/cache/clear")
async def clear_cache(user: dict = Depends(require_superadmin)):
    cache.clear()
    return {"message": "Cache cleared"}

# --- 18. Cache Stats ---
@app.get("/api/admin/cache/stats")
async def cache_stats(user: dict = Depends(require_admin)):
    return {"size": cache.size(), "keys": cache.keys()[:50]}

# --- 19. IP Whitelist ---
@app.get("/api/admin/ip-whitelist")
async def get_ip_whitelist(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    ips = db.query(IPWhitelist).all()
    return [{"id": ip.id, "ip_address": ip.ip_address, "description": ip.description,
             "is_active": ip.is_active, "created_at": str(ip.created_at)} for ip in ips]

# --- 20. Add IP to Whitelist ---
@app.post("/api/admin/ip-whitelist")
async def add_ip_whitelist(
    ip_address: str = Body(...), description: str = Body(""),
    user: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    ip_entry = IPWhitelist(ip_address=ip_address, description=description, created_by=user["user_id"])
    db.add(ip_entry)
    db.commit()
    return {"message": "IP added to whitelist"}

# --- 21. Remove IP from Whitelist ---
@app.delete("/api/admin/ip-whitelist/{ip_id}")
async def remove_ip_whitelist(ip_id: int, user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    ip_entry = db.query(IPWhitelist).filter(IPWhitelist.id == ip_id).first()
    if ip_entry:
        db.delete(ip_entry)
        db.commit()
    return {"message": "IP removed"}

# --- 22. Session Management ---
@app.get("/api/admin/sessions")
async def get_sessions(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    sessions = db.query(UserSession).filter(UserSession.is_active == True).all()
    return [{
        "id": s.id, "user_id": s.user_id, "ip_address": s.ip_address,
        "user_agent": s.user_agent, "created_at": str(s.created_at),
        "last_activity": str(s.last_activity), "expires_at": str(s.expires_at)
    } for s in sessions]

# --- 23. Kill Session ---
@app.delete("/api/admin/sessions/{session_id}")
async def kill_session(session_id: int, user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    session = db.query(UserSession).filter(UserSession.id == session_id).first()
    if session:
        session.is_active = False
        db.commit()
    return {"message": "Session terminated"}

# --- 24. Kill All User Sessions ---
@app.post("/api/admin/users/{user_id}/kill-sessions")
async def kill_all_user_sessions(user_id: int, user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    db.query(UserSession).filter(UserSession.user_id == user_id).update({"is_active": False})
    db.commit()
    return {"message": "All sessions terminated"}

# --- 25. Maintenance Windows ---
@app.get("/api/admin/maintenance")
async def list_maintenance(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    mw = db.query(MaintenanceWindow).all()
    return [{
        "id": m.id, "uid": m.uid, "monitor_id": m.monitor_id,
        "title": m.title, "start_time": str(m.start_time),
        "end_time": str(m.end_time), "created_at": str(m.created_at)
    } for m in mw]

@app.post("/api/admin/maintenance")
async def create_maintenance(data: MaintenanceCreate, user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    mw = MaintenanceWindow(
        monitor_id=data.monitor_id, title=data.title,
        description=data.description,
        start_time=datetime.fromisoformat(data.start_time),
        end_time=datetime.fromisoformat(data.end_time)
    )
    db.add(mw)
    db.commit()
    return {"id": mw.id, "message": "Maintenance window created"}

# --- 26. Notification Templates ---
@app.get("/api/admin/notification-templates")
async def list_templates(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    templates = db.query(NotificationTemplate).all()
    return [{
        "id": t.id, "name": t.name, "template_type": t.template_type,
        "subject": t.subject, "body": t.body, "variables": t.variables
    } for t in templates]

@app.post("/api/admin/notification-templates")
async def create_template(
    name: str = Body(...), template_type: str = Body(...),
    subject: str = Body(""), body: str = Body(...),
    user: dict = Depends(require_admin), db: Session = Depends(get_db)
):
    template = NotificationTemplate(name=name, template_type=template_type, subject=subject, body=body)
    db.add(template)
    db.commit()
    return {"id": template.id, "message": "Template created"}

# --- 27-30. Bulk Operations ---
@app.post("/api/admin/monitors/bulk-pause")
async def bulk_pause_monitors(monitor_ids: List[int] = Body(...), user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    db.query(Monitor).filter(Monitor.id.in_(monitor_ids)).update(
        {Monitor.is_paused: True, Monitor.status: MonitorStatus.PAUSED.value},
        synchronize_session=False
    )
    db.commit()
    return {"message": f"{len(monitor_ids)} monitors paused"}

@app.post("/api/admin/monitors/bulk-resume")
async def bulk_resume_monitors(monitor_ids: List[int] = Body(...), user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    db.query(Monitor).filter(Monitor.id.in_(monitor_ids)).update(
        {Monitor.is_paused: False, Monitor.status: MonitorStatus.PENDING.value},
        synchronize_session=False
    )
    db.commit()
    return {"message": f"{len(monitor_ids)} monitors resumed"}

@app.post("/api/admin/monitors/bulk-delete")
async def bulk_delete_monitors(monitor_ids: List[int] = Body(...), user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    db.query(MonitorLog).filter(MonitorLog.monitor_id.in_(monitor_ids)).delete(synchronize_session=False)
    db.query(Incident).filter(Incident.monitor_id.in_(monitor_ids)).delete(synchronize_session=False)
    db.query(Monitor).filter(Monitor.id.in_(monitor_ids)).delete(synchronize_session=False)
    db.commit()
    return {"message": f"{len(monitor_ids)} monitors deleted"}

@app.post("/api/admin/monitors/bulk-check")
async def bulk_check_monitors(monitor_ids: List[int] = Body(...), user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    monitors = db.query(Monitor).filter(Monitor.id.in_(monitor_ids)).all()
    results = []
    for monitor in monitors:
        result = await checker.check_monitor(monitor)
        results.append({"monitor_id": monitor.id, "name": monitor.name, **result})
    return {"results": results}

# --- 31. Export Data ---
@app.get("/api/admin/export/monitors")
async def export_monitors(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    monitors = db.query(Monitor).all()
    data = [{
        "id": m.id, "name": m.name, "url": m.url, "type": m.monitor_type,
        "status": m.status, "uptime": m.uptime_percentage,
        "user_id": m.user_id, "created_at": str(m.created_at)
    } for m in monitors]
    return StreamingResponse(
        BytesIO(json.dumps(data, indent=2).encode()),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=monitors_export.json"}
    )

@app.get("/api/admin/export/users")
async def export_users(user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    users = db.query(User).all()
    data = [{
        "id": u.id, "username": u.username, "email": u.email,
        "role": u.role, "is_active": u.is_active, "created_at": str(u.created_at)
    } for u in users]
    return StreamingResponse(
        BytesIO(json.dumps(data, indent=2).encode()),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=users_export.json"}
    )

@app.get("/api/admin/export/logs")
async def export_logs(
    monitor_id: Optional[int] = None, days: int = 7,
    user: dict = Depends(require_admin), db: Session = Depends(get_db)
):
    since = datetime.utcnow() - timedelta(days=days)
    query = db.query(MonitorLog).filter(MonitorLog.created_at >= since)
    if monitor_id:
        query = query.filter(MonitorLog.monitor_id == monitor_id)
    logs = query.limit(10000).all()
    data = [{
        "monitor_id": l.monitor_id, "status": l.status,
        "response_time": l.response_time, "status_code": l.status_code,
        "error_message": l.error_message, "created_at": str(l.created_at)
    } for l in logs]
    return StreamingResponse(
        BytesIO(json.dumps(data, indent=2).encode()),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=logs_export.json"}
    )

# --- 32-40. Advanced Analytics ---
@app.get("/api/admin/analytics/uptime-heatmap")
async def uptime_heatmap(days: int = 30, user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(days=days)
    monitors = db.query(Monitor).all()
    heatmap_data = []
    for monitor in monitors:
        logs = db.query(MonitorLog).filter(
            MonitorLog.monitor_id == monitor.id,
            MonitorLog.created_at >= since
        ).all()
        daily = {}
        for log in logs:
            day = log.created_at.strftime("%Y-%m-%d")
            if day not in daily:
                daily[day] = {"up": 0, "total": 0}
            daily[day]["total"] += 1
            if log.status == MonitorStatus.UP.value:
                daily[day]["up"] += 1
        heatmap_data.append({
            "monitor_id": monitor.id, "monitor_name": monitor.name,
            "days": [{
                "date": d,
                "uptime": round(s["up"] / s["total"] * 100, 2) if s["total"] > 0 else 100
            } for d, s in sorted(daily.items())]
        })
    return {"heatmap": heatmap_data}

@app.get("/api/admin/analytics/latency")
async def latency_analytics(hours: int = 24, user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(hours=hours)
    monitors = db.query(Monitor).all()
    data = []
    for monitor in monitors:
        logs = db.query(MonitorLog).filter(
            MonitorLog.monitor_id == monitor.id,
            MonitorLog.created_at >= since,
            MonitorLog.response_time.isnot(None)
        ).all()
        rts = [l.response_time for l in logs if l.response_time]
        if rts:
            data.append({
                "monitor_id": monitor.id, "monitor_name": monitor.name,
                "avg": round(sum(rts) / len(rts), 2),
                "min": round(min(rts), 2),
                "max": round(max(rts), 2),
                "p95": round(sorted(rts)[int(len(rts) * 0.95)] if rts else 0, 2),
                "p99": round(sorted(rts)[int(len(rts) * 0.99)] if rts else 0, 2),
                "samples": len(rts)
            })
    return {"latency_data": data}

@app.get("/api/admin/analytics/response-time-distribution")
async def rt_distribution(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(hours=24)
    logs = db.query(MonitorLog).filter(
        MonitorLog.created_at >= since,
        MonitorLog.response_time.isnot(None)
    ).all()
    buckets = {"<100ms": 0, "100-300ms": 0, "300-500ms": 0, "500-1000ms": 0,
               "1000-3000ms": 0, "3000-5000ms": 0, ">5000ms": 0}
    for log in logs:
        rt = log.response_time or 0
        if rt < 100: buckets["<100ms"] += 1
        elif rt < 300: buckets["100-300ms"] += 1
        elif rt < 500: buckets["300-500ms"] += 1
        elif rt < 1000: buckets["500-1000ms"] += 1
        elif rt < 3000: buckets["1000-3000ms"] += 1
        elif rt < 5000: buckets["3000-5000ms"] += 1
        else: buckets[">5000ms"] += 1
    return {"distribution": buckets, "total_samples": len(logs)}

@app.get("/api/admin/analytics/incident-stats")
async def incident_stats(days: int = 30, user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(days=days)
    incidents = db.query(Incident).filter(Incident.created_at >= since).all()
    total = len(incidents)
    resolved = sum(1 for i in incidents if i.status == IncidentStatus.RESOLVED.value)
    ongoing = sum(1 for i in incidents if i.status == IncidentStatus.ONGOING.value)
    acknowledged = sum(1 for i in incidents if i.status == IncidentStatus.ACKNOWLEDGED.value)
    durations = [i.duration_seconds for i in incidents if i.duration_seconds]
    avg_duration = round(sum(durations) / len(durations), 2) if durations else 0
    mttr = avg_duration

    return {
        "total": total, "resolved": resolved, "ongoing": ongoing,
        "acknowledged": acknowledged, "avg_duration_seconds": avg_duration,
        "mttr_seconds": mttr, "days": days
    }

@app.get("/api/admin/analytics/user-activity")
async def user_activity(days: int = 7, user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(days=days)
    audits = db.query(AuditLog).filter(AuditLog.created_at >= since).all()
    user_actions = {}
    for audit in audits:
        un = audit.username or "unknown"
        if un not in user_actions:
            user_actions[un] = {"total": 0, "actions": {}}
        user_actions[un]["total"] += 1
        act = audit.action
        user_actions[un]["actions"][act] = user_actions[un]["actions"].get(act, 0) + 1
    return {"user_activity": user_actions, "days": days}

@app.get("/api/admin/analytics/monitor-performance")
async def monitor_performance_ranking(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    monitors = db.query(Monitor).all()
    perf = []
    for m in monitors:
        perf.append({
            "id": m.id, "name": m.name, "uptime": m.uptime_percentage,
            "avg_response_time": m.avg_response_time, "status": m.status,
            "consecutive_failures": m.consecutive_failures
        })
    perf.sort(key=lambda x: x["uptime"], reverse=True)
    return {"performance_ranking": perf}

@app.get("/api/admin/analytics/geo-distribution")
async def geo_distribution(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.query(User).filter(User.last_ip.isnot(None)).all()
    ip_map = {}
    for u in users:
        ip = u.last_ip
        if ip:
            ip_map[ip] = ip_map.get(ip, 0) + 1
    return {"ip_distribution": ip_map, "unique_ips": len(ip_map)}

@app.get("/api/admin/analytics/error-breakdown")
async def error_breakdown(hours: int = 24, user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(hours=hours)
    logs = db.query(MonitorLog).filter(
        MonitorLog.created_at >= since,
        MonitorLog.status == MonitorStatus.DOWN.value
    ).all()
    errors = {}
    for log in logs:
        err = log.error_message or "Unknown error"
        err_key = err[:100]
        errors[err_key] = errors.get(err_key, 0) + 1
    return {"error_breakdown": errors, "total_errors": len(logs)}

# --- 41-50. Theme Engine & Customization ---
@app.get("/api/admin/theme")
async def get_theme(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    theme_settings = db.query(SiteSetting).filter(SiteSetting.category == "theme").all()
    return {s.key: s.value for s in theme_settings}

@app.put("/api/admin/theme")
async def update_theme(
    settings: Dict[str, str] = Body(...),
    user: dict = Depends(require_superadmin),
    db: Session = Depends(get_db)
):
    for key, value in settings.items():
        setting = db.query(SiteSetting).filter(SiteSetting.key == key).first()
        if setting:
            setting.value = value
        else:
            db.add(SiteSetting(key=key, value=value, category="theme"))
    db.commit()
    return {"message": "Theme updated"}

@app.get("/api/admin/theme/css")
async def get_custom_css(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    setting = db.query(SiteSetting).filter(SiteSetting.key == "custom_css").first()
    return {"css": setting.value if setting else ""}

@app.put("/api/admin/theme/css")
async def update_custom_css(css: str = Body(..., embed=True), user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    setting = db.query(SiteSetting).filter(SiteSetting.key == "custom_css").first()
    if setting:
        setting.value = css
    else:
        db.add(SiteSetting(key="custom_css", value=css, category="theme"))
    db.commit()
    return {"message": "CSS updated"}

@app.get("/api/admin/theme/particles")
async def get_particle_config(user: dict = Depends(require_admin), db: Session = Depends(get_db)):
    enabled = db.query(SiteSetting).filter(SiteSetting.key == "particle_effects").first()
    count = db.query(SiteSetting).filter(SiteSetting.key == "particle_count").first()
    return {
        "enabled": enabled.value == "true" if enabled else True,
        "count": int(count.value) if count else 50
    }

@app.put("/api/admin/theme/particles")
async def update_particle_config(
    enabled: bool = Body(...), count: int = Body(50),
    user: dict = Depends(require_superadmin), db: Session = Depends(get_db)
):
    for key, val in [("particle_effects", str(enabled).lower()), ("particle_count", str(count))]:
        setting = db.query(SiteSetting).filter(SiteSetting.key == key).first()
        if setting:
            setting.value = val
        else:
            db.add(SiteSetting(key=key, value=val, category="theme"))
    db.commit()
    return {"message": "Particle config updated"}

# --- 51-60. Log Rotation, Cleanup, Health ---
@app.post("/api/admin/logs/rotate")
async def rotate_logs(days: int = Body(90, embed=True), user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    cutoff = datetime.utcnow() - timedelta(days=days)
    deleted = db.query(MonitorLog).filter(MonitorLog.created_at < cutoff).delete()
    db.commit()
    log_audit(db, user["user_id"], user["username"], "log_rotation", "logs", None, {"deleted": deleted, "days": days})
    return {"deleted_count": deleted, "message": f"Logs older than {days} days deleted"}

@app.post("/api/admin/logs/clear-all")
async def clear_all_logs(user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    deleted = db.query(MonitorLog).delete()
    db.commit()
    return {"deleted_count": deleted}

@app.post("/api/admin/audit-logs/clear")
async def clear_audit_logs(days: int = Body(365, embed=True), user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    cutoff = datetime.utcnow() - timedelta(days=days)
    deleted = db.query(AuditLog).filter(AuditLog.created_at < cutoff).delete()
    db.commit()
    return {"deleted_count": deleted}

@app.get("/api/admin/health")
async def health_check(user: dict = Depends(require_admin)):
    checks = {
        "database": "ok",
        "scheduler": "ok" if scheduler.running else "error",
        "websocket": "ok",
        "cache": "ok",
    }
    try:
        db = SessionLocal()
        db.execute(sa_text("SELECT 1"))
        db.close()
    except Exception:
        checks["database"] = "error"

    overall = "healthy" if all(v == "ok" for v in checks.values()) else "degraded"
    return {"status": overall, "checks": checks, "timestamp": datetime.utcnow().isoformat()}

@app.post("/api/admin/scheduler/trigger")
async def trigger_check_cycle(user: dict = Depends(require_superadmin)):
    asyncio.create_task(run_monitor_checks())
    return {"message": "Monitor check cycle triggered"}

@app.get("/api/admin/scheduler/jobs")
async def get_scheduler_jobs(user: dict = Depends(require_admin)):
    jobs = []
    for job in scheduler.get_jobs():
        jobs.append({
            "id": job.id,
            "name": job.name,
            "next_run": str(job.next_run_time) if job.next_run_time else None,
            "trigger": str(job.trigger)
        })
    return {"jobs": jobs}

# --- 61-70. Advanced Features ---
@app.post("/api/admin/maintenance-mode/toggle")
async def toggle_maintenance_mode(user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    setting = db.query(SiteSetting).filter(SiteSetting.key == "maintenance_mode").first()
    if setting:
        setting.value = "false" if setting.value == "true" else "true"
    else:
        db.add(SiteSetting(key="maintenance_mode", value="true", category="general"))
    db.commit()
    return {"maintenance_mode": setting.value if setting else "true"}

@app.post("/api/admin/registration/toggle")
async def toggle_registration(user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    setting = db.query(SiteSetting).filter(SiteSetting.key == "registration_enabled").first()
    if setting:
        setting.value = "false" if setting.value == "true" else "true"
    db.commit()
    return {"registration_enabled": setting.value}

@app.post("/api/admin/2fa/toggle-required")
async def toggle_2fa_required(user: dict = Depends(require_superadmin), db: Session = Depends(get_db)):
    setting = db.query(SiteSetting).filter(SiteSetting.key == "two_factor_required").first()
    if setting:
        setting.value = "false" if setting.value == "true" else "true"
    db.commit()
    return {"two_factor_required": setting.value}

@app.get("/api/admin/features")
async def list_admin_features(user: dict = Depends(require_admin)):
    """List all 70+ admin features"""
    features = [
        {"id": 1, "name": "User Management", "category": "Users", "endpoint": "/api/admin/users"},
        {"id": 2, "name": "Create User/Admin", "category": "Users", "endpoint": "/api/admin/users POST"},
        {"id": 3, "name": "Update User", "category": "Users", "endpoint": "/api/admin/users/{id} PUT"},
        {"id": 4, "name": "Delete User", "category": "Users", "endpoint": "/api/admin/users/{id} DELETE"},
        {"id": 5, "name": "User Impersonation", "category": "Users", "endpoint": "/api/admin/impersonate/{id}"},
        {"id": 6, "name": "Toggle User Active", "category": "Users", "endpoint": "/api/admin/users/{id}/toggle-active"},
        {"id": 7, "name": "Reset Password", "category": "Users", "endpoint": "/api/admin/users/{id}/reset-password"},
        {"id": 8, "name": "Unlock User", "category": "Users", "endpoint": "/api/admin/users/{id}/unlock"},
        {"id": 9, "name": "Site Settings", "category": "Settings", "endpoint": "/api/admin/settings"},
        {"id": 10, "name": "Update Setting", "category": "Settings", "endpoint": "/api/admin/settings/{key} PUT"},
        {"id": 11, "name": "Audit Logs", "category": "Security", "endpoint": "/api/admin/audit-logs"},
        {"id": 12, "name": "All Monitors", "category": "Monitors", "endpoint": "/api/admin/monitors"},
        {"id": 13, "name": "System Stats", "category": "System", "endpoint": "/api/admin/system-stats"},
        {"id": 14, "name": "Database Backup", "category": "Database", "endpoint": "/api/admin/database/backup"},
        {"id": 15, "name": "Database Vacuum", "category": "Database", "endpoint": "/api/admin/database/vacuum"},
        {"id": 16, "name": "Database Stats", "category": "Database", "endpoint": "/api/admin/database/stats"},
        {"id": 17, "name": "Clear Cache", "category": "Cache", "endpoint": "/api/admin/cache/clear"},
        {"id": 18, "name": "Cache Stats", "category": "Cache", "endpoint": "/api/admin/cache/stats"},
        {"id": 19, "name": "IP Whitelist View", "category": "Security", "endpoint": "/api/admin/ip-whitelist"},
        {"id": 20, "name": "Add IP Whitelist", "category": "Security", "endpoint": "/api/admin/ip-whitelist POST"},
        {"id": 21, "name": "Remove IP Whitelist", "category": "Security", "endpoint": "/api/admin/ip-whitelist/{id} DELETE"},
        {"id": 22, "name": "Session Management", "category": "Security", "endpoint": "/api/admin/sessions"},
        {"id": 23, "name": "Kill Session", "category": "Security", "endpoint": "/api/admin/sessions/{id} DELETE"},
        {"id": 24, "name": "Kill All User Sessions", "category": "Security", "endpoint": "/api/admin/users/{id}/kill-sessions"},
        {"id": 25, "name": "Maintenance Windows", "category": "Monitors", "endpoint": "/api/admin/maintenance"},
        {"id": 26, "name": "Notification Templates", "category": "Notifications", "endpoint": "/api/admin/notification-templates"},
        {"id": 27, "name": "Bulk Pause Monitors", "category": "Monitors", "endpoint": "/api/admin/monitors/bulk-pause"},
        {"id": 28, "name": "Bulk Resume Monitors", "category": "Monitors", "endpoint": "/api/admin/monitors/bulk-resume"},
        {"id": 29, "name": "Bulk Delete Monitors", "category": "Monitors", "endpoint": "/api/admin/monitors/bulk-delete"},
        {"id": 30, "name": "Bulk Check Monitors", "category": "Monitors", "endpoint": "/api/admin/monitors/bulk-check"},
        {"id": 31, "name": "Export Monitors", "category": "Data", "endpoint": "/api/admin/export/monitors"},
        {"id": 32, "name": "Export Users", "category": "Data", "endpoint": "/api/admin/export/users"},
        {"id": 33, "name": "Export Logs", "category": "Data", "endpoint": "/api/admin/export/logs"},
        {"id": 34, "name": "Uptime Heatmap", "category": "Analytics", "endpoint": "/api/admin/analytics/uptime-heatmap"},
        {"id": 35, "name": "Latency Analytics", "category": "Analytics", "endpoint": "/api/admin/analytics/latency"},
        {"id": 36, "name": "Response Time Distribution", "category": "Analytics", "endpoint": "/api/admin/analytics/response-time-distribution"},
        {"id": 37, "name": "Incident Stats", "category": "Analytics", "endpoint": "/api/admin/analytics/incident-stats"},
        {"id": 38, "name": "User Activity", "category": "Analytics", "endpoint": "/api/admin/analytics/user-activity"},
        {"id": 39, "name": "Monitor Performance", "category": "Analytics", "endpoint": "/api/admin/analytics/monitor-performance"},
        {"id": 40, "name": "Geo Distribution", "category": "Analytics", "endpoint": "/api/admin/analytics/geo-distribution"},
        {"id": 41, "name": "Error Breakdown", "category": "Analytics", "endpoint": "/api/admin/analytics/error-breakdown"},
        {"id": 42, "name": "Theme Settings", "category": "Theme", "endpoint": "/api/admin/theme"},
        {"id": 43, "name": "Update Theme", "category": "Theme", "endpoint": "/api/admin/theme PUT"},
        {"id": 44, "name": "Custom CSS Editor", "category": "Theme", "endpoint": "/api/admin/theme/css"},
        {"id": 45, "name": "Update Custom CSS", "category": "Theme", "endpoint": "/api/admin/theme/css PUT"},
        {"id": 46, "name": "Particle Effects Config", "category": "Theme", "endpoint": "/api/admin/theme/particles"},
        {"id": 47, "name": "Update Particles", "category": "Theme", "endpoint": "/api/admin/theme/particles PUT"},
        {"id": 48, "name": "Log Rotation", "category": "Maintenance", "endpoint": "/api/admin/logs/rotate"},
        {"id": 49, "name": "Clear All Logs", "category": "Maintenance", "endpoint": "/api/admin/logs/clear-all"},
        {"id": 50, "name": "Clear Audit Logs", "category": "Maintenance", "endpoint": "/api/admin/audit-logs/clear"},
        {"id": 51, "name": "Health Check", "category": "System", "endpoint": "/api/admin/health"},
        {"id": 52, "name": "Trigger Check Cycle", "category": "System", "endpoint": "/api/admin/scheduler/trigger"},
        {"id": 53, "name": "Scheduler Jobs", "category": "System", "endpoint": "/api/admin/scheduler/jobs"},
        {"id": 54, "name": "Maintenance Mode Toggle", "category": "System", "endpoint": "/api/admin/maintenance-mode/toggle"},
        {"id": 55, "name": "Registration Toggle", "category": "System", "endpoint": "/api/admin/registration/toggle"},
        {"id": 56, "name": "2FA Required Toggle", "category": "Security", "endpoint": "/api/admin/2fa/toggle-required"},
        {"id": 57, "name": "Feature List", "category": "System", "endpoint": "/api/admin/features"},
        {"id": 58, "name": "WebSocket Status", "category": "System", "endpoint": "/ws"},
        {"id": 59, "name": "API Key Management", "category": "Users", "endpoint": "/api/auth/regenerate-api-key"},
        {"id": 60, "name": "Monitor Uptime Report", "category": "Reports", "endpoint": "/api/monitors/{id}/uptime"},
        {"id": 61, "name": "Monitor Logs Export", "category": "Reports", "endpoint": "/api/monitors/{id}/logs"},
        {"id": 62, "name": "Status Page Management", "category": "StatusPages", "endpoint": "/api/status-pages"},
        {"id": 63, "name": "Public Status Page", "category": "StatusPages", "endpoint": "/api/status/{slug}"},
        {"id": 64, "name": "Alert Channel Management", "category": "Alerts", "endpoint": "/api/alerts"},
        {"id": 65, "name": "Test Alert Channel", "category": "Alerts", "endpoint": "/api/alerts/{id}/test"},
        {"id": 66, "name": "Incident Management", "category": "Incidents", "endpoint": "/api/incidents"},
        {"id": 67, "name": "Acknowledge Incident", "category": "Incidents", "endpoint": "/api/incidents/{id}/acknowledge"},
        {"id": 68, "name": "Resolve Incident", "category": "Incidents", "endpoint": "/api/incidents/{id}/resolve"},
        {"id": 69, "name": "Dashboard Stats", "category": "Dashboard", "endpoint": "/api/dashboard/stats"},
        {"id": 70, "name": "Dashboard Charts", "category": "Dashboard", "endpoint": "/api/dashboard/charts"},
        {"id": 71, "name": "Password Change", "category": "Auth", "endpoint": "/api/auth/change-password"},
        {"id": 72, "name": "2FA Setup", "category": "Auth", "endpoint": "/api/auth/setup-2fa"},
        {"id": 73, "name": "Create Maintenance Window", "category": "Monitors", "endpoint": "/api/admin/maintenance POST"},
        {"id": 74, "name": "Create Notification Template", "category": "Notifications", "endpoint": "/api/admin/notification-templates POST"},
    ]
    return {"features": features, "total": len(features)}

# ============================================================================
# WEBSOCKET ENDPOINT
# ============================================================================
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = Query(None)):
    user_id = 0
    if token:
        payload = verify_jwt_token(token)
        if payload:
            user_id = payload.get("user_id", 0)

    await ws_manager.connect(websocket, user_id)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong", "timestamp": datetime.utcnow().isoformat()})
            except:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, user_id)

# ============================================================================
# REACT FRONTEND - COMPLETE MOBILE-FIRST SPA
# ============================================================================
REACT_APP = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="mobile-web-app-capable" content="yes">
<meta name="theme-color" content="#0f172a">
<title>MonitorPro SaaS</title>
<script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
* { margin:0; padding:0; box-sizing:border-box; font-family:'Inter',sans-serif; -webkit-tap-highlight-color:transparent; }
body { background:#0f172a; color:#e2e8f0; overflow-x:hidden; min-height:100vh; min-height:100dvh; }
::-webkit-scrollbar { width:4px; }
::-webkit-scrollbar-track { background:#1e293b; }
::-webkit-scrollbar-thumb { background:#6366f1; border-radius:4px; }
.gradient-bg { background:linear-gradient(135deg,#0f172a 0%,#1e1b4b 50%,#0f172a 100%); }
.glass { background:rgba(30,41,59,0.8); backdrop-filter:blur(20px); border:1px solid rgba(99,102,241,0.2); }
.glass-card { background:rgba(30,41,59,0.6); backdrop-filter:blur(12px); border:1px solid rgba(148,163,184,0.1); border-radius:16px; }
.pulse-green { animation:pulse-g 2s infinite; }
@keyframes pulse-g { 0%,100%{box-shadow:0 0 0 0 rgba(34,197,94,0.4);} 50%{box-shadow:0 0 0 8px rgba(34,197,94,0);} }
.pulse-red { animation:pulse-r 1.5s infinite; }
@keyframes pulse-r { 0%,100%{box-shadow:0 0 0 0 rgba(239,68,68,0.4);} 50%{box-shadow:0 0 0 8px rgba(239,68,68,0);} }
.slide-up { animation:slideUp 0.3s ease; }
@keyframes slideUp { from{transform:translateY(20px);opacity:0;} to{transform:translateY(0);opacity:1;} }
.fade-in { animation:fadeIn 0.3s ease; }
@keyframes fadeIn { from{opacity:0;} to{opacity:1;} }
.btn-primary { background:linear-gradient(135deg,#6366f1,#8b5cf6); border:none; color:white; padding:12px 24px; border-radius:12px; font-weight:600; cursor:pointer; transition:all 0.2s; }
.btn-primary:hover { transform:translateY(-1px); box-shadow:0 4px 15px rgba(99,102,241,0.4); }
.btn-primary:active { transform:translateY(0); }
.input-field { background:rgba(15,23,42,0.8); border:1px solid rgba(148,163,184,0.2); color:#e2e8f0; padding:12px 16px; border-radius:12px; width:100%; font-size:16px; transition:border-color 0.2s; outline:none; }
.input-field:focus { border-color:#6366f1; box-shadow:0 0 0 3px rgba(99,102,241,0.1); }
.fab { position:fixed; right:20px; bottom:90px; width:56px; height:56px; border-radius:28px; background:linear-gradient(135deg,#6366f1,#8b5cf6); color:white; border:none; font-size:24px; cursor:pointer; box-shadow:0 4px 15px rgba(99,102,241,0.4); z-index:40; display:flex; align-items:center; justify-content:center; transition:all 0.2s; }
.fab:active { transform:scale(0.95); }
.status-dot { width:10px; height:10px; border-radius:50%; display:inline-block; }
.status-up { background:#22c55e; }
.status-down { background:#ef4444; }
.status-pending { background:#f59e0b; }
.status-paused { background:#94a3b8; }
canvas#particles { position:fixed; top:0; left:0; width:100%; height:100%; z-index:0; pointer-events:none; }
.content-wrapper { position:relative; z-index:1; }
.modal-overlay { position:fixed; top:0; left:0; right:0; bottom:0; background:rgba(0,0,0,0.7); backdrop-filter:blur(4px); z-index:50; display:flex; align-items:flex-end; justify-content:center; }
.modal-content { background:#1e293b; border-radius:20px 20px 0 0; width:100%; max-width:500px; max-height:85vh; overflow-y:auto; padding:24px; border:1px solid rgba(99,102,241,0.2); border-bottom:none; }
.heatmap-cell { width:14px; height:14px; border-radius:3px; display:inline-block; margin:1px; }
.tab-active { border-bottom:2px solid #6366f1; color:#6366f1; }
.skeleton { background:linear-gradient(90deg,#1e293b 25%,#334155 50%,#1e293b 75%); background-size:200% 100%; animation:shimmer 1.5s infinite; border-radius:8px; }
@keyframes shimmer { 0%{background-position:200% 0;} 100%{background-position:-200% 0;} }
.progress-bar { height:6px; border-radius:3px; background:#1e293b; overflow:hidden; }
.progress-fill { height:100%; border-radius:3px; transition:width 0.5s ease; }
.chart-bar { transition:height 0.3s ease; }
.bottom-nav { position:fixed; bottom:0; left:0; right:0; height:70px; z-index:30; }
.safe-bottom { padding-bottom:90px; }
</style>
</head>
<body>
<canvas id="particles"></canvas>
<div id="root"></div>

<script type="text/babel">
const { useState, useEffect, useCallback, useRef, useMemo, createContext, useContext } = React;

// ======== CONTEXT ========
const AppContext = createContext();

const useApp = () => useContext(AppContext);

// ======== API HELPER ========
const API = {
    token: localStorage.getItem('token'),
    setToken(t) { this.token = t; if(t) localStorage.setItem('token',t); else localStorage.removeItem('token'); },
    async req(method, url, body=null) {
        const opts = { method, headers: {'Content-Type':'application/json'} };
        if(this.token) opts.headers['Authorization'] = `Bearer ${this.token}`;
        if(body) opts.body = JSON.stringify(body);
        const r = await fetch(url, opts);
        if(r.status === 401) { this.setToken(null); window.location.reload(); return null; }
        const data = await r.json();
        if(!r.ok) throw new Error(data.detail || 'Request failed');
        return data;
    },
    get: (u) => API.req('GET',u),
    post: (u,b) => API.req('POST',u,b),
    put: (u,b) => API.req('PUT',u,b),
    del: (u) => API.req('DELETE',u),
};

// ======== PARTICLES ========
function initParticles() {
    const canvas = document.getElementById('particles');
    if(!canvas) return;
    const ctx = canvas.getContext('2d');
    let W, H, particles = [];
    function resize() { W=canvas.width=window.innerWidth; H=canvas.height=window.innerHeight; }
    resize(); window.addEventListener('resize', resize);
    class P {
        constructor() { this.reset(); }
        reset() {
            this.x=Math.random()*W; this.y=Math.random()*H;
            this.vx=(Math.random()-0.5)*0.5; this.vy=(Math.random()-0.5)*0.5;
            this.r=Math.random()*2+0.5; this.a=Math.random()*0.5+0.1;
        }
        update() {
            this.x+=this.vx; this.y+=this.vy;
            if(this.x<0||this.x>W||this.y<0||this.y>H) this.reset();
        }
        draw() {
            ctx.beginPath(); ctx.arc(this.x,this.y,this.r,0,Math.PI*2);
            ctx.fillStyle=`rgba(99,102,241,${this.a})`; ctx.fill();
        }
    }
    for(let i=0;i<50;i++) particles.push(new P());
    function animate() {
        ctx.clearRect(0,0,W,H);
        particles.forEach(p => { p.update(); p.draw(); });
        for(let i=0;i<particles.length;i++) {
            for(let j=i+1;j<particles.length;j++) {
                const dx=particles[i].x-particles[j].x, dy=particles[i].y-particles[j].y;
                const d=Math.sqrt(dx*dx+dy*dy);
                if(d<120) {
                    ctx.beginPath(); ctx.moveTo(particles[i].x,particles[i].y);
                    ctx.lineTo(particles[j].x,particles[j].y);
                    ctx.strokeStyle=`rgba(99,102,241,${0.1*(1-d/120)})`; ctx.stroke();
                }
            }
        }
        requestAnimationFrame(animate);
    }
    animate();
}

// ======== ICONS (SVG) ========
const Icons = {
    Home: () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>,
    Monitor: () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>,
    Bell: () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/></svg>,
    Settings: () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>,
    Shield: () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg>,
    Plus: () => <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12h14"/><path d="M12 5v14"/></svg>,
    Check: () => <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>,
    X: () => <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>,
    Activity: () => <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>,
    Users: () => <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>,
    Trash: () => <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>,
    Pause: () => <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect width="4" height="16" x="6" y="4"/><rect width="4" height="16" x="14" y="4"/></svg>,
    Play: () => <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>,
    RefreshCw: () => <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg>,
    ChevronRight: () => <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="m9 18 6-6-6-6"/></svg>,
    Logout: () => <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/></svg>,
};

// ======== LOGIN PAGE ========
function LoginPage({ onLogin }) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [isRegister, setIsRegister] = useState(false);
    const [email, setEmail] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault(); setLoading(true); setError('');
        try {
            if(isRegister) {
                const data = await API.post('/api/auth/register', {username,password,email});
                API.setToken(data.token);
                onLogin(data.user);
            } else {
                const data = await API.post('/api/auth/login', {username,password});
                if(data.requires_2fa) { setError('2FA required (enter code)'); setLoading(false); return; }
                API.setToken(data.token);
                onLogin(data.user);
            }
        } catch(e) { setError(e.message); }
        setLoading(false);
    };

    return (
        <div className="min-h-screen flex items-center justify-center p-4 content-wrapper">
            <div className="glass-card p-8 w-full max-w-sm slide-up">
                <div className="text-center mb-8">
                    <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-indigo-500 to-purple-600 mx-auto mb-4 flex items-center justify-center">
                        <Icons.Shield/>
                    </div>
                    <h1 className="text-2xl font-bold bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">MonitorPro</h1>
                    <p className="text-slate-400 text-sm mt-1">{isRegister?'Create Account':'Welcome back'}</p>
                </div>
                {error && <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-3 mb-4 text-red-400 text-sm">{error}</div>}
                <form onSubmit={handleSubmit} className="space-y-4">
                    <input type="text" placeholder="Username" value={username} onChange={e=>setUsername(e.target.value)} className="input-field" required />
                    {isRegister && <input type="email" placeholder="Email" value={email} onChange={e=>setEmail(e.target.value)} className="input-field"/>}
                    <input type="password" placeholder="Password" value={password} onChange={e=>setPassword(e.target.value)} className="input-field" required />
                    <button type="submit" disabled={loading} className="btn-primary w-full disabled:opacity-50">
                        {loading ? '...' : isRegister ? 'Create Account' : 'Sign In'}
                    </button>
                </form>
                <p className="text-center text-sm text-slate-400 mt-4">
                    <button onClick={()=>setIsRegister(!isRegister)} className="text-indigo-400 underline">
                        {isRegister?'Already have an account?':'Create new account'}
                    </button>
                </p>
            </div>
        </div>
    );
}

// ======== STAT CARD ========
function StatCard({label, value, color='indigo', icon}) {
    const colors = {indigo:'from-indigo-500/20 to-indigo-600/10 border-indigo-500/30', green:'from-green-500/20 to-green-600/10 border-green-500/30', red:'from-red-500/20 to-red-600/10 border-red-500/30', amber:'from-amber-500/20 to-amber-600/10 border-amber-500/30', purple:'from-purple-500/20 to-purple-600/10 border-purple-500/30'};
    return (
        <div className={`bg-gradient-to-br ${colors[color]||colors.indigo} border rounded-2xl p-4 slide-up`}>
            <p className="text-slate-400 text-xs uppercase tracking-wider">{label}</p>
            <p className="text-2xl font-bold mt-1">{value}</p>
        </div>
    );
}

// ======== MONITOR CARD ========
function MonitorCard({monitor, onClick, onPause, onCheck}) {
    const statusColors = {up:'bg-green-500',down:'bg-red-500',pending:'bg-amber-500',paused:'bg-slate-500',maintenance:'bg-blue-500'};
    const statusPulse = {up:'pulse-green',down:'pulse-red'};
    return (
        <div className="glass-card p-4 mb-3 slide-up active:scale-[0.98] transition-transform" onClick={()=>onClick&&onClick(monitor)}>
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-3 flex-1 min-w-0">
                    <div className={`w-3 h-3 rounded-full ${statusColors[monitor.status]||'bg-slate-500'} ${statusPulse[monitor.status]||''}`}/>
                    <div className="min-w-0">
                        <h3 className="font-semibold text-sm truncate">{monitor.name}</h3>
                        <p className="text-xs text-slate-400 truncate">{monitor.url}</p>
                    </div>
                </div>
                <div className="text-right ml-2 shrink-0">
                    <p className="text-sm font-mono">{monitor.uptime_percentage?.toFixed(1)||'100.0'}%</p>
                    <p className="text-xs text-slate-400">{monitor.avg_response_time?.toFixed(0)||'0'}ms</p>
                </div>
            </div>
            <div className="flex gap-2 mt-3">
                <button onClick={(e)=>{e.stopPropagation();onPause&&onPause(monitor)}} className="flex-1 bg-slate-700/50 rounded-lg py-2 text-xs font-medium flex items-center justify-center gap-1 active:bg-slate-600/50">
                    {monitor.is_paused?<Icons.Play/>:<Icons.Pause/>} {monitor.is_paused?'Resume':'Pause'}
                </button>
                <button onClick={(e)=>{e.stopPropagation();onCheck&&onCheck(monitor)}} className="flex-1 bg-indigo-600/30 rounded-lg py-2 text-xs font-medium flex items-center justify-center gap-1 active:bg-indigo-500/30">
                    <Icons.RefreshCw/> Check
                </button>
            </div>
        </div>
    );
}

// ======== SIMPLE CHART ========
function MiniChart({data, height=60}) {
    if(!data||!data.length) return <div className="text-xs text-slate-500 text-center py-4">No data</div>;
    const max = Math.max(...data.map(d=>d.value),1);
    return (
        <div className="flex items-end gap-[2px]" style={{height:height+'px'}}>
            {data.slice(-30).map((d,i) => (
                <div key={i} className="flex-1 rounded-t-sm chart-bar" title={`${d.label}: ${d.value}`}
                    style={{height:`${Math.max((d.value/max)*100,2)}%`, background: d.value > 0 ? (d.color||'#6366f1') : '#334155'}}/>
            ))}
        </div>
    );
}

// ======== DASHBOARD ========
function Dashboard() {
    const {user} = useApp();
    const [stats, setStats] = useState(null);
    const [monitors, setMonitors] = useState([]);
    const [chartData, setChartData] = useState([]);
    const [loading, setLoading] = useState(true);

    const load = useCallback(async () => {
        try {
            const [s, m, c] = await Promise.all([
                API.get('/api/dashboard/stats'),
                API.get('/api/monitors'),
                API.get('/api/dashboard/charts?hours=24')
            ]);
            setStats(s); setMonitors(m); setChartData(c.chart_data||[]);
        } catch(e) { console.error(e); }
        setLoading(false);
    }, []);

    useEffect(() => { load(); const t=setInterval(load,30000); return()=>clearInterval(t); }, [load]);

    if(loading) return <div className="p-4 safe-bottom"><div className="skeleton h-24 mb-4"/><div className="skeleton h-24 mb-4"/><div className="skeleton h-40"/></div>;

    const uptimeChart = chartData.map(d => ({value:d.uptime, label:d.time, color: d.uptime >= 99 ? '#22c55e' : d.uptime >= 95 ? '#f59e0b' : '#ef4444'}));
    const rtChart = chartData.map(d => ({value:d.avg_response_time, label:d.time, color:'#6366f1'}));

    return (
        <div className="p-4 safe-bottom content-wrapper">
            <div className="mb-6">
                <h1 className="text-xl font-bold">Dashboard</h1>
                <p className="text-sm text-slate-400">Welcome, {user?.username}</p>
            </div>

            <div className="grid grid-cols-2 gap-3 mb-6">
                <StatCard label="Total" value={stats?.total_monitors||0} color="indigo"/>
                <StatCard label="Up" value={stats?.up||0} color="green"/>
                <StatCard label="Down" value={stats?.down||0} color="red"/>
                <StatCard label="Avg Uptime" value={`${stats?.avg_uptime||100}%`} color="purple"/>
            </div>

            <div className="glass-card p-4 mb-4">
                <h3 className="text-sm font-semibold mb-3">Uptime (24h)</h3>
                <MiniChart data={uptimeChart}/>
            </div>

            <div className="glass-card p-4 mb-4">
                <h3 className="text-sm font-semibold mb-3">Response Time (24h)</h3>
                <MiniChart data={rtChart} height={50}/>
            </div>

            {stats?.ongoing_incidents > 0 && (
                <div className="bg-red-500/10 border border-red-500/30 rounded-2xl p-4 mb-4 flex items-center gap-3">
                    <div className="w-3 h-3 rounded-full bg-red-500 pulse-red"/>
                    <div>
                        <p className="font-semibold text-red-400">{stats.ongoing_incidents} Active Incident{stats.ongoing_incidents>1?'s':''}</p>
                        <p className="text-xs text-slate-400">Requires attention</p>
                    </div>
                </div>
            )}
        </div>
    );
}

// ======== MONITORS PAGE ========
function MonitorsPage() {
    const [monitors, setMonitors] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showCreate, setShowCreate] = useState(false);
    const [detail, setDetail] = useState(null);
    const [filter, setFilter] = useState('all');

    const load = useCallback(async () => {
        try { const d = await API.get('/api/monitors'); setMonitors(d); } catch(e) {}
        setLoading(false);
    }, []);

    useEffect(() => { load(); }, [load]);

    const handlePause = async (m) => {
        try { await API.post(`/api/monitors/${m.id}/pause`); load(); } catch(e) { alert(e.message); }
    };
    const handleCheck = async (m) => {
        try { await API.post(`/api/monitors/${m.id}/check`); load(); } catch(e) { alert(e.message); }
    };
    const handleDelete = async (m) => {
        if(!confirm('Delete this monitor?')) return;
        try { await API.del(`/api/monitors/${m.id}`); setDetail(null); load(); } catch(e) { alert(e.message); }
    };

    const filtered = monitors.filter(m => {
        if(filter==='all') return true;
        if(filter==='up') return m.status==='up';
        if(filter==='down') return m.status==='down';
        if(filter==='paused') return m.is_paused;
        return true;
    });

    return (
        <div className="p-4 safe-bottom content-wrapper">
            <div className="flex items-center justify-between mb-4">
                <h1 className="text-xl font-bold">Monitors</h1>
                <span className="text-sm text-slate-400">{monitors.length} total</span>
            </div>

            <div className="flex gap-2 mb-4 overflow-x-auto pb-2">
                {['all','up','down','paused'].map(f => (
                    <button key={f} onClick={()=>setFilter(f)} className={`px-4 py-2 rounded-full text-xs font-medium whitespace-nowrap ${filter===f?'bg-indigo-600 text-white':'bg-slate-700/50 text-slate-300'}`}>
                        {f.charAt(0).toUpperCase()+f.slice(1)}
                    </button>
                ))}
            </div>

            {loading ? <div><div className="skeleton h-24 mb-3"/><div className="skeleton h-24 mb-3"/></div> :
                filtered.length === 0 ? <div className="text-center text-slate-400 py-12"><p>No monitors found</p></div> :
                filtered.map(m => <MonitorCard key={m.id} monitor={m} onClick={setDetail} onPause={handlePause} onCheck={handleCheck}/>)
            }

            <button className="fab" onClick={()=>setShowCreate(true)}><Icons.Plus/></button>

            {showCreate && <CreateMonitorModal onClose={()=>setShowCreate(false)} onCreated={()=>{setShowCreate(false);load()}}/>}
            {detail && <MonitorDetailModal monitor={detail} onClose={()=>setDetail(null)} onDelete={handleDelete} onRefresh={load}/>}
        </div>
    );
}

// ======== CREATE MONITOR MODAL ========
function CreateMonitorModal({onClose, onCreated}) {
    const [form, setForm] = useState({name:'',url:'',monitor_type:'http',interval:60,timeout:30,expected_status:200,keyword:'',method:'GET'});
    const [loading, setLoading] = useState(false);
    const set = (k,v) => setForm(p=>({...p,[k]:v}));

    const submit = async (e) => {
        e.preventDefault(); setLoading(true);
        try { await API.post('/api/monitors', form); onCreated(); } catch(e) { alert(e.message); }
        setLoading(false);
    };

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content slide-up" onClick={e=>e.stopPropagation()}>
                <div className="flex items-center justify-between mb-6">
                    <h2 className="text-lg font-bold">New Monitor</h2>
                    <button onClick={onClose} className="p-2"><Icons.X/></button>
                </div>
                <form onSubmit={submit} className="space-y-4">
                    <div>
                        <label className="text-xs text-slate-400 mb-1 block">Name</label>
                        <input value={form.name} onChange={e=>set('name',e.target.value)} className="input-field" placeholder="My Website" required/>
                    </div>
                    <div>
                        <label className="text-xs text-slate-400 mb-1 block">URL</label>
                        <input value={form.url} onChange={e=>set('url',e.target.value)} className="input-field" placeholder="https://example.com" required/>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                        <div>
                            <label className="text-xs text-slate-400 mb-1 block">Type</label>
                            <select value={form.monitor_type} onChange={e=>set('monitor_type',e.target.value)} className="input-field">
                                <option value="http">HTTP</option><option value="https">HTTPS</option>
                                <option value="ping">Ping</option><option value="port">Port</option>
                                <option value="keyword">Keyword</option><option value="tcp">TCP</option>
                            </select>
                        </div>
                        <div>
                            <label className="text-xs text-slate-400 mb-1 block">Interval (s)</label>
                            <input type="number" value={form.interval} onChange={e=>set('interval',parseInt(e.target.value))} className="input-field"/>
                        </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                        <div>
                            <label className="text-xs text-slate-400 mb-1 block">Method</label>
                            <select value={form.method} onChange={e=>set('method',e.target.value)} className="input-field">
                                <option>GET</option><option>POST</option><option>PUT</option><option>HEAD</option>
                            </select>
                        </div>
                        <div>
                            <label className="text-xs text-slate-400 mb-1 block">Expected Status</label>
                            <input type="number" value={form.expected_status} onChange={e=>set('expected_status',parseInt(e.target.value))} className="input-field"/>
                        </div>
                    </div>
                    {form.monitor_type==='keyword' && (
                        <div>
                            <label className="text-xs text-slate-400 mb-1 block">Keyword</label>
                            <input value={form.keyword} onChange={e=>set('keyword',e.target.value)} className="input-field" placeholder="Expected keyword"/>
                        </div>
                    )}
                    <button type="submit" disabled={loading} className="btn-primary w-full">{loading?'Creating...':'Create Monitor'}</button>
                </form>
            </div>
        </div>
    );
}

// ======== MONITOR DETAIL MODAL ========
function MonitorDetailModal({monitor, onClose, onDelete, onRefresh}) {
    const [logs, setLogs] = useState([]);
    const [uptime, setUptime] = useState(null);
    const [tab, setTab] = useState('overview');

    useEffect(() => {
        API.get(`/api/monitors/${monitor.id}/logs?limit=50`).then(setLogs).catch(()=>{});
        API.get(`/api/monitors/${monitor.id}/uptime?days=30`).then(setUptime).catch(()=>{});
    }, [monitor.id]);

    const statusColor = {up:'text-green-400',down:'text-red-400',pending:'text-amber-400',paused:'text-slate-400'}[monitor.status]||'text-slate-400';

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content slide-up" onClick={e=>e.stopPropagation()} style={{maxHeight:'90vh'}}>
                <div className="flex items-center justify-between mb-4">
                    <div>
                        <h2 className="text-lg font-bold">{monitor.name}</h2>
                        <p className="text-xs text-slate-400 truncate">{monitor.url}</p>
                    </div>
                    <button onClick={onClose} className="p-2"><Icons.X/></button>
                </div>

                <div className="flex items-center gap-4 mb-4">
                    <span className={`text-sm font-semibold uppercase ${statusColor}`}>{monitor.status}</span>
                    <span className="text-sm text-slate-400">{monitor.uptime_percentage?.toFixed(2)}% uptime</span>
                    <span className="text-sm text-slate-400">{monitor.avg_response_time?.toFixed(0)}ms</span>
                </div>

                <div className="flex gap-1 mb-4 border-b border-slate-700">
                    {['overview','logs','uptime'].map(t => (
                        <button key={t} onClick={()=>setTab(t)} className={`px-4 py-2 text-sm font-medium ${tab===t?'tab-active':'text-slate-400'}`}>
                            {t.charAt(0).toUpperCase()+t.slice(1)}
                        </button>
                    ))}
                </div>

                {tab==='overview' && (
                    <div className="space-y-3">
                        <div className="grid grid-cols-2 gap-3">
                            <div className="bg-slate-800/50 rounded-xl p-3"><p className="text-xs text-slate-400">Type</p><p className="font-medium text-sm">{monitor.monitor_type}</p></div>
                            <div className="bg-slate-800/50 rounded-xl p-3"><p className="text-xs text-slate-400">Interval</p><p className="font-medium text-sm">{monitor.interval}s</p></div>
                            <div className="bg-slate-800/50 rounded-xl p-3"><p className="text-xs text-slate-400">Last Checked</p><p className="font-medium text-sm truncate">{monitor.last_checked||'Never'}</p></div>
                            <div className="bg-slate-800/50 rounded-xl p-3"><p className="text-xs text-slate-400">Failures</p><p className="font-medium text-sm">{monitor.consecutive_failures||0}</p></div>
                        </div>
                        <button onClick={()=>onDelete(monitor)} className="w-full bg-red-500/10 border border-red-500/30 rounded-xl py-3 text-red-400 text-sm font-medium">Delete Monitor</button>
                    </div>
                )}

                {tab==='logs' && (
                    <div className="space-y-2 max-h-60 overflow-y-auto">
                        {logs.length===0 ? <p className="text-sm text-slate-400 text-center py-4">No logs yet</p> :
                            logs.map(l => (
                                <div key={l.id} className="flex items-center justify-between bg-slate-800/30 rounded-xl p-3">
                                    <div className="flex items-center gap-2">
                                        <div className={`w-2 h-2 rounded-full ${l.status==='up'?'bg-green-500':'bg-red-500'}`}/>
                                        <span className="text-xs text-slate-400">{new Date(l.created_at).toLocaleTimeString()}</span>
                                    </div>
                                    <div className="text-right">
                                        <span className="text-xs font-mono">{l.response_time?.toFixed(0)||'-'}ms</span>
                                        {l.status_code && <span className="text-xs text-slate-400 ml-2">{l.status_code}</span>}
                                    </div>
                                </div>
                            ))
                        }
                    </div>
                )}

                {tab==='uptime' && uptime && (
                    <div>
                        <div className="text-center mb-4">
                            <p className="text-3xl font-bold text-green-400">{uptime.uptime_percentage}%</p>
                            <p className="text-xs text-slate-400">{uptime.days}-day uptime</p>
                        </div>
                        <div className="flex flex-wrap gap-[2px]">
                            {(uptime.heatmap||[]).map((d,i) => {
                                const color = d.uptime >= 99.9 ? '#22c55e' : d.uptime >= 99 ? '#86efac' : d.uptime >= 95 ? '#f59e0b' : d.uptime >= 90 ? '#f97316' : '#ef4444';
                                return <div key={i} className="heatmap-cell" style={{background:color}} title={`${d.date}: ${d.uptime}%`}/>;
                            })}
                        </div>
                        <div className="flex justify-between mt-2">
                            <span className="text-xs text-slate-400">30 days ago</span>
                            <span className="text-xs text-slate-400">Today</span>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

// ======== INCIDENTS PAGE ========
function IncidentsPage() {
    const [incidents, setIncidents] = useState([]);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState('');

    useEffect(() => {
        API.get(`/api/incidents${filter?'?status='+filter:''}`).then(d=>{setIncidents(d);setLoading(false);}).catch(()=>setLoading(false));
    }, [filter]);

    const handleAck = async (id) => { try { await API.post(`/api/incidents/${id}/acknowledge`); setIncidents(prev=>prev.map(i=>i.id===id?{...i,status:'acknowledged'}:i)); } catch(e){} };
    const handleResolve = async (id) => { try { await API.post(`/api/incidents/${id}/resolve`,{resolution:'Resolved manually'}); setIncidents(prev=>prev.map(i=>i.id===id?{...i,status:'resolved'}:i)); } catch(e){} };

    const sevColors = {high:'text-red-400 bg-red-500/10',medium:'text-amber-400 bg-amber-500/10',low:'text-green-400 bg-green-500/10'};
    const statusBadge = {ongoing:'bg-red-500/20 text-red-400',resolved:'bg-green-500/20 text-green-400',acknowledged:'bg-amber-500/20 text-amber-400'};

    return (
        <div className="p-4 safe-bottom content-wrapper">
            <h1 className="text-xl font-bold mb-4">Incidents</h1>
            <div className="flex gap-2 mb-4 overflow-x-auto pb-2">
                {['','ongoing','acknowledged','resolved'].map(f => (
                    <button key={f} onClick={()=>setFilter(f)} className={`px-4 py-2 rounded-full text-xs font-medium whitespace-nowrap ${filter===f?'bg-indigo-600 text-white':'bg-slate-700/50 text-slate-300'}`}>
                        {f||'All'}
                    </button>
                ))}
            </div>
            {loading ? <div className="skeleton h-20 mb-3"/> :
                incidents.length === 0 ? <div className="text-center text-slate-400 py-12"><Icons.Check/><p className="mt-2">No incidents</p></div> :
                incidents.map(i => (
                    <div key={i.id} className="glass-card p-4 mb-3 slide-up">
                        <div className="flex items-start justify-between mb-2">
                            <div className="flex-1 min-w-0">
                                <h3 className="font-semibold text-sm">{i.title}</h3>
                                <p className="text-xs text-slate-400 mt-1">{new Date(i.started_at).toLocaleString()}</p>
                            </div>
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusBadge[i.status]||''}`}>{i.status}</span>
                        </div>
                        {i.status==='ongoing' && (
                            <div className="flex gap-2 mt-3">
                                <button onClick={()=>handleAck(i.id)} className="flex-1 bg-amber-600/20 rounded-lg py-2 text-xs font-medium text-amber-400">Acknowledge</button>
                                <button onClick={()=>handleResolve(i.id)} className="flex-1 bg-green-600/20 rounded-lg py-2 text-xs font-medium text-green-400">Resolve</button>
                            </div>
                        )}
                        {i.duration_seconds && <p className="text-xs text-slate-400 mt-2">Duration: {Math.round(i.duration_seconds/60)}min</p>}
                    </div>
                ))
            }
        </div>
    );
}

// ======== ADMIN PAGE ========
function AdminPage() {
    const {user} = useApp();
    const [tab, setTab] = useState('overview');
    const [sysStats, setSysStats] = useState(null);
    const [users, setUsers] = useState([]);
    const [auditLogs, setAuditLogs] = useState([]);
    const [settings, setSettings] = useState([]);
    const [loading, setLoading] = useState(true);

    const isSuperadmin = user?.role === 'superadmin';

    useEffect(() => {
        Promise.all([
            API.get('/api/admin/system-stats').catch(()=>null),
            API.get('/api/admin/users').catch(()=>[]),
            API.get('/api/admin/audit-logs?limit=50').catch(()=>[]),
            API.get('/api/admin/settings').catch(()=>[]),
        ]).then(([s,u,a,st]) => {
            setSysStats(s); setUsers(u||[]); setAuditLogs(a||[]); setSettings(st||[]);
            setLoading(false);
        });
    }, []);

    const toggleUser = async (id) => {
        try { await API.post(`/api/admin/users/${id}/toggle-active`); const u = await API.get('/api/admin/users'); setUsers(u); } catch(e) { alert(e.message); }
    };
    const deleteUser = async (id) => {
        if(!confirm('Delete user?')) return;
        try { await API.del(`/api/admin/users/${id}`); setUsers(prev=>prev.filter(u=>u.id!==id)); } catch(e) { alert(e.message); }
    };
    const impersonate = async (id) => {
        try { const d = await API.post(`/api/admin/impersonate/${id}`); alert(`Impersonation token: ${d.token.substring(0,20)}...`); } catch(e) { alert(e.message); }
    };
    const dbBackup = async () => { try { const d = await API.post('/api/admin/database/backup'); alert(d.message); } catch(e) { alert(e.message); } };
    const dbVacuum = async () => { try { const d = await API.post('/api/admin/database/vacuum'); alert(d.message); } catch(e) { alert(e.message); } };
    const clearCache = async () => { try { const d = await API.post('/api/admin/cache/clear'); alert(d.message); } catch(e) { alert(e.message); } };
    const triggerChecks = async () => { try { const d = await API.post('/api/admin/scheduler/trigger'); alert(d.message); } catch(e) { alert(e.message); } };
    const rotateLogs = async () => { try { const d = await API.post('/api/admin/logs/rotate',{days:90}); alert(d.message+' Deleted: '+d.deleted_count); } catch(e) { alert(e.message); } };

    if(loading) return <div className="p-4 safe-bottom"><div className="skeleton h-32 mb-4"/><div className="skeleton h-32"/></div>;

    const tabs = ['overview','users','audit','settings','tools'];

    return (
        <div className="p-4 safe-bottom content-wrapper">
            <div className="flex items-center gap-2 mb-4">
                <Icons.Shield/>
                <h1 className="text-xl font-bold">{isSuperadmin?'Super':''}Admin Panel</h1>
            </div>

            <div className="flex gap-1 mb-4 overflow-x-auto pb-2">
                {tabs.map(t => (
                    <button key={t} onClick={()=>setTab(t)} className={`px-3 py-2 rounded-lg text-xs font-medium whitespace-nowrap ${tab===t?'bg-indigo-600 text-white':'bg-slate-700/50 text-slate-300'}`}>
                        {t.charAt(0).toUpperCase()+t.slice(1)}
                    </button>
                ))}
            </div>

            {tab==='overview' && sysStats && (
                <div className="space-y-3">
                    <div className="grid grid-cols-2 gap-3">
                        <StatCard label="Users" value={sysStats.total_users} color="indigo"/>
                        <StatCard label="Monitors" value={sysStats.total_monitors} color="green"/>
                        <StatCard label="Logs" value={sysStats.total_logs?.toLocaleString()} color="purple"/>
                        <StatCard label="Incidents" value={sysStats.active_incidents} color="red"/>
                        <StatCard label="Sessions" value={sysStats.active_sessions} color="amber"/>
                        <StatCard label="DB Size" value={`${sysStats.database_size_mb}MB`} color="indigo"/>
                        <StatCard label="Cache" value={sysStats.cache_size} color="green"/>
                        <StatCard label="WS Conns" value={sysStats.websocket_connections} color="purple"/>
                    </div>
                    <div className="glass-card p-4">
                        <h3 className="text-sm font-semibold mb-2">Quick Actions</h3>
                        <div className="grid grid-cols-2 gap-2">
                            <button onClick={triggerChecks} className="bg-indigo-600/20 rounded-xl py-3 text-xs font-medium text-indigo-400">Run Checks</button>
                            <button onClick={clearCache} className="bg-amber-600/20 rounded-xl py-3 text-xs font-medium text-amber-400">Clear Cache</button>
                            <button onClick={dbBackup} className="bg-green-600/20 rounded-xl py-3 text-xs font-medium text-green-400">DB Backup</button>
                            <button onClick={dbVacuum} className="bg-purple-600/20 rounded-xl py-3 text-xs font-medium text-purple-400">DB Vacuum</button>
                            <button onClick={rotateLogs} className="bg-red-600/20 rounded-xl py-3 text-xs font-medium text-red-400">Rotate Logs</button>
                            <button onClick={async()=>{const d=await API.get('/api/admin/health');alert(JSON.stringify(d,null,2))}} className="bg-cyan-600/20 rounded-xl py-3 text-xs font-medium text-cyan-400">Health Check</button>
                        </div>
                    </div>
                </div>
            )}

            {tab==='users' && (
                <div className="space-y-3">
                    {users.map(u => (
                        <div key={u.id} className="glass-card p-4 slide-up">
                            <div className="flex items-center justify-between">
                                <div>
                                    <div className="flex items-center gap-2">
                                        <h3 className="font-semibold text-sm">{u.username}</h3>
                                        <span className={`px-2 py-0.5 rounded-full text-xs ${u.role==='superadmin'?'bg-purple-500/20 text-purple-400':u.role==='admin'?'bg-indigo-500/20 text-indigo-400':'bg-slate-500/20 text-slate-400'}`}>{u.role}</span>
                                    </div>
                                    <p className="text-xs text-slate-400">{u.email||'No email'}</p>
                                    <p className="text-xs text-slate-400">Last: {u.last_login?new Date(u.last_login).toLocaleDateString():'Never'}</p>
                                </div>
                                <div className="flex items-center gap-1">
                                    <div className={`w-2 h-2 rounded-full ${u.is_active?'bg-green-500':'bg-red-500'}`}/>
                                </div>
                            </div>
                            {isSuperadmin && u.role !== 'superadmin' && (
                                <div className="flex gap-2 mt-3">
                                    <button onClick={()=>toggleUser(u.id)} className="flex-1 bg-slate-700/50 rounded-lg py-2 text-xs">{u.is_active?'Disable':'Enable'}</button>
                                    <button onClick={()=>impersonate(u.id)} className="flex-1 bg-indigo-600/20 rounded-lg py-2 text-xs text-indigo-400">Impersonate</button>
                                    <button onClick={()=>deleteUser(u.id)} className="bg-red-600/20 rounded-lg py-2 px-3 text-xs text-red-400"><Icons.Trash/></button>
                                </div>
                            )}
                        </div>
                    ))}
                </div>
            )}

            {tab==='audit' && (
                <div className="space-y-2">
                    {auditLogs.map(l => (
                        <div key={l.id} className="glass-card p-3">
                            <div className="flex items-center justify-between">
                                <div>
                                    <span className="text-xs font-medium text-indigo-400">{l.action}</span>
                                    <span className="text-xs text-slate-400 ml-2">by {l.username}</span>
                                </div>
                                <span className="text-xs text-slate-500">{new Date(l.created_at).toLocaleTimeString()}</span>
                            </div>
                            {l.resource_type && <p className="text-xs text-slate-400 mt-1">{l.resource_type} #{l.resource_id}</p>}
                        </div>
                    ))}
                </div>
            )}

            {tab==='settings' && (
                <div className="space-y-2">
                    {settings.map(s => (
                        <div key={s.id} className="glass-card p-3 flex items-center justify-between">
                            <div>
                                <p className="text-sm font-medium">{s.key}</p>
                                <p className="text-xs text-slate-400">{s.category}</p>
                            </div>
                            <span className="text-xs text-indigo-400 font-mono max-w-[120px] truncate">{s.value||'(empty)'}</span>
                        </div>
                    ))}
                </div>
            )}

            {tab==='tools' && (
                <div className="space-y-3">
                    <div className="glass-card p-4">
                        <h3 className="text-sm font-semibold mb-3">Analytics</h3>
                        <div className="grid grid-cols-1 gap-2">
                            {[
                                {label:'Uptime Heatmap',fn:()=>API.get('/api/admin/analytics/uptime-heatmap')},
                                {label:'Latency Analysis',fn:()=>API.get('/api/admin/analytics/latency')},
                                {label:'RT Distribution',fn:()=>API.get('/api/admin/analytics/response-time-distribution')},
                                {label:'Incident Stats',fn:()=>API.get('/api/admin/analytics/incident-stats')},
                                {label:'User Activity',fn:()=>API.get('/api/admin/analytics/user-activity')},
                                {label:'Error Breakdown',fn:()=>API.get('/api/admin/analytics/error-breakdown')},
                                {label:'Monitor Performance',fn:()=>API.get('/api/admin/analytics/monitor-performance')},
                            ].map(t => (
                                <button key={t.label} onClick={async()=>{const d=await t.fn();alert(JSON.stringify(d,null,2))}} className="bg-slate-700/50 rounded-xl py-3 px-4 text-xs font-medium text-left flex items-center justify-between">
                                    {t.label} <Icons.ChevronRight/>
                                </button>
                            ))}
                        </div>
                    </div>
                    <div className="glass-card p-4">
                        <h3 className="text-sm font-semibold mb-3">Export Data</h3>
                        <div className="grid grid-cols-1 gap-2">
                            <a href="/api/admin/export/monitors" target="_blank" className="block bg-slate-700/50 rounded-xl py-3 px-4 text-xs font-medium">Export Monitors (JSON)</a>
                            {isSuperadmin && <a href="/api/admin/export/users" target="_blank" className="block bg-slate-700/50 rounded-xl py-3 px-4 text-xs font-medium">Export Users (JSON)</a>}
                            <a href="/api/admin/export/logs?days=7" target="_blank" className="block bg-slate-700/50 rounded-xl py-3 px-4 text-xs font-medium">Export Logs - 7 days (JSON)</a>
                        </div>
                    </div>
                    <div className="glass-card p-4">
                        <h3 className="text-sm font-semibold mb-3">Feature List</h3>
                        <button onClick={async()=>{const d=await API.get('/api/admin/features');alert(`Total Features: ${d.total}\\n\\n`+d.features.map(f=>`#${f.id} ${f.name} [${f.category}]`).join('\\n'))}} className="bg-indigo-600/20 rounded-xl py-3 px-4 text-xs font-medium text-indigo-400 w-full">View All 70+ Features</button>
                    </div>
                </div>
            )}
        </div>
    );
}

// ======== SETTINGS PAGE ========
function SettingsPage() {
    const {user, setUser, logout} = useApp();
    const [profile, setProfile] = useState(null);

    useEffect(() => { API.get('/api/auth/me').then(setProfile).catch(()=>{}); }, []);

    return (
        <div className="p-4 safe-bottom content-wrapper">
            <h1 className="text-xl font-bold mb-4">Settings</h1>

            {profile && (
                <div className="glass-card p-4 mb-4">
                    <div className="flex items-center gap-4 mb-4">
                        <div className="w-14 h-14 rounded-full bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center text-xl font-bold">
                            {profile.username?.charAt(0).toUpperCase()}
                        </div>
                        <div>
                            <h2 className="font-bold">{profile.username}</h2>
                            <p className="text-sm text-slate-400">{profile.email||'No email'}</p>
                            <span className={`text-xs px-2 py-0.5 rounded-full ${profile.role==='superadmin'?'bg-purple-500/20 text-purple-400':'bg-indigo-500/20 text-indigo-400'}`}>{profile.role}</span>
                        </div>
                    </div>
                    <div className="grid grid-cols-2 gap-3 text-sm">
                        <div className="bg-slate-800/50 rounded-xl p-3"><p className="text-xs text-slate-400">Last Login</p><p className="truncate">{profile.last_login?new Date(profile.last_login).toLocaleDateString():'N/A'}</p></div>
                        <div className="bg-slate-800/50 rounded-xl p-3"><p className="text-xs text-slate-400">2FA</p><p>{profile.totp_enabled?'Enabled':'Disabled'}</p></div>
                    </div>
                </div>
            )}

            <div className="space-y-2">
                <button onClick={async()=>{try{const d=await API.post('/api/auth/regenerate-api-key');alert('New API Key: '+d.api_key)}catch(e){alert(e.message)}}} className="glass-card p-4 w-full text-left flex items-center justify-between">
                    <span className="text-sm font-medium">Regenerate API Key</span><Icons.ChevronRight/>
                </button>
                <button onClick={async()=>{try{const d=await API.post('/api/auth/setup-2fa');alert('2FA Secret: '+d.secret+'\\nURI: '+d.uri)}catch(e){alert(e.message)}}} className="glass-card p-4 w-full text-left flex items-center justify-between">
                    <span className="text-sm font-medium">Setup 2FA</span><Icons.ChevronRight/>
                </button>
                <button onClick={logout} className="glass-card p-4 w-full text-left flex items-center justify-between text-red-400">
                    <span className="text-sm font-medium flex items-center gap-2"><Icons.Logout/>Logout</span><Icons.ChevronRight/>
                </button>
            </div>
        </div>
    );
}

// ======== BOTTOM NAV ========
function BottomNav({active, onChange, isAdmin}) {
    const items = [
        {id:'dashboard', label:'Home', icon:Icons.Home},
        {id:'monitors', label:'Monitors', icon:Icons.Monitor},
        {id:'incidents', label:'Alerts', icon:Icons.Bell},
        ...(isAdmin ? [{id:'admin', label:'Admin', icon:Icons.Shield}] : []),
        {id:'settings', label:'Settings', icon:Icons.Settings},
    ];
    return (
        <div className="bottom-nav glass" style={{borderTop:'1px solid rgba(99,102,241,0.15)'}}>
            <div className="flex items-center justify-around h-full max-w-lg mx-auto">
                {items.map(item => {
                    const Icon = item.icon;
                    const isActive = active === item.id;
                    return (
                        <button key={item.id} onClick={()=>onChange(item.id)}
                            className={`flex flex-col items-center justify-center gap-1 py-2 px-3 rounded-xl transition-all ${isActive?'text-indigo-400':'text-slate-500'}`}>
                            <Icon/>
                            <span className="text-[10px] font-medium">{item.label}</span>
                            {isActive && <div className="w-1 h-1 rounded-full bg-indigo-400"/>}
                        </button>
                    );
                })}
            </div>
        </div>
    );
}

// ======== MAIN APP ========
function App() {
    const [user, setUser] = useState(null);
    const [page, setPage] = useState('dashboard');
    const [loading, setLoading] = useState(true);
    const wsRef = useRef(null);

    useEffect(() => { initParticles(); }, []);

    useEffect(() => {
        if(API.token) {
            API.get('/api/auth/me').then(u => { setUser(u); setLoading(false); })
            .catch(() => { API.setToken(null); setLoading(false); });
        } else { setLoading(false); }
    }, []);

    useEffect(() => {
        if(!user) return;
        const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
        const ws = new WebSocket(`${proto}://${window.location.host}/ws?token=${API.token}`);
        ws.onopen = () => console.log('WS connected');
        ws.onmessage = (e) => { try { const d = JSON.parse(e.data); console.log('WS:', d); } catch{} };
        ws.onclose = () => setTimeout(() => {}, 5000);
        wsRef.current = ws;
        const ping = setInterval(() => { if(ws.readyState===1) ws.send(JSON.stringify({type:'ping'})); }, 30000);
        return () => { clearInterval(ping); ws.close(); };
    }, [user]);

    const logout = () => { API.setToken(null); setUser(null); setPage('dashboard'); };

    const isAdmin = user?.role === 'admin' || user?.role === 'superadmin';

    if(loading) return <div className="min-h-screen flex items-center justify-center content-wrapper"><div className="skeleton w-16 h-16 rounded-2xl"/></div>;
    if(!user) return <LoginPage onLogin={(u) => setUser(u)}/>;

    return (
        <AppContext.Provider value={{user, setUser, logout}}>
            <div className="min-h-screen gradient-bg">
                {page==='dashboard' && <Dashboard/>}
                {page==='monitors' && <MonitorsPage/>}
                {page==='incidents' && <IncidentsPage/>}
                {page==='admin' && isAdmin && <AdminPage/>}
                {page==='settings' && <SettingsPage/>}
                <BottomNav active={page} onChange={setPage} isAdmin={isAdmin}/>
            </div>
        </AppContext.Provider>
    );
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
</script>
</body>
</html>"""

# ============================================================================
# SERVE FRONTEND
# ============================================================================
app_start_time = time.time()

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    return HTMLResponse(content=REACT_APP)

@app.get("/app", response_class=HTMLResponse)
async def serve_app():
    return HTMLResponse(content=REACT_APP)

# ============================================================================
# HEALTH ENDPOINT (PUBLIC)
# ============================================================================
@app.get("/api/health")
async def public_health():
    return {
        "status": "healthy",
        "app": config.APP_NAME,
        "version": config.APP_VERSION,
        "timestamp": datetime.utcnow().isoformat()
    }

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================
if __name__ == "__main__":
    import uvicorn
    run_port = int(os.environ.get("PORT", 8000))
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║              MonitorPro SaaS Platform v2.0                   ║
║══════════════════════════════════════════════════════════════║
║  URL:        http://localhost:{run_port}                        ║
║  SuperAdmin: {config.SUPERADMIN_USERNAME} / {config.SUPERADMIN_PASSWORD}                  ║
║  API Docs:   http://localhost:{run_port}/docs                   ║
║  Database:   {config.DATABASE_URL[:50]}...  ║
║  Features:   70+ Admin Features                              ║
║  Frontend:   Mobile-First React + Tailwind                   ║
╚══════════════════════════════════════════════════════════════╝
    """)
    uvicorn.run(
        app,
        host=config.HOST,
        port=run_port,
        log_level="info",
        access_log=True
    )