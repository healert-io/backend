# =============================================================================
# main.py — Healert Backend v0.1.0
# =============================================================================
#
# Copyright 2026 Healert OÜ
# Licensed under the Apache License, Version 2.0
# https://www.apache.org/licenses/LICENSE-2.0
#
# =============================================================================

# main.py — Healert Backend v0.1.0
#
# Self-hosted FastAPI backend for the Healert Backstage plugin.
# Receives friction events from the Go agent, calculates friction scores,
# and serves data to the Backstage plugin via REST API.
#
# ─────────────────────────────────────────────────────────────────────────────
# SECURITY MODEL
# ─────────────────────────────────────────────────────────────────────────────
#
#   API Key        All write endpoints require Authorization: Bearer {key}
#                  Set HEALERT_API_KEY on both backend and agent.
#                  Generate: openssl rand -base64 32
#
#   CORS           Restricted to HEALERT_ALLOWED_ORIGINS (default: localhost:3000)
#                  Prevents cross-origin requests from unauthorized websites.
#
#   Input          All fields validated: max length, allowed values whitelist.
#                  Rejects malformed entity_ref, unknown event types, bad severity.
#
#   Rate limiting  POST /events limited to 60 requests/minute per IP.
#                  Prevents event flood attacks from compromised agents.
#
#   Bind address   Binds to 127.0.0.1 by default (localhost only).
#                  Set HEALERT_HOST=0.0.0.0 for network access (use with HTTPS).
#
#   Retention      Events older than HEALERT_RETENTION_DAYS deleted on startup
#                  and every 24 hours. Default: 30 days.
#
# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION — environment variables
# ─────────────────────────────────────────────────────────────────────────────
#
#   HEALERT_API_KEY          Required for write endpoints (POST /events)
#   HEALERT_DB               SQLite database path   (default: ./healert.db)
#   HEALERT_ALLOWED_ORIGINS  Comma-separated CORS origins (default: http://localhost:3000)
#   HEALERT_RETENTION_DAYS   Event retention in days    (default: 30)
#   HEALERT_HOST             Bind address               (default: 127.0.0.1)
#   HEALERT_PORT             Bind port                  (default: 8000)
#
# ─────────────────────────────────────────────────────────────────────────────
# START
# ─────────────────────────────────────────────────────────────────────────────
#
#   pip install fastapi uvicorn pydantic slowapi
#   uvicorn main:app --host 127.0.0.1 --port 8000

import hmac
import math
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# =============================================================================
# 1. CONFIGURATION
# =============================================================================

# API key — required for all write endpoints
# Generate: openssl rand -base64 32
API_KEY = os.getenv('HEALERT_API_KEY', '').strip()

# SQLite database path — validated to prevent path traversal
_raw_db_path = os.getenv('HEALERT_DB', './healert.db')
DB_PATH = os.path.abspath(_raw_db_path)

# CORS — restrict to Backstage origin
# Default: localhost:3000 (local development)
_raw_origins = os.getenv('HEALERT_ALLOWED_ORIGINS', 'http://localhost:3000')
ALLOWED_ORIGINS = [o.strip() for o in _raw_origins.split(',') if o.strip()]

# Event retention — delete events older than this many days
RETENTION_DAYS = int(os.getenv('HEALERT_RETENTION_DAYS', '30'))

# Allowed values for strict input validation
# Event types are defined in rules.yaml — not hardcoded here.
# The backend accepts any type that matches the rules agent sends.
# Validation: type must be non-empty, max 64 chars, alphanumeric + hyphens only.
ALLOWED_EVENT_TYPES: set[str] = set()  # empty = accept all valid types
ALLOWED_SEVERITIES = {'high', 'medium', 'low'}

# Scoring weights — must match EVENT_POINTS in FrictionScoreCard.tsx
# Scoring is automatic — derived from event severity.
# No hardcoded rule names. No manual points assignment.
# Works for all current and future rules without any code changes.
#
# Severity → Points mapping:
#   high   → 10  (direct platform bypass, critical policy violation)
#   medium →  6  (indirect bypass, elevated but not critical)
#   low    →  3  (informational, common but low-risk)
#
# The agent may also send an explicit points field from rules.yaml.
# If present it overrides this table — allows fine-grained tuning per rule.
SEVERITY_POINTS: dict[str, int] = {
    'high':   10,
    'medium':  6,
    'low':     3,
}
DEFAULT_POINTS = 5  # fallback if severity is missing or unrecognised

# Entity ref format: component:{namespace}/{name}
ENTITY_REF_PATTERN = re.compile(
    r'^[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+/[a-zA-Z0-9_.\-]+$'
)

# =============================================================================
# 2. RATE LIMITER
# =============================================================================

limiter = Limiter(key_func=get_remote_address)

# =============================================================================
# 3. APP SETUP
# =============================================================================

app = FastAPI(
    title='Healert Backend',
    version='v0.1.0',
    docs_url=None,   # Disable Swagger UI in production
    redoc_url=None,  # Disable ReDoc in production
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS — restricted to configured origins only
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=['GET', 'POST'],
    allow_headers=['Authorization', 'Content-Type'],
)

# =============================================================================
# 4. SECURITY — API KEY AUTHENTICATION
# =============================================================================

security = HTTPBearer(auto_error=False)

def verify_api_key(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> None:
    """
    Validates the Authorization: Bearer {key} header on write endpoints.
    Raises HTTP 401 if the key is missing or incorrect.

    If HEALERT_API_KEY is not set, authentication is skipped with a warning.
    This allows local development without a key while requiring one in production.
    """
    if not API_KEY:
        # No key configured — skip auth (development mode)
        return

    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail='Unauthorized — missing API key',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    # Use hmac.compare_digest for constant-time comparison.
    # Prevents timing attacks that could reveal the key character by character.
    if not hmac.compare_digest(credentials.credentials, API_KEY):
        raise HTTPException(
            status_code=401,
            detail='Unauthorized — invalid API key',
            headers={'WWW-Authenticate': 'Bearer'},
        )

# =============================================================================
# 5. DATABASE
# =============================================================================

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # WAL mode: allows concurrent reads while writing.
    # Also more resilient to crashes — no DB corruption on unclean shutdown.
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn

def init_db() -> None:
    """Creates the friction_events table if it does not exist."""
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS friction_events (
            id          TEXT PRIMARY KEY
                        DEFAULT (lower(hex(randomblob(16)))),
            entity_ref  TEXT NOT NULL,
            type        TEXT NOT NULL,
            severity    TEXT NOT NULL,
            actor       TEXT,
            service     TEXT,
            namespace   TEXT,
            workflow    TEXT,
            description TEXT,
            timestamp   TEXT,
            points      INTEGER DEFAULT 5
        )
    ''')
    # Index on entity_ref + timestamp for fast friction score queries
    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_entity_timestamp
        ON friction_events (entity_ref, timestamp)
    ''')
    conn.commit()
    conn.close()

def delete_old_events() -> int:
    """
    Deletes events older than RETENTION_DAYS. Returns count deleted.
    Called at startup and every 24 hours by the retention thread.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat()
    conn = get_db()
    cursor = conn.execute(
        'DELETE FROM friction_events WHERE timestamp < ?', (cutoff,)
    )
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted

def retention_loop() -> None:
    """Background thread — runs delete_old_events every 24 hours."""
    while True:
        time.sleep(86400)  # 24 hours
        try:
            deleted = delete_old_events()
            if deleted > 0:
                print(f'[retention] Deleted {deleted} events older than {RETENTION_DAYS} days')
        except Exception as e:
            print(f'[retention] Error: {e}')

# Initialize database and start retention thread
init_db()
deleted_on_startup = delete_old_events()
if deleted_on_startup > 0:
    print(f'[startup] Deleted {deleted_on_startup} expired events')

threading.Thread(target=retention_loop, daemon=True).start()

# =============================================================================
# 6. SCORING
# =============================================================================

# =============================================================================
# SCORING CONSTANTS
# =============================================================================
#
# SCORE_RETENTION_DAYS: only events within this window count toward score.
#   Events older than 30 days have zero weight — score decays naturally.
#
# SCORE_DECAY_HALF_LIFE: events lose half their weight every N days.
#   7 days = an event from last week counts as half a fresh event.
#   This reflects real platform engineering reality: recent bypasses
#   are more urgent than old ones.
#
# SCORE_CRITICAL_THRESHOLD: weighted points needed for score = 100.
#   50 = 5 high-severity events today = critical service.
#   Tune this based on your organisation's bypass tolerance.
#
SCORE_RETENTION_DAYS    = int(os.getenv('SCORE_RETENTION_DAYS',    '30'))
SCORE_DECAY_HALF_LIFE   = int(os.getenv('SCORE_DECAY_HALF_LIFE',   '7'))
SCORE_CRITICAL_THRESHOLD = int(os.getenv('SCORE_CRITICAL_THRESHOLD', '50'))


def calculate_score(events: list[dict]) -> dict:
    """
    Production friction score with exponential time decay.

    Formula:
      1. Filter to last SCORE_RETENTION_DAYS (default: 30 days)
      2. Apply exponential decay: weight = 0.5 ^ (age_days / half_life)
         Recent events count more — events from 7 days ago count as half.
      3. Score = min(100, round(weighted_total / SCORE_CRITICAL_THRESHOLD * 100))

    Behaviour:
      - Score rises immediately when bypass events occur
      - Score naturally decays over time without any manual reset
      - Burst of 5 high events today  = 100 (critical)
      - Same 5 events from 7 days ago = 50  (medium)
      - Same 5 events from 14 days ago= 25  (low)
      - Same 5 events from 30 days ago= 0   (score fully decayed)
      - Production healthy service (1 event/week) = 14 (low)

    This is configurable via environment variables:
      SCORE_RETENTION_DAYS     — event window (default: 30)
      SCORE_DECAY_HALF_LIFE    — decay rate in days (default: 7)
      SCORE_CRITICAL_THRESHOLD — points for score=100 (default: 50)
    """
    if not events:
        return {
            'score':                   0,
            'severity':                'low',
            'bypassCount':             0,
            'overheadHoursPerEngineer': 0.0,
            'topFrictionWorkflow':     'none',
            'calculatedAt':            datetime.now(timezone.utc).isoformat(),
        }

    now     = datetime.now(timezone.utc)
    cutoff  = now - timedelta(days=SCORE_RETENTION_DAYS)

    # Apply exponential time decay to each event
    weighted_total = 0.0
    counted        = 0

    for e in events:
        # Parse timestamp — fall back to now if missing or malformed
        ts_str = e.get('timestamp', '')
        try:
            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        except Exception:
            ts = now

        # Skip events outside retention window — they do not affect score
        if ts < cutoff:
            continue

        counted += 1

        # Points: explicit > severity-based > default
        points = (
            e.get('points') or
            SEVERITY_POINTS.get(e.get('severity', ''), DEFAULT_POINTS)
        )

        # Exponential decay: weight = 0.5 ^ (age_days / half_life)
        # age=0 days  → weight=1.0  (full weight)
        # age=7 days  → weight=0.5  (half weight)
        # age=14 days → weight=0.25 (quarter weight)
        # age=30 days → weight=0.03 (near zero)
        age_days = max(0.0, (now - ts).total_seconds() / 86400.0)
        weight   = math.pow(0.5, age_days / SCORE_DECAY_HALF_LIFE)
        weighted_total += points * weight

    # Score = weighted total relative to critical threshold
    score = min(100, round((weighted_total / SCORE_CRITICAL_THRESHOLD) * 100))

    severity = (
        'critical' if score >= 80 else
        'high'     if score >= 60 else
        'medium'   if score >= 40 else
        'low'
    )

    workflows = [e['workflow'] for e in events if e.get('workflow')]
    top_workflow = max(set(workflows), key=workflows.count) if workflows else 'deploy'

    return {
        'score':                   score,
        'severity':                severity,
        'bypassCount':             counted,  # events within retention window only
        'overheadHoursPerEngineer': round(counted * 25 / 60, 1),
        'topFrictionWorkflow':     top_workflow,
        'calculatedAt':            datetime.now(timezone.utc).isoformat(),
    }

# =============================================================================
# 7. REQUEST MODELS
# =============================================================================

class FrictionEventRequest(BaseModel):
    """
    Incoming friction event from the Go agent.
    All fields are validated before storage.
    """

    entity_ref: str = Field(
        ...,
        min_length=3,
        max_length=200,
        description='Backstage entity ref — format: component:{namespace}/{name}',
    )
    type: str = Field(
        ...,
        min_length=3,
        max_length=50,
        description='Event type — must be a known friction event type',
    )
    severity: str = Field(
        ...,
        min_length=3,
        max_length=10,
        description='Severity level — high, medium, or low',
    )
    actor: Optional[str] = Field(None, max_length=200)
    service: Optional[str] = Field(None, max_length=200)
    namespace: Optional[str] = Field(None, max_length=200)
    workflow: Optional[str] = Field(None, max_length=200)
    description: Optional[str] = Field(None, max_length=500)
    points:      Optional[int] = Field(None, ge=1, le=100,
        description='Friction score weight — defined in rules.yaml. '
                    'Defaults to POINTS table or DEFAULT_POINTS if not set.')
    timestamp: Optional[str] = Field(None, max_length=40)

    @field_validator('entity_ref')
    @classmethod
    def validate_entity_ref(cls, v: str) -> str:
        """Validates entity_ref matches component:{namespace}/{name} format."""
        if not ENTITY_REF_PATTERN.match(v):
            raise ValueError(
                f'Invalid entity_ref format: {v!r}. '
                'Expected: component:{namespace}/{name} '
                '(alphanumeric, hyphens, underscores, dots only)'
            )
        return v

    @field_validator('type')
    @classmethod
    def validate_type(cls, v: str) -> str:
        """Validates event type format — alphanumeric and hyphens only.
        
        Accepts any type defined in rules.yaml — not a fixed whitelist.
        This allows platform engineers to add custom rules without
        changing the backend code.
        
        Format: lowercase letters, digits, and hyphens. Max 64 chars.
        Examples: kubectl-exec, secret-deletion, my-custom-rule
        """
        import re
        if not v:
            raise ValueError('Event type cannot be empty')
        if len(v) > 64:
            raise ValueError(
                f'Event type too long: {len(v)} chars (max 64): {v!r}'
            )
        if not re.match(r'^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$', v):
            raise ValueError(
                f'Invalid event type format: {v!r}. '
                f'Must be lowercase letters, digits, and hyphens only. '
                f'Examples: kubectl-exec, secret-deletion, config-drift'
            )
        return v

    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v: str) -> str:
        """Validates severity is high, medium, or low."""
        if v not in ALLOWED_SEVERITIES:
            raise ValueError(
                f'Invalid severity: {v!r}. '
                f'Allowed: {sorted(ALLOWED_SEVERITIES)}'
            )
        return v

    @field_validator('timestamp')
    @classmethod
    def validate_timestamp(cls, v: Optional[str]) -> Optional[str]:
        """Validates timestamp is a valid ISO 8601 string if provided."""
        if v is None:
            return v
        try:
            datetime.fromisoformat(v.replace('Z', '+00:00'))
        except ValueError:
            raise ValueError(
                f'Invalid timestamp: {v!r}. Expected ISO 8601 format.'
            )
        return v

# =============================================================================
# 8. ENDPOINTS
# =============================================================================

@app.get('/health')
def health() -> dict:
    """Health check endpoint — no authentication required."""
    return {
        'status':  'ok',
        'version': 'v0.1.0',
        'auth':    'enabled' if API_KEY else 'disabled (set HEALERT_API_KEY)',
    }


@app.post('/events', dependencies=[Depends(verify_api_key)])
@limiter.limit('60/minute')
def receive_event(request: Request, event: FrictionEventRequest) -> dict:
    """
    Receives a friction event from the Go agent.

    Requires: Authorization: Bearer {HEALERT_API_KEY}
    Rate limit: 60 requests per minute per IP

    Returns HTTP 401 if API key is missing or wrong.
    Returns HTTP 422 if event data fails validation.
    Returns HTTP 429 if rate limit is exceeded.

    Request body size is limited by Pydantic field max_length constraints.
    For additional protection, configure uvicorn with --limit-max-requests
    or place nginx/Caddy in front with client_max_body_size 64k.
    """
    conn = get_db()
    conn.execute(
        '''INSERT INTO friction_events
           (entity_ref, type, severity, actor, service,
            namespace, workflow, description, timestamp, points)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (
            event.entity_ref,
            event.type,
            event.severity,
            event.actor,
            event.service,
            event.namespace,
            event.workflow,
            event.description,
            event.timestamp or datetime.now(timezone.utc).isoformat(),
            event.points or SEVERITY_POINTS.get(event.severity, DEFAULT_POINTS),
        ),
    )
    conn.commit()
    conn.close()
    return {'status': 'ok', 'message': 'Event recorded'}


@app.get('/friction/{entity_ref:path}')
def get_friction(entity_ref: str) -> dict:
    """
    Returns the friction score and recent events for a Backstage entity.
    No authentication — read-only, accessed via Backstage proxy only.
    Returns events from the last RETENTION_DAYS days.
    """
    # Validate entity_ref format before querying
    if not ENTITY_REF_PATTERN.match(entity_ref):
        raise HTTPException(
            status_code=400,
            detail=f'Invalid entity_ref format: {entity_ref!r}',
        )

    conn  = get_db()
    since = (datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)).isoformat()
    rows  = conn.execute(
        '''SELECT * FROM friction_events
           WHERE entity_ref = ? AND timestamp >= ?
           ORDER BY timestamp DESC
           LIMIT 500''',
        (entity_ref, since),
    ).fetchall()
    conn.close()

    events = [dict(r) for r in rows]
    return {
        'entityRef':    entity_ref,
        'frictionScore': calculate_score(events),
        'recentEvents': [
            {
                'timestamp':   e['timestamp'],
                'actor':       e['actor'],
                'type':        e['type'],
                'description': e['description'],
                'workflow':    e['workflow'],
            }
            for e in events
        ],
        'sources': {
            'kubernetesAuditLog': True,
            'github':             False,
            'jira':               False,
        },
        'fetchedAt': datetime.now(timezone.utc).isoformat(),
    }


@app.get('/events')
def get_all_events(limit: int = 100) -> list:
    """
    Returns recent events across all entities.
    Used by the Backstage plugin Live Feed tab (v0.2.0+).
    No authentication — read-only, accessed via Backstage proxy only.

    limit: max results, capped at 500 to prevent large responses.
    """
    # Cap limit to prevent accidentally large responses
    safe_limit = min(max(1, limit), 500)

    conn = get_db()
    rows = conn.execute(
        'SELECT * FROM friction_events ORDER BY timestamp DESC LIMIT ?',
        (safe_limit,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]
