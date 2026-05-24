# Healert Backend

**The self-hosted FastAPI backend for the Healert Friction Intelligence Platform.**

Receives friction events from the Go agent, calculates friction scores using
exponential time decay, and serves data to the Backstage plugin via REST API.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/version-0.1.1-green.svg)](https://github.com/healert-io/backend/releases)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)

---

## Overview

```
Healert Go Agent  (github.com/healert-io/agent)
      |  POST /events  (API key auth, rate limited 60/min)
      v
Healert Backend                         <- this repo
  FastAPI + SQLite + WAL mode
  Exponential decay scoring
      |  GET /friction/{entityRef}
      v
Backstage Proxy  (/api/proxy/healert)
      |
      v
@backstage-community/plugin-healert
  FrictionScoreCard + FrictionHeatmap
```

---

## Repository Structure

```
healert-backend/
|
+-- main.py           FastAPI backend (605 lines, 8 sections)
|                     1. Configuration   env vars and constants
|                     2. Rate Limiter    SlowAPI, 60 req/min on POST /events
|                     3. App Setup       FastAPI, CORS middleware
|                     4. Security        API key auth, hmac.compare_digest
|                     5. Database        SQLite, WAL mode, retention thread
|                     6. Scoring         Exponential time decay formula
|                     7. Request Models  Pydantic validators
|                     8. Endpoints       /health, /events, /friction, /events
|
+-- requirements.txt  4 dependencies: fastapi, uvicorn, pydantic, slowapi
|
+-- .env.example      All configuration variables documented
|
+-- catalog-info.yaml Backstage entity definition
|
+-- SECURITY.md       Vulnerability reporting process
|
+-- CHANGELOG.md      Version history
|
+-- LICENSE           Apache-2.0, Copyright 2026 Healert OÜ
```

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.8+ | Runtime |
| pip | Any | Package installer |
| curl | Any | Health check verification |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/healert-io/backend.git
cd backend

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure
cp .env.example .env
chmod 600 .env
# Edit .env and set HEALERT_API_KEY:
#   openssl rand -base64 32

# 5. Start
uvicorn main:app --host 127.0.0.1 --port 8000

# 6. Verify
curl http://localhost:8000/health
```

Expected:
```json
{"status": "ok", "version": "0.1.1", "auth": "enabled"}
```

---

## Managed by healert.sh "Recommended"

In production the backend is managed by the agent management script:
# [healert-io/agent](https://github.com/healert-io/agent) | Go agent + DaemonSet + healert.sh |

```bash
# From the agent directory (github.com/healert/agent)
./healert.sh start backend      # start backend only
./healert.sh stop backend       # stop backend only
./healert.sh restart            # restart both backend and agent
./healert.sh status             # check backend health
./healert.sh reset --confirm    # delete and recreate database
./healert.sh configure scoring  # update scoring parameters
```

---

## Configuration

All configuration via environment variables (see `.env.example`):

### Required

| Variable | Description |
|---|---|
| `HEALERT_API_KEY` | Bearer token for POST /events — generate with `openssl rand -base64 32` |

### Optional

| Variable | Default | Description |
|---|---|---|
| `HEALERT_DB` | `./healert.db` | SQLite database path |
| `HEALERT_HOST` | `127.0.0.1` | Bind host — see Deployment section |
| `HEALERT_PORT` | `8000` | Bind port |
| `HEALERT_ALLOWED_ORIGINS` | `http://localhost:3000` | CORS origins (comma-separated) |
| `HEALERT_RETENTION_DAYS` | `30` | Event retention in days |

### Scoring (configurable via `./healert.sh configure scoring`)

| Variable | Default | Description |
|---|---|---|
| `SCORE_CRITICAL_THRESHOLD` | `50` | Weighted points for score=100 |
| `SCORE_DECAY_HALF_LIFE` | `7` | Event weight half-life in days |
| `SCORE_RETENTION_DAYS` | `30` | Event scoring window in days |

**Tuning guide:**

```bash
./healert.sh configure scoring --threshold 20 --half-life 3   # strict
./healert.sh configure scoring --threshold 50 --half-life 7   # default
./healert.sh configure scoring --threshold 100 --half-life 14 # lenient
```

---

## API Reference

### GET /health

No authentication required. Returns service status.

```bash
curl http://localhost:8000/health
```

```json
{"status": "ok", "version": "0.1.1", "auth": "enabled"}
```

---

### POST /events

Receives a friction event from the Go agent.

**Auth:** `Authorization: Bearer {HEALERT_API_KEY}`
**Rate limit:** 60 requests/minute per IP

```bash
curl -X POST http://localhost:8000/events \
  -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "entity_ref":  "component:default/payments-api",
    "type":        "kubectl-exec",
    "severity":    "high",
    "actor":       "dev@company.com",
    "workflow":    "deploy",
    "description": "kubectl exec on pods/payments-api by dev@company.com"
  }'
```

**Response:**
```json
{"status": "ok", "message": "Event recorded"}
```

**Error codes:**

| Code | Reason |
|---|---|
| 401 | Missing or invalid API key |
| 422 | Validation failed (bad entity_ref, unknown severity, etc.) |
| 429 | Rate limit exceeded (60/min) |

---

### GET /friction/{entity_ref}

Returns friction score and recent events for a Backstage entity.
No authentication required — read-only, accessed via Backstage proxy.

```bash
curl http://localhost:8000/friction/component:default/payments-api
```

```json
{
  "entityRef": "component:default/payments-api",
  "frictionScore": {
    "score": 60,
    "severity": "high",
    "bypassCount": 3,
    "overheadHoursPerEngineer": 1.3,
    "topFrictionWorkflow": "deploy",
    "calculatedAt": "2026-05-22T10:00:00Z"
  },
  "recentEvents": [
    {
      "timestamp": "2026-05-22T10:00:00Z",
      "actor": "dev@company.com",
      "type": "kubectl-exec",
      "description": "kubectl exec on pods/payments-api",
      "workflow": "deploy"
    }
  ],
  "sources": {
    "kubernetesAuditLog": true,
    "github": false,
    "jira": false
  },
  "fetchedAt": "2026-05-22T10:01:00Z"
}
```

---

### GET /events

Returns recent events across all entities. No authentication required.

```bash
curl "http://localhost:8000/events?limit=50"
```

Limit is capped at 500 to prevent large responses.

---

## Scoring Formula

The friction score uses exponential time decay — recent events matter more
than old ones. Scores decay automatically — no manual resets needed.

```
Score = min(100, round(weighted_total / threshold * 100))

weighted_total = sum(points * 0.5 ^ (age_days / half_life))
```

### Severity Points

| Severity | Points |
|---|---|
| high | 10 |
| medium | 6 |
| low | 3 |

### Score to Severity

| Score | Severity |
|---|---|
| 80-100 | Critical |
| 60-79 | High |
| 40-59 | Medium |
| 0-39 | Low |

### Examples (default settings)

| Scenario | Score | Severity |
|---|---|---|
| 0 events | 0 | Low |
| 1 high event today | 20 | Low |
| 3 high events today | 60 | High |
| 5 high events today | 100 | Critical |
| 5 high events — 7 days ago | 50 | Medium |
| 5 high events — 30 days ago | ~3 | Low (decayed) |

---

## Security

| Property | Implementation |
|---|---|
| API key auth | `hmac.compare_digest` — constant-time, prevents timing attacks |
| Rate limiting | SlowAPI — 60 POST /events per minute per IP |
| CORS | Restricted to `HEALERT_ALLOWED_ORIGINS` only |
| Input validation | Pydantic — entity_ref regex, severity whitelist, type format |
| SQL injection | Parameterised queries only — zero string concatenation |
| Path traversal | `os.path.abspath()` on DB_PATH — no `..` allowed |
| Swagger UI | Disabled in production (`docs_url=None`, `redoc_url=None`) |
| Bind address | `127.0.0.1` by default — not exposed to network |
| WAL mode | SQLite WAL — no DB corruption on unclean shutdown |
| Retention | Events auto-deleted after `HEALERT_RETENTION_DAYS` days |
| API key storage | `.env` with `chmod 600` — never committed to git |

---

## Deployment

### Local Development

Default — binds to `127.0.0.1`, accessible from localhost only:

```bash
uvicorn main:app --host 127.0.0.1 --port 8000
```

### Docker Testing

When testing with Docker containers that need to reach the backend
from the Docker bridge network, bind to all interfaces:

```bash
# Set in .env for Docker testing only
HEALERT_HOST=0.0.0.0

# Or export before starting
export HEALERT_HOST=0.0.0.0
./healert.sh start backend
```

**Note:** `0.0.0.0` is acceptable for local testing only.
Always use nginx or a ClusterIP Service in production.

### systemd (Production)

Backend binds to `127.0.0.1` — nginx handles external traffic:

```ini
[Unit]
Description=Healert Backend
After=network.target

[Service]
Type=simple
User=healert
WorkingDirectory=/opt/healert/backend
EnvironmentFile=/opt/healert/backend/.env
ExecStart=/opt/healert/backend/venv/bin/uvicorn main:app \
  --host 127.0.0.1 \
  --port 8000 \
  --log-level info
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable:

```bash
sudo systemctl enable --now healert-backend
sudo systemctl status healert-backend
```

### nginx (HTTPS Reverse Proxy)

```nginx
server {
    listen 443 ssl;
    server_name healert.company.com;

    ssl_certificate     /etc/ssl/healert.crt;
    ssl_certificate_key /etc/ssl/healert.key;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        client_max_body_size 64k;
    }
}
```

### Kubernetes DaemonSet (In-Cluster)

For production DaemonSet deployments run the backend as a ClusterIP Service.
Pods reach it via internal DNS — no `0.0.0.0` needed:

```yaml
# In daemonset.yaml:
- name: HEALERT_BACKEND_URL
  value: "http://healert-backend.healert-system.svc.cluster.local:8000"
```

Backend binds to `127.0.0.1` — traffic routed via Kubernetes Service internally.

---

## Related Repositories

| Repo | Description |
|---|---|
| [healert-io/agent](https://github.com/healert-io/agent) | Go agent + DaemonSet + healert.sh |
| [backstage/community-plugins](https://github.com/backstage/community-plugins) | Backstage plugin (`@backstage-community/plugin-healert`) |

---

## License

Apache License 2.0 — Copyright 2026 Healert OÜ

See [LICENSE](./LICENSE) for the full license text.
