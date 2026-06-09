# Security Policy — Healert Backend

## Supported Versions

| Version | Supported |
|---|---|
| v0.1.0   |  Yes    |

## Reporting a Vulnerability

Please do NOT open a public GitHub issue for security vulnerabilities.

**Email:** Security@healert.io

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected version
- Potential impact

We will respond within 48 hours and aim to release a fix within 7 days
for critical issues.

## Security Model

- API key authentication on all write endpoints (hmac.compare_digest)
- Rate limiting: 60 POST /events per minute per IP
- CORS restricted to configured origins only
- Input validation via Pydantic — entity_ref format, severity whitelist
- Parameterised SQL queries — no string concatenation
- Swagger UI disabled in production
- Binds to 127.0.0.1 by default
- SQLite WAL mode — no corruption on unclean shutdown
- Events deleted after HEALERT_RETENTION_DAYS days

## Production Recommendations

- Always run behind nginx or similar reverse proxy with HTTPS
- Never expose port 8000 directly to the internet
- Rotate API key regularly: ./healert.sh setup rotate
- Use a dedicated system user with minimal permissions
- Store .env with chmod 600
