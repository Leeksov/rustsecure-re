# RustSecure Server — Security Analysis

**Target:** rustsecure.ru (144.31.237.250), backend 2.26.50.179
**Date:** 2026-08-15

---

## Infrastructure

| Host | Ports | Stack |
|------|-------|-------|
| `144.31.237.250` (rustsecure.ru) | **443** (HTTPS), **3389** (RDP, IP-filtered), **9000** (MinIO S3) | Kestrel (ASP.NET) + Caddy reverse proxy, React SPA (Vite), Let's Encrypt TLS 1.2/1.3 |
| `2.26.50.179` (backend) | **80** (HTTP — full admin panel without Caddy), **3389** (RDP, IP-filtered), **5000** (Kestrel, empty), **5003** (Kestrel, manifest API) | Kestrel without reverse proxy |

---

## Critical Findings

### 1. MinIO S3 storage exposed without TLS (port 9000)

```
http://144.31.237.250:9000/
```

- Bucket `rustsecure` **exists** (AccessDenied on anonymous access)
- **STS endpoint active** — `AssumeRoleWithWebIdentity` leaks internal ARN:
  ```
  arn:minio:iam:::role/dummy-internal
  ```
- Health endpoint `/minio/health/live` accessible without authentication
- Traffic over HTTP — S3 keys interceptable via MITM
- CVE-2023-28432 (env var leak) — **patched**, not vulnerable
- Default credentials `minioadmin:minioadmin` — not working

### 2. Backend admin panel without TLS or Caddy (port 80)

```
http://2.26.50.179:80/
```

- Serves the **full admin panel** (same React SPA as rustsecure.ru)
- **No TLS** — credentials transmitted in plaintext
- **No Caddy** — no rate limiting on login
- Security headers set by Kestrel itself (X-Frame-Options, X-Content-Type-Options present)
- Port **5000** runs another Kestrel service (404 on all paths — internal microservice)
- Port **5003** — manifest API: `/api/manifest/checksum` without authentication

### 3. Payloads served without authentication

```
GET https://rustsecure.ru/api/loader/core → 200, application/octet-stream
GET https://rustsecure.ru/api/loader/native → 200, application/octet-stream
```

- Encrypted payloads (AES-256-CBC + HMAC-SHA256) downloadable **anonymously**
- IV, nonce, timestamp, MAC — in `X-Rs-*` headers, refreshed on every request
- Only protection is encryption, with the key derived from `sharedSecret` embedded in the client binary

### 4. Missing CSP and HSTS on main panel

```
Content-Security-Policy: ✗ MISSING
Strict-Transport-Security: ✗ MISSING
```

- XSS in the panel = full session hijack (no CSP)
- HTTP downgrade possible (no HSTS)
- MinIO has HSTS enabled, but the main panel does not

---

## High Severity

### 5. Full API structure leaked via client-side JS

Extracted from JS bundles (`/assets/index-D8zSoidR.js` + lazy-loaded chunks):

**Auth:**
- `POST /api/auth/login` — login, returns `{accessToken, username, role, allowedServers}`
- `GET /api/auth/me` — current user

**Admin:**
- `GET /api/admin/servers` — server list

**Players:**
- `GET /api/players/active` — active players
- `POST /api/players/ban` / `POST /api/players/unban` — ban/unban
- `GET /api/players/details?serverId=X&steamId=Y` — player details
- `GET /api/players/linked-accounts` — linked accounts
- `GET /api/players/local-accounts` — local accounts
- `GET /api/players/screenshots/content` — screenshot contents
- `POST /api/players/screenshots/request` — request screenshot from client
- `GET /api/players/database-snapshot` — database dump
- `GET /api/players/detection-stats` — detection statistics
- `GET /api/players/online-series` — online charts
- `GET /api/players/stats-summary` — summary
- `GET /api/players/audit-logs` — audit logs
- `GET /api/players/detections` — detections
- `GET /api/players/logs` — logs
- `POST /api/players/assfuck` — ?

**SignalR:**
- `/anticheat` — WebSocket hub (real-time events: PlayerUpdated, DetectionAdded, BansChanged, ScreenshotAdded, AuditChanged, LogAdded)

### 6. Internal model leaked via validation errors

Sending invalid JSON types:

```json
POST /api/auth/login
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

Server responds:

```json
{
  "errors": {
    "request": ["The request field is required."],
    "$.username": ["The JSON value could not be converted to System.String. Path: $.username | LineNumber: 0 | BytePositionInLine: 14."]
  },
  "traceId": "00-1d6c4931794cbd9f0b6d8db6b37df780-0f15897967430691-00"
}
```

Reveals: `request` model (wrapper DTO), JSON parser path, distributed traceId.

### 7. SuperAdmin role exposed in client-side JS

```javascript
(r?.role) === "SuperAdmin"
```

- Token stored in `localStorage["rs_token"]`
- Bearer JWT authentication
- Role determines access to admin functions

---

## Medium Severity

### 8. Weak rate limiting

Login blocked (429) after **~10 attempts**. On the backend (`2.26.50.179:80`) rate limiting is **absent**.

### 9. Server fingerprinting

```
Server: Kestrel
Via: 1.1 Caddy
Alt-Svc: h3=":443"; ma=2592000
```

### 10. RDP open but IP-filtered

Both servers have port 3389 open (TCP handshake completes), but drop the connection before the RDP handshake. Likely IP whitelist. BlueKeep (CVE-2019-0708) testing not possible without a trusted IP.

---

## Not Vulnerable

- **JWT** — `alg:none` bypass doesn't work, secret not in standard wordlists
- **SQL injection** — login handles `' OR 1=1--` without errors
- **NoSQL injection** — `{"$gt":""}` triggers type validation error, not injection
- **XXE** — server only accepts `application/json`, XML rejected (415)
- **SSTI** — `{{7*7}}` and `${7*7}` not interpreted
- **Path traversal** — `../` normalized by Caddy and Kestrel
- **Config disclosure** — `appsettings.json`, `.env`, `web.config` — 404
- **Source maps** — `.js.map` / `.css.map` — 404
- **CORS** — no `Access-Control-Allow-Origin`, cross-origin requests blocked
- **CVE-2023-28432** (MinIO env leak) — patched
- **Prototype pollution** — `__proto__` in JSON ignored

---

## Further Exploitation Vectors

1. **MinIO S3 brute** — access key / secret key brute-force
2. **Login brute via `2.26.50.179:80`** — no rate limiting
3. **JWT brute** — hashcat / john with large wordlist
4. **RDP brute from RU VPS** — `hydra -t 4 -l administrator -P rockyou.txt rdp://IP`
5. **MITM on backend** — intercept S3 keys and JWT over HTTP traffic
6. **Reverse sharedSecret from client** — decrypt payload → reconstruct server logic
