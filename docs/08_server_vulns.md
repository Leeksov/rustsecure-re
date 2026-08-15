# RustSecure Server — Security Analysis

**Target:** rustsecure.ru (144.31.237.250), backend 2.26.50.179
**Date:** 2026-08-15

---

## Инфраструктура

| Хост | Порты | Стек |
|------|-------|------|
| `144.31.237.250` (rustsecure.ru) | **443** (HTTPS), **3389** (RDP, IP-filtered), **9000** (MinIO S3) | Kestrel (ASP.NET) + Caddy reverse proxy, React SPA (Vite), Let's Encrypt TLS 1.2/1.3 |
| `2.26.50.179` (backend) | **80** (HTTP — полная панель без Caddy), **3389** (RDP, IP-filtered), **5000** (Kestrel, пустой), **5003** (Kestrel, manifest API) | Kestrel без reverse proxy |

---

## Критические находки

### 1. MinIO S3 хранилище открыто без TLS (порт 9000)

```
http://144.31.237.250:9000/
```

- Бакет `rustsecure` **существует** (AccessDenied на анонимный доступ)
- **STS endpoint активен** — `AssumeRoleWithWebIdentity` раскрывает внутренний ARN:
  ```
  arn:minio:iam:::role/dummy-internal
  ```
- Health endpoint `/minio/health/live` доступен без аутентификации
- Трафик по HTTP — S3-ключи перехватываются при MITM
- CVE-2023-28432 (env var leak) — **пропатчен**, не уязвим
- Дефолтные креды `minioadmin:minioadmin` — не работают

### 2. Backend панель без TLS и без Caddy (порт 80)

```
http://2.26.50.179:80/
```

- Отдаёт **полную админ-панель** (тот же React SPA что на rustsecure.ru)
- **Без TLS** — credentials передаются открытым текстом
- **Без Caddy** — нет rate limiting на login
- Security headers ставит сам Kestrel (X-Frame-Options, X-Content-Type-Options есть)
- На порту **5000** ещё один Kestrel-сервис (404 на всех путях — внутренний микросервис)
- На порту **5003** — manifest API: `/api/manifest/checksum` без аутентификации

### 3. Payload раздаётся без аутентификации

```
GET https://rustsecure.ru/api/loader/core → 200, application/octet-stream
GET https://rustsecure.ru/api/loader/native → 200, application/octet-stream
```

- Зашифрованные payload (AES-256-CBC + HMAC-SHA256) скачиваются **анонимно**
- IV, nonce, timestamp, MAC — в заголовках `X-Rs-*`, обновляются при каждом запросе
- Единственная защита — шифрование, ключ для которого выводится из `sharedSecret` в клиентском бинарнике

### 4. Отсутствуют CSP и HSTS на основной панели

```
Content-Security-Policy: ✗ MISSING
Strict-Transport-Security: ✗ MISSING
```

- XSS в панели = полный захват сессии (нет CSP)
- Возможен downgrade до HTTP (нет HSTS)
- При этом на MinIO HSTS установлен

---

## Высокий уровень

### 5. Утечка структуры API через клиентский JS

Из JS-бандлов (`/assets/index-D8zSoidR.js` + lazy-loaded чанки) извлечена полная карта API:

**Auth:**
- `POST /api/auth/login` — логин, возвращает `{accessToken, username, role, allowedServers}`
- `GET /api/auth/me` — текущий пользователь

**Admin:**
- `GET /api/admin/servers` — список серверов

**Players:**
- `GET /api/players/active` — активные игроки
- `POST /api/players/ban` / `POST /api/players/unban` — бан/разбан
- `GET /api/players/details?serverId=X&steamId=Y` — детали игрока
- `GET /api/players/linked-accounts` — привязанные аккаунты
- `GET /api/players/local-accounts` — локальные аккаунты
- `GET /api/players/screenshots/content` — содержимое скриншотов
- `POST /api/players/screenshots/request` — запрос скриншота у клиента
- `GET /api/players/database-snapshot` — дамп базы данных
- `GET /api/players/detection-stats` — статистика детекций
- `GET /api/players/online-series` — онлайн-графики
- `GET /api/players/stats-summary` — сводка
- `GET /api/players/audit-logs` — аудит
- `GET /api/players/detections` — детекции
- `GET /api/players/logs` — логи
- `POST /api/players/assfuck` — ?

**SignalR:**
- `/anticheat` — WebSocket hub (real-time events: PlayerUpdated, DetectionAdded, BansChanged, ScreenshotAdded, AuditChanged, LogAdded)

### 6. Утечка внутренней модели через ошибки валидации

При отправке невалидного типа в JSON:

```json
POST /api/auth/login
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

Сервер возвращает:

```json
{
  "errors": {
    "request": ["The request field is required."],
    "$.username": ["The JSON value could not be converted to System.String. Path: $.username | LineNumber: 0 | BytePositionInLine: 14."]
  },
  "traceId": "00-1d6c4931794cbd9f0b6d8db6b37df780-0f15897967430691-00"
}
```

Раскрывает: модель `request` (wrapper DTO), JSON parser path, distributed traceId.

### 7. Роль SuperAdmin в клиентском JS

```javascript
(r?.role) === "SuperAdmin"
```

- Токен хранится в `localStorage["rs_token"]`
- Bearer JWT аутентификация
- Роль определяет доступ к admin-функциям

---

## Средний уровень

### 8. Слабый rate limiting

Login блокируется (429) после **~10 попыток**. На бэкенде (`2.26.50.179:80`) rate limiting **отсутствует**.

### 9. Server fingerprint

```
Server: Kestrel
Via: 1.1 Caddy
Alt-Svc: h3=":443"; ma=2592000
```

### 10. RDP открыт, но IP-фильтрован

Оба сервера имеют порт 3389 открытым (TCP handshake проходит), но сбрасывают соединение до RDP-хендшейка. Вероятно, whitelist по IP. Проверка на BlueKeep (CVE-2019-0708) невозможна без доверенного IP.

---

## Что НЕ уязвимо

- **JWT** — `alg:none` bypass не работает, секрет не в стандартных словарях
- **SQL injection** — login обрабатывает `' OR 1=1--` без ошибок
- **NoSQL injection** — `{"$gt":""}` вызывает ошибку валидации типа, не инъекцию
- **XXE** — сервер принимает только `application/json`, XML отклоняется (415)
- **SSTI** — `{{7*7}}` и `${7*7}` не интерпретируются
- **Path traversal** — `../` нормализуется Caddy и Kestrel
- **Config disclosure** — `appsettings.json`, `.env`, `web.config` — 404
- **Source maps** — `.js.map` / `.css.map` — 404
- **CORS** — нет `Access-Control-Allow-Origin`, кросс-доменные запросы блокируются
- **CVE-2023-28432** (MinIO env leak) — пропатчен
- **Prototype pollution** — `__proto__` в JSON игнорируется

---

## Рекомендации по дальнейшей эксплуатации

1. **MinIO S3 brute** — подбор access key / secret key
2. **Login brute через `2.26.50.179:80`** — без rate limiting
3. **JWT brute** — hashcat / john с большим словарём
4. **RDP brute с RU VPS** — `hydra -t 4 -l administrator -P rockyou.txt rdp://IP`
5. **MITM на бэкенд** — перехват S3-ключей и JWT через HTTP трафик
6. **Реверс sharedSecret из клиента** — расшифровка payload → реконструкция серверной логики
