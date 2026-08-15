# 02 — АНАЛИЗ СЕРВЕРНОГО API RustSecure

Цель: понять, что за эндпоинты, как устроено шифрование payload'ов, и как расшифровать
скачанные `core.enc` / `native.enc`.

---

## 1. Эндпоинты (проверены вживую 2026-08-15)

| URL | Метод | Ответ | Что это |
|-----|-------|-------|---------|
| `https://rustsecure.ru/api/loader/core` | GET | `200`, `application/octet-stream` | **Core payload** (managed .NET DLL), зашифрован |
| `https://rustsecure.ru/api/loader/native` | GET | `200`, `application/octet-stream` | **Native payload** (нативная DLL), зашифрован |
| `http://2.26.50.179:5003/api/manifest/checksum` | GET | `200`, `text/plain` | **SHA-256 checksum** манифеста |

### Ответ checksum
```
97D73857C54C23893A1092142B7B4D85A56E69AA20890EA8247F564668271440
```
Это 64 hex-символа = **SHA-256**. Вероятно — контрольная сумма манифеста версий
(серверная часть проверки целостности / актуальности сборки).

---

## 2. Заголовки ответа core/native (КЛЮЧЕВОЕ)

Сервер: `Server: Kestrel` (ASP.NET Core), за обратным прокси `Via: 1.1 Caddy`.

Пример (core):
```
X-Rs-Alg:   AES-256-CBC+HMAC-SHA256
X-Rs-Iv:    w6zwZFLN9_sb7uTZgmE4ww      # base64url, 16 байт — IV AES
X-Rs-Mac:   KBtsPj_tZVlRPfz7FmxiVm4wZaqmzyL5V9r58eww9bI   # base64url, 32 байта — HMAC-SHA256
X-Rs-Nonce: tidnxTZ4igTlJHuMgm7FxQ      # base64url, 16 байт — nonce
X-Rs-Ts:    1786792769                  # unix timestamp
```

Пример (native):
```
X-Rs-Iv:    8vfeDbVAoe5_mni__36dhg
X-Rs-Mac:   5d3AAP3MgfS272daoZaxqo3tsJUHeanVwmABebPB_nE
X-Rs-Nonce: o45ve-1cqwLQxxb-LNcSMw
```

### Смысл заголовков
- `X-Rs-Alg` — алгоритм: **AES-256-CBC + HMAC-SHA256** (шифрование + аутентификация).
- `X-Rs-Iv` — вектор инициализации AES (base64url → 16 байт).
- `X-Rs-Mac` — HMAC-SHA256 подпись (base64url → 32 байта). Клиент проверяет её до расшифровки.
- `X-Rs-Nonce` — одноразовый nonce (base64url → 16 байт), участвует в выводе ключа.
- `X-Rs-Ts` — метка времени, участвует в выводе ключа и защите от replay.

> base64url: символы `-` и `_` вместо `+` и `/`, без `=`-паддинга.
> IV и nonce = 22 символа → 16 байт; MAC = 43 символа → 32 байта.

---

## 3. Тело ответа

- `Content-Type: application/octet-stream`.
- Тело = **AES-256-CBC шифротекст** (размер кратен 16).
- Каждый запрос возвращает **новый nonce / IV / размер** (payload пересобирается заново):
  core был 84 384 / 97 216 / 125 824 байт в разных запросах — данные переупаковываются.

---

## 4. Схема криптографии (гипотеза, требует подтверждения по коду загрузчика)

1. Клиент и сервер знают общий секрет **`sharedSecret`** (зашит в загрузчик, одна из 347 строк).
2. Вывод ключа (KDF) — примерно:
   `key = HMAC-SHA256(sharedSecret, nonce || ts)`  (или PBKDF2) → 32 байта.
3. Подпись: `mac = HMAC-SHA256(key, nonce || ts || iv || ciphertext)` → 32 байта.
4. Клиент: проверяет `mac`, затем `AES-256-CBC-decrypt(ciphertext, key, iv)`.

### Где это в коде загрузчика (методы, которые надо прочитать)
- `DecryptPayload` — **0x2FD**
- `ComputeSignature` — **0x2FE**
- `HmacSha256` — **0x300 / 0x301**

Прочитать их IL (через dnfile/dncil, как в `dump_089e.py`) и восстановить точный KDF.

---

## 5. Как расшифровать payload'ы (пошагово)

1. Получить `sharedSecret` (из этапа 1 — расшифровка 347 строк).
2. Прочитать IL методов 0x2FD/0x2FE/0x300/0x301 → точный KDF и порядок полей HMAC.
3. Для каждого скачанного файла (`re_analysis\payloads\*.enc` + соседний `*.headers.txt`):
   - взять `X-Rs-Iv`, `X-Rs-Nonce`, `X-Rs-Ts`, `X-Rs-Mac` из headers-файла;
   - перевести из base64url в байты;
   - вычислить ключ и проверить MAC;
   - расшифровать AES-256-CBC.
4. Результат: `core` = managed DLL (`RustSecure.Core.dll` — **уже выдан клиентом, 19.2 МБ**),
   `native` = нативная DLL для инжекта.

### Файлы payload'ов на диске
```
re_analysis\payloads\core.enc        + core.headers.txt
re_analysis\payloads\native.enc      + native.headers.txt
re_analysis\payloads\manifest_checksum.txt
```

---

## 6. Что это за файлы и зачем (ответ на вопрос клиента)

- **`/api/loader/core`** → **Core payload** — управляемый .NET DLL, который инжектится в Rust
  и содержит основную логику античита. Это и есть
  `RustSecure.Core.dll`.
- **`/api/loader/native`** → **Native payload** — нативная DLL (инжект на уровне WinAPI),
  загружается перед/вместе с Core.
- **`/api/manifest/checksum`** → SHA-256 контрольная сумма манифеста версий —
  серверная сверка целостности/актуальности (какой payload актуален сейчас).

> Итого: сервер раздаёт **шифрованные DLL-полезные нагрузки** с аутентификацией HMAC.
> Чтобы их получить в открытом виде, нужен `sharedSecret` из загрузчика.
