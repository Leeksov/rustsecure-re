# 16 — WebSocket Threat Reporting (связь с сервером)

## Где (файл + метод/адрес)
- Сборка: RustSecure.Core.dll
- Файл: `CONNECTDATAOldValue/SynchronizeFrameUpdate.cs`
- WebSocket URL: [752280813] `wss://rustsecure.ru/ws`
- Telegram: [752280825] `https://t.me/rustsecure`
- Обфускация: Agile.NET

## Как работает

### WebSocket-протокол

Подключение к `wss://rustsecure.ru/ws` с handshake:
1. Клиент отправляет `client-hello` [752280944] с nonce [752280906]
2. Сервер отвечает `server-hello` / `ServerHello` [752280905] с:
   - Публичный ключ: `pub` [752280907]
   - Подпись: `sig` [752280900], `","sig":"` [752280908]
   - Timestamp: `ts` [752280901]
   - Тип: `type` [752280910]
3. Верификация: проверка подписи сервера, валидация ключа

Ошибки handshake:
- [752280903] `Invalid server public key`
- [752280904] `Invalid handshake response type`
- [752280897] `Server handshake signature mismatch`
- [752280911] `Server handshake response is empty`
- [752280896] `Socket is not connected`

### Типы сообщений

| Тип | Строка ID | Описание |
|-----|-----------|----------|
| ThreatDetected | [752280939] | Отправка детекции на сервер |
| PlayerConnected | [752280936] | Игрок подключился |
| PlayerDisconnected | [752280942] | Игрок отключился |
| LocalAccountsCaptured | [752280935] | Отправка списка Steam-аккаунтов |
| Heartbeat | [752280932] | Поддержание соединения |
| RequestScreenshot | — | Сервер запрашивает скриншот |
| RequestScreenshotV2 | — | Сервер запрашивает скриншот v2 |
| BanPlayer | — | Сервер банит игрока |

### Методы

- **ReportThreatAsync()** — отправка `ThreatDetected` с деталями: `threatType` [752280938], `details` [752280933], `steamId` [752280937]
- **BuildPlayerConnectedJson()** — формирование JSON для PlayerConnected
- **SendLocalAccountsAsync()** — отправка списка Steam-аккаунтов из loginusers.vdf [752280748]

### Бан
Строка бана: `Banned by RustSecure.`
Формат: `BanPlayer|` — сервер отправляет команду бана.

### Криптография
- Handshake подписан ECDSA (pub/sig/nonce)
- Скриншоты подписаны HMAC (ComputeScreenshotSignature)
- Начальный токен: [752280812] `RSv1.HoNrj7uosYTypvYR58Zq4YJ3d5RtI8AqtnnjB6qG5YfH3WY9dpNE1Hx1hbv`

## Как обойти

### Вариант A — Патч подключения (рекомендуется)
Найти вызов `ClientWebSocket.ConnectAsync` к `wss://rustsecure.ru/ws` и заменить URL:
```
ldstr "wss://127.0.0.1:1/ws"    // несуществующий хост
```
Или NOP-ить весь метод подключения. Без WebSocket сервер не получит никаких данных.

### Вариант B — Патч ReportThreatAsync()
Заменить тело `ReportThreatAsync()` на:
```
ldsfld Task.CompletedTask
ret
```
Угрозы не будут отправляться.

### Вариант C — Блокировка всех исходящих сообщений
Найти метод отправки WebSocket-сообщений (`SendAsync` или обёртку) и NOP-ить. Соединение установится, но данные не уйдут.

### Вариант D — Патч обработки серверных команд
Найти обработчик входящих сообщений (switch по `type`) и:
- Убрать ветку `RequestScreenshot` / `RequestScreenshotV2` — сервер не сможет запросить скриншот
- Убрать ветку `BanPlayer` — сервер не сможет забанить

### Вариант E — Патч SendLocalAccountsAsync()
NOP-ить метод чтобы список Steam-аккаунтов не отправлялся на сервер.

### Вариант F — DNS/Firewall блокировка
На уровне ОС заблокировать `rustsecure.ru` в hosts или firewall. Простой, но не IL-патч.

## Статус
- [ ] проверено / [ ] подтверждено
