# 14 — Screenshot Capture Service (серверные скриншоты)

## Где (файл + метод/адрес)
- Сборка: RustSecure.Core.dll
- Основной сервис: `IInternalMessageUCOMITypeComp/ScreenshotCaptureService.cs`
- GDI fallback: `WinWindowsRegisterDynamicProperty/MonitorFramePerformance.cs`
- Серверные команды: `RequestScreenshot`, `RequestScreenshotV2`
- Upload endpoint: `/api/ingest/screenshot` [752280941]
- Обфускация: Agile.NET

## Как работает

### Основной сервис (ScreenshotCaptureService)

1. **CaptureOnce(CaptureMethod, int timeoutMs)** — делает один скриншот.
   - `CaptureMethod` определяет способ захвата:
     - DXGI (через DxgiDuplicator, см. #13): строка [752280761] `DXGI: `
     - WGC (Windows Graphics Capture): строка [752280760] `WGC: `
     - GDI (BitBlt fallback)

2. **ReadGameWindowDisplayAffinity()** — проверяет DisplayAffinity окна игры:
   - Строка [752280930] `&affinity=`
   - Если окно помечено `WDA_EXCLUDEFROMCAPTURE` — детектирует защиту от захвата

### GDI Fallback (MonitorFramePerformance)
Если DXGI и WGC недоступны, используется GDI:
- `CreateCompatibleDC`, `CreateCompatibleBitmap`, `BitBlt`, `SelectObject`
- Ошибки: [752280752-758] — подробные сообщения для каждого этапа GDI-захвата
- Поиск окна по классу: `UnityWndClass` [752280762], заголовку: `Rust` [752280757]

### Отправка скриншота
1. Скриншот кодируется в JPEG: [752280824] `image/jpeg`
2. Подписывается HMAC: метод `ComputeScreenshotSignature()`
3. URL: `/api/ingest/screenshot` с параметрами:
   - `?method=` [752280934] (DXGI/WGC/GDI)
   - `&width=` [752280928]
   - `&height=` [752280931]
   - `&affinity=` [752280930]

### Триггеры
- Сервер отправляет WebSocket-команду `RequestScreenshot` или `RequestScreenshotV2`
- Скриншот делается и отправляется автоматически

## Как обойти

### Вариант A — Патч CaptureOnce() (рекомендуется)
Заменить тело `CaptureOnce()` на:
```
ldnull      // вернуть null (нет скриншота)
ret
```
Сервер получит ошибку/пустой ответ.

### Вариант B — Патч обработки серверной команды
Найти обработчик `RequestScreenshot`/`RequestScreenshotV2` в WebSocket-коде и NOP-ить вызов `CaptureOnce`. Команда будет проигнорирована.

### Вариант C — Патч отправки
Найти HTTP-запрос к `/api/ingest/screenshot` и:
- NOP-ить вызов `HttpClient.PostAsync` / `SendAsync`
- Или заменить URL на `ldstr "http://127.0.0.1/null"`

### Вариант D — Подмена скриншота
Перехватить результат CaptureOnce и заменить на заранее подготовленное изображение (чёрный экран / скриншот чистой игры).

### Вариант E — Патч GDI fallback
В `MonitorFramePerformance` NOP-ить вызовы `BitBlt` и `CreateCompatibleBitmap`. GDI-захват вернёт ошибку.

## Статус
- [ ] проверено / [ ] подтверждено
