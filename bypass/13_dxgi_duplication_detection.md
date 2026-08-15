# 13 — DXGI Duplication Detection (захват экрана)

## Где (файл + метод/адрес)
- Сборка: RustSecure.Core.dll
- Файл: `getDeploymentManifestBytesIntegrityStream/DxgiDuplicator.cs`
- Строки: [752280736] `DXGI AcquireNextFrame failed: `, [752280764] `No suitable DXGI output for duplication`, [752280767] `DXGI init failed: `
- Обфускация: Agile.NET

## Как работает

Использует DXGI Desktop Duplication API (через SharpDX) для захвата экрана игры. Это серверная функция — по запросу сервера делает скриншот через DXGI.

### Компоненты SharpDX

1. **Factory1** — перечисление GPU-адаптеров
2. **Adapter1** — конкретный GPU-адаптер
3. **Output1** — монитор/выход адаптера
4. **OutputDuplication** — дупликация вывода (захват кадров)
5. **Texture2D** — текстура с захваченным кадром

### Процесс захвата

1. Инициализация: `Factory1` -> `Adapter1` -> `Output1` -> `DuplicateOutput()` -> `OutputDuplication`
2. Захват кадра: `AcquireNextFrame(timeout)` -> `Texture2D`
3. Копирование: чтение пикселей из GPU-текстуры в CPU-память
4. Обработка ошибок:
   - `DXGI AcquireNextFrame failed` — таймаут или ошибка захвата
   - `DXGI frame timeout` [752280737]
   - `DXGI could not recover capture pipeline` [752280738]
   - `DXGI exception` [752280739]
   - `No suitable DXGI output for duplication` — нет доступного монитора
   - `DXGI init failed` — ошибка инициализации

### Двойное назначение
DXGI Duplicator используется как для детекции (обнаружение overlay/чит-окон через анализ кадров), так и для серверных скриншотов (см. #14).

## Как обойти

### Вариант A — Патч инициализации (рекомендуется)
В конструкторе/init-методе `DxgiDuplicator` заставить инициализацию "провалиться":
```
// Заменить DuplicateOutput() вызов на:
ldnull      // null OutputDuplication
ret         // или throw
```
Все последующие попытки захвата вернут ошибку.

### Вариант B — Патч AcquireNextFrame
Найти вызов `OutputDuplication.AcquireNextFrame(timeout)` и заменить результат на DXGI_ERROR_WAIT_TIMEOUT:
```
ldc.i4 0x80070102    // DXGI_ERROR_WAIT_TIMEOUT
// или NOP и вернуть null-текстуру
```

### Вариант C — Патч на уровне SharpDX
Подменить SharpDX.DXGI.dll — заменить метод `DuplicateOutput` на заглушку, возвращающую ошибку.

### Вариант D — SetDisplayAffinity
Установить `WDA_EXCLUDEFROMCAPTURE` (0x11) на окно игры через `SetWindowDisplayAffinity` — DXGI Duplication API не сможет захватить содержимое. Но это влияет на все программы захвата.

## Статус
- [ ] проверено / [ ] подтверждено
