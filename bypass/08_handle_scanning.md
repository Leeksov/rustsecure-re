# 08 — Handle Scanning (обнаружение внешних процессов)

## Где (файл + метод/адрес)
- Сборка: RustSecure.Core.dll
- Детектор: `RequiredBitSparseFile/HandleScan.cs`
- Сканер: `WinRTClassActivatorContinueWhenAll/SystemHandleScanner.cs`
- Строка детекта: [752280846] `Suspicious handle detected: PID={0} Name={1} Path={2} Hash={3} Score={4} Access={5} DeviceCorrelation={6} Device={7}`
- Строка эскалации: [752280841] `ESCALATED THREAT: PID={0} Name={1} Path={2} Hash={3} Score={4} Access={5} DeviceCorrelation={6} Device={7} ImmediateCritical={8}`
- Обфускация: Agile.NET

## Как работает

1. **SystemHandleScanner** вызывает `NtQuerySystemInformation` с `SystemHandleInformation` (0x10) для получения **всех** открытых хэндлов в системе.

2. Для каждого хэндла определяется:
   - PID владельца
   - Тип объекта (Process, Thread, File и др.)
   - Права доступа (Access mask)
   - Имя объекта (через `NtQueryObject`)

3. **HandleScan** фильтрует хэндлы, ищет:
   - Хэндлы к процессу игры из других процессов
   - Хэндлы с подозрительными правами (PROCESS_VM_READ, PROCESS_VM_WRITE и др.)
   - Корреляция с устройствами (DeviceCorrelation)

4. Скоринговая система: каждый подозрительный хэндл получает Score, при превышении порога — эскалация.

5. **IsWhitelisted()** — белый список процессов (Steam, системные сервисы).

6. Результат отправляется как `ThreatDetected` через WebSocket.

## Как обойти

### Вариант A — Патч метода сканирования (рекомендуется)
В `HandleScan` найти основной метод сканирования (цикл по хэндлам) и заменить тело на:
```
ret    // немедленный возврат, сканирование не происходит
```
IL-байт: `2A`.

### Вариант B — Патч NtQuerySystemInformation
В `SystemHandleScanner` найти вызов `NtQuerySystemInformation(SystemHandleInformation, ...)` и заменить на возврат пустого буфера / STATUS_INFO_LENGTH_MISMATCH. Сканер не получит список хэндлов.

### Вариант C — Расширение белого списка
В методе `IsWhitelisted()` заменить логику на:
```
ldc.i4.1    // true — всё в белом списке
ret
```
IL-байты: `17 2A`.

### Вариант D — Патч скоринга
Найти сравнение Score с порогом и заменить `bge`/`bgt` на `br` к ветке "не угроза".

## Статус
- [ ] проверено / [ ] подтверждено
