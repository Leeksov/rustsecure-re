# 09 — Kdmapper Detection

## Где (файл + метод/адрес)
- Сборка: RustSecure.Core.dll
- Файл: `GetLowerBoundDecoderFallbackBuffer/KdmapperDetector.cs`
- Строка: [752280835] `Kdmapper usermode correlation: Event={0} Confidence={1} Score={2}`
- Обфускация: Agile.NET

## Как работает

Kdmapper — утилита для загрузки неподписанных драйверов через эксплуатацию уязвимых подписанных драйверов (BYOVD). RustSecure детектирует его usermode-артефакты.

### Методы детекции

1. **KdmapperCorrelation** — корреляционный анализ:
   - Мониторинг Event Log: поиск событий загрузки драйверов (строки [752280863]: `EventLog={0} EventProvider={1} EventId={2} EventRecordId={3}`)
   - Поиск служб: [752280862] `Service={0} ServiceType={1} ServicePath={2} ServicePathRaw={3}`
   - Проверка файлов служб: [752280857] `ServiceSeen={0}..{1} ServiceFileExists={2} ServiceFileSize={3}`
   - Подпись файлов: [752280853] `ServiceFileSigner=`
   - Сигналы kdmapper: [752280848] `Signals=`, [752280851] `SignalsDetailed=`

2. **KdmapperHardIndicator** — жёсткие индикаторы:
   - Обнаружение Nal-драйвера: [752280854] `Nal={0} BlocklistDisabled={1} PoolTag={2} PoolDelta={3}`
   - Проверка загруженных модулей: [752280852] `Module={0} ModulePath={1} ModuleHash={2} ModuleFileExists={3}`
   - Кандидат-процессы: [752280849] `CandidatePid={0} CandidateName={1} CandidatePath={2}`

3. **Confidence scoring** — уровни уверенности: Suspicious [752280832], HighConfidence [752280833].

## Как обойти

### Вариант A — Патч детектора (рекомендуется)
В `KdmapperDetector` найти основной метод детекции и заменить тело на:
```
ret
```
Метод ничего не вернёт и не отправит событие.

### Вариант B — Патч корреляции
Найти метод, формирующий строку `Kdmapper usermode correlation:` и NOP-ить вызов, формирующий Event. Это предотвратит отправку репорта.

### Вариант C — Подмена Confidence
Заменить все присвоения Confidence на `Suspicious` -> не приведёт к бану (только к логированию). Найти `ldstr "HighConfidence"` и заменить на `ldstr "None"` или аналог.

## Статус
- [ ] проверено / [ ] подтверждено
