# BYPASS — ПАПКА ДЛЯ ЗАПИСИ ОБХОДОВ

> Сюда новый контекст Claude записывает **каждый найденный метод детекта и его обход** —
> по одному `.md`-файлу на метод. Это журнал обходов, который заполняется по мере анализа.

---

## ПРАВИЛО ЗАПОЛНЕНИЯ

Для **каждого** найденного метода защиты/детекта создавать файл
`bypass\NN_короткое_имя.md` (NN — порядковый номер 01, 02, 03…).

Внутри файла — строго по шаблону ниже (чтобы по файлу можно было быстро патчить):

```markdown
# NN — <Название метода детекта/защиты>

## Где (файл + метод/адрес)
- Сборка: RustSecure.exe / RustSecure.Core.dll / Native
- Метод/класс/токен (и IL-смещение, если есть):
- Поле/строка, участвующая в проверке:

## Как работает
<описание логики проверки: что читает, что сравнивает, что возвращает>

## Как обойти
<конкретный способ: какой IL-патч / какой вызов подменить / какое значение вернуть>

## Статус
- [ ] проверено / [x] подтверждено
```

---

## ИНДЕКС (заполняется по мере нахождения)

| # | Метод | Файл | Статус |
|---|-------|------|--------|
| 01 | Single-instance мьютекс | RustSecure.exe | описан ранее |
| 02 | PrivacyConsentForm | RustSecure.exe | описан ранее |
| 03 | VC++ redist check | RustSecure.exe | описан ранее |
| 04 | Anti-Debug (18 техник) | Core.dll — InspectFrameBufferSerializer / RuntimeSecurityMonitor | заполнен |
| 05 | Anti-VM / Sandbox Detection | Core.dll — InterpolateFrameValues.cs (IsSandbox) | заполнен |
| 06 | Syscall Infrastructure (15 NT syscalls + anti-hook) | Core.dll — CalculateFrameDelta / StabilizeFrameTimingCalculator | заполнен |
| 07 | HWID Collection (25+ идентификаторов) | Core.dll — MeterFrameInterval.cs | заполнен |
| 08 | Handle Scanning | Core.dll — HandleScan / SystemHandleScanner | заполнен |
| 09 | Kdmapper Detection | Core.dll — KdmapperDetector.cs | заполнен |
| 10 | BepInEx Detection | Core.dll — BepInExDetector.cs | заполнен |
| 11 | Emulated Mouse Scanner | Core.dll — EmulatedMouseScanner.cs | заполнен |
| 12 | IL2CPP/Mono Hook Detection | Core.dll — Il2cppOldHook / OldRustMonoNativeHook / OldRustAssemblyLoadDetector | заполнен |
| 13 | DXGI Duplication Detection | Core.dll — DxgiDuplicator.cs | заполнен |
| 14 | Screenshot Capture Service | Core.dll — ScreenshotCaptureService / MonitorFramePerformance | заполнен |
| 15 | Window/Process Scanning | Core.dll — BlendFrameUpdates.cs | заполнен |
| 16 | WebSocket Threat Reporting | Core.dll — SynchronizeFrameUpdate.cs | заполнен |

---

## ЗАДАЧА (поочерёдно)

1. После деобфускации каждой сборки — искать по реальным именам методы детекта.
2. Для каждого — создавать файл по шаблону выше.
3. Обновлять этот `README.md` (таблица-индекс).
4. Все обходы должны быть **статическими** (патч IL / подмена значения / офлайн-расшифровка) —
   **бинарь не запускать**.
