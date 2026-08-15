# 06 — Syscall Infrastructure (обход usermode-хуков)

## Где (файл + метод/адрес)
- Сборка: RustSecure.Core.dll
- Syscall resolver: `opLessThanDays/CalculateFrameDelta.cs`
- Anti-hook утилиты: `ArmDES/StabilizeFrameTimingCalculator.cs`
- Обфускация: Agile.NET

## Как работает

### Прямые syscall-ы (CalculateFrameDelta)
Вместо вызова Win32 API через ntdll.dll (где антивирус/EDR может перехватить), RustSecure резолвит номера syscall-ов напрямую из ntdll.dll на диске и вызывает их через `syscall` инструкцию. 15 syscall-ов:

| Syscall | Строка ID | Использование |
|---------|-----------|---------------|
| NtQueryInformationProcess | [752280864] | Anti-debug (ProcessDebugPort/Flags/ObjectHandle) |
| NtQueryVirtualMemory | [752280866] | Сканирование памяти |
| NtQuerySystemInformation | [752280867] | Handle scan, VM detection, процессы |
| NtProtectVirtualMemory | [752280888] | Изменение прав страниц (PageGuard и др.) |
| NtQueryVolumeInformationFile | [752280889] | HWID (серийный номер тома) |
| NtQueryInformationFile | [752280891] | HWID (file basic info) |
| NtOpenKey | [752280892] | HWID (реестр через syscall) |
| NtQueryInformationThread | [752280893] | HideThreadFromDebugger |
| NtCreateFile | [752280894] | Открытие файлов/устройств |
| NtQueryValueKey | [752280895] | Чтение реестра через syscall |
| NtClose | [752280899] | Anti-debug (invalid handle) |

### Anti-hook (StabilizeFrameTimingCalculator)
- **LowLevelGetModuleHandle** — ручной поиск модуля через PEB->Ldr без `GetModuleHandle`
- **LowLevelGetProcAddress** — ручной парсинг PE export table без `GetProcAddress`
- **HookFunction** — установка inline-хуков (перезапись пролога jmp-ом)
- **FollowJmpTrampoline** — проход по цепочке jmp для определения реального адреса
- **TerminateCurrentProcess** — аварийное завершение через `NtTerminateProcess` syscall

## Как обойти

### Вариант A — Заставить использовать обычные API
В `CalculateFrameDelta` найти метод резолва syscall-номеров и заменить его результат на вызовы стандартных ntdll-функций. Это позволит перехватывать вызовы обычными хуками.

### Вариант B — Патч вызовов syscall
Каждый wrapper-метод (напр. `SyscallNtQueryInformationProcess`) заменить на:
```
ldc.i4.0    // STATUS_SUCCESS / "не обнаружено"
ret
```
Это отключит конкретные проверки, использующие syscall.

### Вариант C — Нейтрализация Anti-hook
В `StabilizeFrameTimingCalculator`:
- **LowLevelGetModuleHandle**: заменить на `call GetModuleHandle` (обычный P/Invoke)
- **LowLevelGetProcAddress**: заменить на `call GetProcAddress`
- **TerminateCurrentProcess**: NOP-ить весь метод (предотвратить аварийное завершение)
- **HookFunction**: NOP-ить (не даст RS ставить свои хуки на ntdll)

### Вариант D — Подмена ntdll на диске
Syscall-номера читаются из ntdll.dll на диске. Можно подложить модифицированный ntdll с неверными номерами, но это рискованно для стабильности системы. Не рекомендуется.

## Статус
- [ ] проверено / [ ] подтверждено
