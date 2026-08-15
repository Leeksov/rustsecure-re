# 04 — Anti-Debug (18 техник)

## Где (файл + метод/адрес)
- Сборка: RustSecure.Core.dll
- Детекторы: `setOwnersetItem/InspectFrameBufferSerializer.cs`
- Оркестратор: `getHoursObjectAce/RuntimeSecurityMonitor.cs`
- Обфускация: Agile.NET

## Как работает

Оркестратор `RuntimeSecurityMonitor` запускает 18 проверок анти-отладки. Каждая техника возвращает результат детекции, который агрегируется и отправляется на сервер.

### Список техник

1. **DebuggerIsAttached** — `System.Diagnostics.Debugger.IsAttached` (managed)
2. **IsDebuggerPresent** — P/Invoke `kernel32!IsDebuggerPresent`
3. **BeingDebugged PEB** — чтение PEB->BeingDebugged напрямую из памяти
4. **NtGlobalFlag** — чтение PEB->NtGlobalFlag, проверка флагов 0x70 (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)
5. **NtQueryInformationProcess (ProcessDebugFlags 0x1F)** — syscall, если результат == 0 -> отладчик
6. **NtQueryInformationProcess (ProcessDebugPort 0x7)** — syscall, если результат != 0 -> отладчик
7. **NtQueryInformationProcess (ProcessDebugObjectHandle 0x1E)** — syscall, если STATUS_SUCCESS -> отладчик
8. **AntiDebugAttach** — патчит `DbgUiRemoteBreakin` (строка [752280707]) и `DbgBreakPoint` (строка [752280706]) в ntdll.dll чтобы предотвратить attach
9. **FindWindow** — ищет окна OllyDbg, x64dbg, x32dbg (строки [752280728], [752280734], [752280735])
10. **NtUserGetForegroundWindow** — строки `DebuggerForegroundWindow` [752280677], `DebuggerForegroundWindow(Runtime)` [752280676] — проверяет, является ли foreground окно окном отладчика
11. **HideThreadsAntiDebug** — `NtSetInformationThread` с ThreadHideFromDebugger (0x11), строка [752280678]
12. **GetTickCount timing** — замер времени выполнения, аномалия = отладчик
13. **OutputDebugString** — строка [752280700], [752280703] — проверяет `GetLastError` после `OutputDebugString`
14. **OllyDbg format string** — строка [752280702] (`%s%s%s%s...` x40) — вызывает крэш OllyDbg при попытке отобразить
15. **DebugBreak** — вызов `BreakInternal` (строка [752280697])
16. **Hardware breakpoints (DR registers)** — строка [752280696]: `HardwareRegistersBreakpointsDetection: Hardware breakpoint detected on thread {0}` — проверяет DR0-DR3 через `GetThreadContext`
17. **ParentProcess check** — проверяет родительский процесс (должен быть explorer.exe [752280654] или rustsecure.exe [752280650])
18. **NtSetDebugFilterState** — вызов для детекции kernel-режима отладки
19. **PageGuard** — строка [752280646]: `Exception during page guard test` — устанавливает PAGE_GUARD на страницу и проверяет, съел ли отладчик исключение
20. **NtClose invalid/protected handle** — вызов NtClose с невалидным хэндлом, отладчик генерирует исключение

Также проверяются процессы по именам: cheat engine [752280724], cheatengine [752280727], ida [752280726], dnspy [752280731], windbg [752280729], ollydbg [752280728], hyperdbg [752280725], immunity debugger [752280730], aida32 [752280720], aida64 [752280721].

## Как обойти

### Вариант A — Патч оркестратора (рекомендуется)
В `RuntimeSecurityMonitor` найти метод, который вызывает все проверки, и заменить его тело на `ret` (IL: `0x2A`). Это отключит все 18 техник разом.

### Вариант B — Патч каждой техники отдельно
Для каждого метода в `InspectFrameBufferSerializer`:
- **Managed-проверки** (IsAttached и т.п.): заменить `call` на `ldc.i4.0` + `nop` (всегда возвращать false/0)
- **Syscall-проверки** (NtQuery*): в теле метода заменить на `ldc.i4.0` + `ret` (вернуть "не обнаружен")
- **FindWindow**: заменить вызов `FindWindow` на `ldc.i4.0` (IntPtr.Zero)
- **Timing**: заменить проверку разницы тиков на `ldc.i4.0`
- **PageGuard**: убрать `VirtualProtect` вызов с `PAGE_GUARD`, заставить метод вернуть "не обнаружен"

### Вариант C — Патч AntiDebugAttach
Метод патчит `DbgUiRemoteBreakin`/`DbgBreakPoint` — NOP-ить весь метод чтобы не мешал attach отладчика.

## Статус
- [ ] проверено / [ ] подтверждено
