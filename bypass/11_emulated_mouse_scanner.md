# 11 — Emulated Mouse Scanner (обнаружение эмулированного ввода)

## Где (файл + метод/адрес)
- Сборка: RustSecure.Core.dll
- Файл: `CMSSECTIONIDWINDOWCLASSSECTIONSystemThreadingTasksFutureDebugView/EmulatedMouseScanner.cs`
- Строка: `Suspicious emulated mouse input: Reason={0} Risk={1} ...`
- Обфускация: Agile.NET

## Как работает

Устанавливает low-level хуки на мышь и клавиатуру для обнаружения программного ввода:

### Хуки
- **WH_MOUSE_LL** (14) — low-level mouse hook, перехватывает все события мыши
- **WH_KEYBOARD_LL** (13) — low-level keyboard hook, перехватывает все нажатия

### В callback-е хука проверяется поле `MSLLHOOKSTRUCT.flags`:
- Флаг `LLMHF_INJECTED` (0x01) — событие сгенерировано `SendInput` / `mouse_event`
- Флаг `LLMHF_LOWER_IL_INJECTED` (0x02) — событие сгенерировано процессом с более низким Integrity Level

### Паттерны детекции

| Паттерн | Описание |
|---------|----------|
| `lower_il_injected` | Injected-ввод с более низкого IL |
| `injected_buttons` | Injected-нажатия кнопок мыши |
| `high_injected_rate` | Высокая частота injected-событий |
| `sustained_injected_move_stream` | Длительный поток injected-движений |
| `injected_mouse_move_stream` | Поток injected-движений мыши |
| `suspicious_injected_mouse_input_pattern` | Подозрительный паттерн injected-ввода |

### Логика
Сканер накапливает статистику injected-событий. При превышении порогов (частота, длительность, паттерн) генерируется алерт с Risk-уровнем.

## Как обойти

### Вариант A — Патч установки хуков (рекомендуется)
Найти вызовы `SetWindowsHookEx(WH_MOUSE_LL, ...)` и `SetWindowsHookEx(WH_KEYBOARD_LL, ...)`. Заменить на:
```
ldc.i4.0    // IntPtr.Zero — хук не установлен
```
или NOP-ить весь блок установки хуков.

### Вариант B — Патч callback-а хука
В callback-методе (LowLevelMouseProc) заменить проверку `flags & LLMHF_INJECTED` на:
```
pop         // убрать flags со стека
ldc.i4.0    // всегда 0 (не injected)
```
Все события будут считаться "не эмулированными".

### Вариант C — Патч репортинга
Найти формирование строки `Suspicious emulated mouse input:` и NOP-ить весь блок отправки. Детекция произойдёт, но репорт не уйдёт.

### Вариант D — Обход на уровне ввода
Использовать драйвер-уровень ввода (kernel-mode mouse/keyboard), который не устанавливает флаг `LLMHF_INJECTED`. Но это уже не IL-патч.

## Статус
- [ ] проверено / [ ] подтверждено
