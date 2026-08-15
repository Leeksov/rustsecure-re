# 05 — Anti-VM / Sandbox Detection

## Где (файл + метод/адрес)
- Сборка: RustSecure.Core.dll
- Файл: `PopDirectionalFormatSecurityControlFlags/InterpolateFrameValues.cs`
- Метод: `IsSandbox()` (строка ~1877)
- Обфускация: Agile.NET

## Как работает

Метод `IsSandbox()` выполняет комплексную проверку виртуализации и sandbox-окружения:

1. **SYSTEM_CODEINTEGRITY_INFORMATION** — вызов `NtQuerySystemInformation` с `SystemCodeIntegrityInformation` (0x67). Проверяет, включён ли Code Integrity / HVCI. В VM/sandbox CI может быть отключён.

2. **SYSTEM_SECUREBOOT_INFORMATION** — вызов `NtQuerySystemInformation` с `SystemSecureBootInformation`. Проверяет наличие Secure Boot — в большинстве VM он отключён.

3. **STORAGE_DEVICE_DESCRIPTOR (VM disk vendor)** — `DeviceIoControl` с `IOCTL_STORAGE_QUERY_PROPERTY` на физическом диске. Ищет строки вендоров VM в `VendorId`/`ProductId`:
   - VMware: "vmware", "virtual"
   - VirtualBox: "vbox"
   - Hyper-V: "microsoft virtual"
   - QEMU: "qemu"

4. **WMI queries** — `SELECT * FROM Win32_ComputerSystemProduct` и другие WMI-классы для определения виртуального оборудования.

5. **DeviceIoControl** — прямые запросы к дисковому контроллеру для обнаружения виртуальных дисков.

Результат: `true` = sandbox/VM обнаружен.

## Как обойти

### Вариант A — Патч метода IsSandbox()
Заменить тело `IsSandbox()` на:
```
ldc.i4.0    // false — не sandbox
ret
```
IL-байты: `16 2A` (с padding nop-ами по размеру оригинала).

### Вариант B — Патч каждой подпроверки
Если нужно выборочно отключить:
- **Code Integrity**: NOP-ить вызов `NtQuerySystemInformation(0x67, ...)`, заменить результат на "CI включён"
- **Secure Boot**: аналогично с `SystemSecureBootInformation`
- **Disk vendor**: NOP-ить `DeviceIoControl` вызов, подставить пустой `VendorId`
- **WMI**: NOP-ить `ManagementObjectSearcher` вызовы

### Вариант C — На уровне оркестратора
В вызывающем коде найти `if (IsSandbox())` и заменить условный переход `brtrue`/`brfalse` на безусловный `br` к ветке "не sandbox".

## Статус
- [ ] проверено / [ ] подтверждено
