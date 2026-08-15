# 07 — HWID Collection (25+ идентификаторов)

## Где (файл + метод/адрес)
- Сборка: RustSecure.Core.dll
- Файл: `MeterFrameInterval.cs`
- Строка-префикс: `rs.hwid.v1|` [752280613]
- Обфускация: Agile.NET

## Как работает

Собирает 25+ аппаратных идентификаторов из WMI, реестра, MAC-адресов, syscall-ов. Все идентификаторы конкатенируются через `|` с префиксом `rs.hwid.v1|` и отправляются на сервер для привязки лицензии и бана.

### Полный список идентификаторов

| ID строки | Идентификатор | Источник |
|-----------|---------------|----------|
| [752280640] | hwid_machine_guid | `SOFTWARE\Microsoft\Cryptography\MachineGuid` [752280615] |
| [752280617] | hwid_disk_physical_serials | `\\.\PhysicalDrive` [752280600] + DeviceIoControl |
| [752280620] | hwid_mac_address | Сетевые адаптеры |
| [752280622] | hwid_memory_serials | WMI Win32_PhysicalMemory |
| [752280623] | hwid_gpu_nvml_uuid | NVIDIA NVML API |
| [752280642] | hwid_motherboard_registry | `HARDWARE\DESCRIPTION\System\BIOS` [752280610] (BaseBoardProduct [752280638], BaseBoardManufacturer [752280639]) |
| [752280643] | hwid_volume_serial | Серийный номер тома (через syscall NtQueryVolumeInformationFile) |
| [752280656] | hwid_syscall_machine_guid | MachineGuid через NtOpenKey+NtQueryValueKey |
| [752280657] | hwid_usn_journal_id | USN Journal ID (уникален для NTFS тома) |
| [752280661] | hwid_system_uuid | WMI Win32_ComputerSystemProduct [752280626] UUID |
| [752280662] | hwid_boot_uuid | Boot GUID |
| [752280663] | hwid_sqm_machine_id | SQM Machine ID (телеметрия Windows) |
| [752280664] | hwid_gpu_pnp_device | PNPDeviceID [752280627] видеокарты |
| [752280665] | hwid_gpu_registry | `SYSTEM\CurrentControlSet\Control\Video` [752280628] (DriverDesc [752280630]) |
| [752280666] | hwid_registry_persistent | Персистентный ID в реестре RS |
| [752280667] | hwid_steam_folder_ticks | Timestamp создания папки Steam [752280603] |
| [752280668] | hwid_user_sid | SID текущего пользователя Windows |
| [752280669] | hwid_windows_install | InstallDate [752280635] из `SOFTWARE\Microsoft\Windows NT\CurrentVersion` [752280632] |
| [752280670] | hwid_monitor_device | Идентификатор монитора |
| [752280671] | hwid_syscall_volume | Серийный номер тома через syscall |
| [752280660] | hwid_hwprofile_guid | Hardware Profile GUID |
| [752280658] | hwid_syscall_motherboard | Материнская плата через syscall (NtOpenKey) |
| [752280659] | hwid_syscall_windows_install | Дата установки Windows через syscall |
| [752280616] | hwid_syscall_file_basic | File basic info через NtQueryInformationFile |
| [752280621] | hwid_syscall_system_basic | System basic info через NtQuerySystemInformation |

Дополнительно: PROCESSOR_IDENTIFIER [752280611], BIOSVersion [752280633], ProductId [752280634], SystemProductName [752280636], SystemManufacturer [752280637], BuildLabEx [752280629], DriverVersion [752280625].

## Как обойти

### Вариант A — Подмена всей HWID-строки (рекомендуется)
Найти место формирования финальной строки `rs.hwid.v1|...` и заменить на статическую подмену. В IL: после конкатенации всех компонентов заменить результат на `ldstr "rs.hwid.v1|spoofed"`.

### Вариант B — Патч отдельных коллекторов
Каждый метод сбора (hwid_machine_guid, hwid_disk_physical_serials и т.д.) заменить на:
```
ldstr "spoofed_value"
ret
```

### Вариант C — Патч отправки
Найти метод, отправляющий HWID на сервер, и NOP-ить вызов. HWID не уйдёт, но локальная привязка может нарушиться.

### Вариант D — Спуфинг на уровне ОС
Подменить значения в реестре и WMI до запуска. Работает для обычных запросов, но НЕ для syscall-вариантов (hwid_syscall_*), которые читают реестр напрямую через NtOpenKey/NtQueryValueKey.

## Статус
- [ ] проверено / [ ] подтверждено
