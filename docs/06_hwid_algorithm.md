# HWID Fingerprinting Algorithm

## Overview

RustSecure Core collects **30 hardware identifiers** from the target machine, individually SHA-256 hashes each one, and sends the hashed dictionary to the server as a JSON object inside the heartbeat/authentication payload. The collection lives entirely in `MeterFrameInterval.cs` (obfuscated name for the HWID Collector class, ~45,000 lines).

All collector methods are protected by a custom **stack-based virtual machine** (virtualization obfuscator). The actual logic is encoded as bytecode streams in static byte arrays and interpreted at runtime through opcode dispatch loops. Method names visible in the decompilation are random/misleading.

---

## Entry Point

```
public static IReadOnlyDictionary<string, string> CollectHashedHwids()
```

This is the single public entry point (line 14148). It:

1. Creates a `Dictionary<string, string>` with `StringComparer.OrdinalIgnoreCase`
2. Calls each of the 30 collector functions via a VM dispatch table (`getShortestDayNamesTaskContinuationOptions[]`)
3. For each result, calls `HashHwid(label, rawValue)` to compute a per-field SHA-256 hash
4. For multi-valued fields (disk serials, memory serials, MAC addresses), uses `AddSetHwid()` to store individual items as `label_item_0`, `label_item_1`, ..., plus `label_count`
5. Returns the completed dictionary

---

## Hashing: SHA-256 Per Field

```
private static string HashHwid(string label, string value)  // line 26283
```

Per-field hashing procedure:
1. Creates `SHA256.Create()` (confirmed at lines 10990, 21865)
2. Concatenates `label + value` into a combined string
3. Converts to bytes via `Encoding.UTF8.GetBytes()`
4. Calls `SHA256.ComputeHash(bytes)` (wrapper methods at lines 4570, 12159)
5. Converts hash bytes to lowercase hex string (dashes removed)
6. Disposes the SHA256 instance
7. Returns hex-encoded SHA-256 hash

---

## Fingerprint String Format

The raw (pre-hash) fingerprint for the `rs.hwid.v1` format is assembled as pipe-delimited concatenation:

```
rs.hwid.v1|<field1>|<field2>|...|<fieldN>
```

- Prefix: `rs.hwid.v1|` (decrypted string [752280613])
- Separator: `|` (decrypted string [752280612])
- Each field is the raw collected value for that HWID component, ordered by collection sequence

---

## JSON Serialization for Server

The hashed HWID dictionary is serialized into the server payload as:

```json
,"hwids":{
  "hwid_machine_guid":"<sha256hex>",
  "hwid_motherboard_registry":"<sha256hex>",
  "hwid_disk_physical_serials_item_0":"<sha256hex>",
  "hwid_disk_physical_serials_count":"2",
  ...
}
```

- Format prefix: `,"hwids":{` (decrypted string [752280962])
- Multi-valued suffix: `_item_` (decrypted string [752280618]), `_count` (decrypted string [752280619])
- Nested inside the larger heartbeat/authentication JSON body

---

## Complete HWID Identifier Table (30 Fields)

### Category 1: Registry (Managed .NET API)

| # | Field Name | String ID | Collection Method | Registry Path / Property |
|---|---|---|---|---|
| 1 | `hwid_machine_guid` | 752280640 | `GetMachineGuid()` | `HKLM\SOFTWARE\Microsoft\Cryptography` -> `MachineGuid` [752280615] |
| 2 | `hwid_motherboard_registry` | 752280642 | `GetMotherboardFingerprint()` | `HKLM\HARDWARE\DESCRIPTION\System\BIOS` [752280610] -> `BaseBoardProduct` [752280638], `BaseBoardManufacturer` [752280639], `SystemProductName` [752280636], `SystemManufacturer` [752280637] |
| 3 | `hwid_volume_serial` | 752280643 | `GetSystemVolumeSerial()` | Volume serial number of `C:\` [752280609] drive |
| 4 | `hwid_windows_install` | 752280669 | `GetWindowsInstallFingerprint()` | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` [752280632] -> `ProductId` [752280634], `InstallDate` [752280635], `BuildLabEx` [752280629] |
| 5 | `hwid_gpu_registry` | 752280665 | `GetGpuRegistryFingerprint()` | `HKLM\SYSTEM\CurrentControlSet\Control\Video` [752280628] -> enumerates subkeys, reads `DriverDesc` [752280630] from `\0000` [752280631] |
| 6 | `hwid_hwprofile_guid` | 752280660 | `GetHwProfileGuid()` | Hardware profile GUID (likely `HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB`) |
| 7 | `hwid_sqm_machine_id` | 752280663 | `GetSqmMachineId()` | `HKLM\SOFTWARE\Microsoft\SQMClient` -> `MachineId` |
| 8 | `hwid_registry_persistent` | 752280666 | `GetPersistentRegistryGuid()` | Self-generated GUID stored in user-writable registry key (HKCU); creates `Guid.NewGuid()` if absent and persists it |

### Category 2: Registry (Native Syscalls - Anti-Spoof)

| # | Field Name | String ID | Collection Method | Native Registry Path |
|---|---|---|---|---|
| 9 | `hwid_syscall_machine_guid` | 752280656 | `GetMachineGuidViaSyscall()` | `\Registry\Machine\SOFTWARE\Microsoft\Cryptography` [752281068] -> `MachineGuid` (via `NtOpenKey`/`NtQueryValueKey`) |
| 10 | `hwid_syscall_motherboard` | 752280658 | `GetMotherboardViaSyscall()` | `\Registry\Machine\HARDWARE\DESCRIPTION\System\BIOS` [752281066] -> same BIOS values via native syscalls |
| 11 | `hwid_syscall_windows_install` | 752280659 | `GetWindowsInstallViaSyscall()` | `\Registry\Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion` [752281071] via native syscalls |
| 12 | `hwid_syscall_computer_name` | 752281085 | `GetComputerNameViaSyscall()` | `\Registry\Machine\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName` [752281064] -> `ComputerName` [752281067] |

### Category 3: WMI (ManagementObjectSearcher)

| # | Field Name | String ID | Collection Method | WMI Query |
|---|---|---|---|---|
| 13 | `hwid_system_uuid` | 752280661 | `GetSystemUuidFingerprint()` | `SELECT UUID FROM Win32_ComputerSystemProduct` [752280626] |
| 14 | `hwid_cpu_processor_id` | 752281084 | `GetCpuProcessorIdFingerprint()` | `SELECT ProcessorId FROM Win32_Processor` (via `QueryWmiFingerprint()`) |
| 15 | `hwid_gpu_pnp_device` | 752280664 | `GetGpuPnpDeviceFingerprint()` | `SELECT PNPDeviceID FROM Win32_VideoController` [752280624, 752280627] |
| 16 | `hwid_memory_serials` | 752280622 | `GetMemorySerialFingerprint()` | `SELECT SerialNumber FROM Win32_PhysicalMemory` (multi-valued, via `AddSetHwid`) |
| 17 | `hwid_bios_firmware` | 752281057 | `GetBiosSerialFingerprint()` / `GetFirmwareFingerprint()` | Registry `BIOSVersion` [752280633] and/or WMI `Win32_BIOS` |

### Category 4: Native Syscalls (NtQuerySystemInformation)

| # | Field Name | String ID | Collection Method | Syscall Details |
|---|---|---|---|---|
| 18 | `hwid_syscall_system_basic` | 752280621 | `GetSystemBasicViaSyscall()` | `NtQuerySystemInformation(SystemBasicInformation)` -> `PageSize`, `NumberOfPhysicalPages`, processor count |
| 19 | `hwid_boot_uuid` | 752280662 | `GetBootUuid()` / `TryGetBootUuidRaw()` | `NtQuerySystemInformation(class 90 = SystemBootEnvironmentInformation)` -> extracts GUID from `SYSTEM_BOOT_ENVIRONMENT_INFORMATION` struct |
| 20 | `hwid_syscall_code_integrity` | 752281056 | `GetCodeIntegrityViaSyscall()` | `NtQuerySystemInformation(class 103 = SystemCodeIntegrityInformation)` -> code integrity flags |

### Category 5: Device I/O (CreateFile + DeviceIoControl/FSCTL)

| # | Field Name | String ID | Collection Method | I/O Details |
|---|---|---|---|---|
| 21 | `hwid_disk_physical_serials` | 752280617 | `GetPhysicalDiskSerialFingerprint()` | Opens `\\.\PhysicalDrive0`, `\\.\PhysicalDrive1`, ... [752280600] via `IOCTL_STORAGE_QUERY_PROPERTY` (0x2D1400) -> `SerialNumberOffset` from `STORAGE_DEVICE_DESCRIPTOR` (multi-valued) |
| 22 | `hwid_usn_journal_id` | 752280657 | `GetUsnJournalIdFingerprint()` | `FSCTL_QUERY_USN_JOURNAL` (0x000900EC) on system volume -> `USN_JOURNAL_DATA_V0.UsnJournalID` |
| 23 | `hwid_syscall_volume` | 752280671 | `GetVolumeFingerprintViaSyscall()` | `NtQueryVolumeInformationFile(FileFsSizeInformation, class 3)` -> `VolumeSerialNumber` |

### Category 6: File System Timestamps

| # | Field Name | String ID | Collection Method | Details |
|---|---|---|---|---|
| 24 | `hwid_syscall_file_basic` | 752280616 | `GetSystemFileBasicViaSyscall()` | `NtQueryInformationFile(FileBasicInformation, class 4)` on `Windows\System32\ntdll.dll` [752281061] -> creation/modification timestamps |
| 25 | `hwid_system_file_ticks` | 752281059 | `TryReadFileBasicManaged()` | Same concept via managed .NET `FileInfo.CreationTime` / `LastWriteTime` |
| 26 | `hwid_steam_folder_ticks` | 752280667 | `GetSteamFolderFingerprint()` | Checks `C:\Program Files (x86)\Steam` [752280603], reads `CreationTime`/`LastWriteTime` ticks; also probes `Users\desktop.ini` [752280602] |

### Category 7: SetupAPI

| # | Field Name | String ID | Collection Method | Details |
|---|---|---|---|---|
| 27 | `hwid_monitor_device` | 752280670 | `GetMonitorFingerprint()` | `SetupDiGetClassDevs` with GUID `{4D36E96E-E325-11CE-BFC1-08002BE10318}` [752281086] (monitor class) -> `SetupDiEnumDeviceInfo` -> `SetupDiGetDeviceInstanceId` |

### Category 8: .NET Managed APIs

| # | Field Name | String ID | Collection Method | Details |
|---|---|---|---|---|
| 28 | `hwid_computer_name` | 752281058 | `Environment.MachineName` | Direct .NET API |
| 29 | `hwid_user_sid` | 752280668 | `GetUserSid()` | `WindowsIdentity.GetCurrent()` -> SID string (e.g., `S-1-5-21-...`) |
| 30 | `hwid_mac_address` | 752280620 | `GetMacFingerprint()` | `NetworkInterface.GetAllNetworkInterfaces()` -> filters Ethernet/WiFi, excludes virtual/tunnel NICs, collects `GetPhysicalAddress()`, sorts, joins with pipe (multi-valued) |

### Category 9: GPU-Specific

| # | Field Name | String ID | Collection Method | Details |
|---|---|---|---|---|
| -- | `hwid_gpu_nvml_uuid` | 752280623 | `GetGpuNvmlUuidFingerprint()` | Loads `nvml.dll` (NVIDIA Management Library), calls `nvmlInit_v2`, `nvmlDeviceGetCount_v2`, iterates devices with `nvmlDeviceGetUUID` (buffer size 80 chars) |

### Category 10: CPU-Specific

| # | Field Name | String ID | Collection Method | Details |
|---|---|---|---|---|
| -- | `hwid_cpu_profile` | 752281087 | `GetCpuFingerprint()` | Environment variable `PROCESSOR_IDENTIFIER` [752280611] combined with processor architecture and count from `NtQuerySystemInformation(SystemInfo)` |

---

## WMI Query Helper

```
private static string QueryWmiFingerprint(string className, string propertyName)  // line 5941
```

Constructs `SELECT <propertyName> FROM <className>` using string fragments:
- `SELECT ` [752280606]
- ` FROM ` [752280601]

Creates a `ManagementObjectSearcher`, iterates `ManagementObjectCollection`, extracts the property value, trims whitespace, joins multi-valued results.

---

## Multi-Valued HWID Helper

```
private static void AddSetHwid(IDictionary<string, string> target, string baseKey, IReadOnlyCollection<string> values)  // line 7156
```

For HWIDs that return multiple values (disk serials, memory DIMMs, MAC addresses):
1. Filters out null/empty values
2. Trims whitespace from each value
3. Sorts values using `StringComparer.OrdinalIgnoreCase`
4. Removes duplicates
5. Stores each as `<baseKey>_item_<N>` where N is 0-indexed
6. Stores total count as `<baseKey>_count`

---

## Anti-Spoof Architecture

The redundant managed + syscall collection pairs are a deliberate anti-spoof design:

| Managed (user API) | Syscall (native) | What's Compared |
|---|---|---|
| `hwid_machine_guid` | `hwid_syscall_machine_guid` | MachineGuid registry value |
| `hwid_motherboard_registry` | `hwid_syscall_motherboard` | BIOS registry values |
| `hwid_volume_serial` | `hwid_syscall_volume` | Volume serial number |
| `hwid_windows_install` | `hwid_syscall_windows_install` | Windows install info |
| `hwid_computer_name` | `hwid_syscall_computer_name` | Computer name |
| `hwid_system_file_ticks` | `hwid_syscall_file_basic` | ntdll.dll timestamps |

Any usermode hook on `RegOpenKeyEx`/`RegQueryValueEx` that spoofs HWID values will produce a mismatch when compared against the raw NT syscall results. The server can detect this discrepancy to flag HWID spoofing attempts.

---

## Auxiliary Data Model Fields

Several supporting data model classes hold additional fields that may be collected alongside the core 30 HWIDs:

| Class (Obfuscated) | Field | Purpose |
|---|---|---|
| `CollectFrameSamples` | `domain_sid` | Active Directory domain SID |
| `CollectFrameSamples` | `hwid_smbios_uuid` | SMBIOS UUID (redundant with system_uuid) |
| `CollectFrameSamples` | `windows_product_key` | Windows product/license key |
| `ForecastFrameLoadConstructor` | `hwid_gpu_identifier` | GPU identifier string |
| `ForecastFrameLoadConstructor` | `hwid_tpm_endorsement` | TPM endorsement key fingerprint |
| `NormalizeFrameRateSynchronizer` | `hwid_kernel_timestamp` | Kernel build timestamp |
| `NormalizeFrameRateSynchronizer` | `machine_certificate` | Machine certificate hash |
| `CheckFrameStabilityProxy` | `hwid_wifi_bssid` | WiFi BSSID (access point MAC) |
| `CheckFrameStabilityProxy` | `bitlocker_recovery_key` | BitLocker recovery key identifier |
| `TuneFrameLatencyTransformer` | `hwid_audio_device_id` | Audio device identifier |
| `TuneFrameLatencyTransformer` | `oauth_refresh_token` | OAuth refresh token (credential theft) |

---

## Dispatch Table Mapping

The `CollectHashedHwids()` VM bytecode calls functions through the `getShortestDayNamesTaskContinuationOptions[]` dispatch table. Complete slot-to-function mapping:

| Slot | Obfuscated Wrapper | Actual Fingerprint Function |
|---|---|---|
| 0 | `getRootgetBaseDirectory` | `StringComparer.OrdinalIgnoreCase` (comparator) |
| 1 | `SystemEnvironmentCompletionActionInvoker` | `new Dictionary<string, string>(comparer)` |
| 2 | `setWrapNonExceptionThrowsaddAssemblyLoad` | `goLRktYZPMUxZogV.JLKedGIqgARc()` (string decryptor) |
| 3 | `getAppDomainInitializerArguments...` | `GetMachineGuid()` |
| 4 | `EnvelopeEndDeserializationEventHandler` | `dict.Add(key, value)` (dict insert) |
| 5 | `AssemblyHashAlgorithmgetExecution` | `GetSystemVolumeSerial()` |
| 6 | `UniversalTimeAddAccess` | `GetMotherboardFingerprint()` |
| 7 | `EventWaitHandleRightsMicrosoftTelemetry` | `GetWindowsInstallFingerprint()` |
| 8 | `DOWNLOADCollectFromServerContext` | `GetUserSid()` |
| 9 | `setSecurityZoneProgramFiles` | `GetVolumeFingerprintViaSyscall()` |
| 10 | `getApplicationName...` | `GetMonitorFingerprint()` |
| 11 | `ObjectHolderListEnumeratorDefaultValue` | `GetGpuRegistryFingerprint()` |
| 12 | `ThaiBuddhistCalendarFlags` | `GetGpuPnpDeviceFingerprint()` |
| 13 | `SoapPositiveIntegerPopref` | `GetSteamFolderFingerprint()` |
| 14 | `ApplyPolicyUserQuota` | `GetPersistentRegistryGuid()` |
| 15 | `SubOvfUnSharedState` | `GetSystemUuidFingerprint()` |
| 16 | `CharCapacityAssertFailure` | `GetHwProfileGuid()` |
| 17 | `InProcessServerRecordArrayElementFixup` | `GetSqmMachineId()` |
| 18 | `getKeysNormalized...` | `GetBootUuid()` |
| 19 | `BinaryCrossAppDomain...` | `GetUsnJournalIdFingerprint()` |
| 20 | `GetValueDirectXmlNamespaceEncoder` | `GetMachineGuidViaSyscall()` |
| 21 | `LookForMeIndexOfValue` | `GetWindowsInstallViaSyscall()` |
| 22 | `KeyDataSpecialKey` | `GetMotherboardViaSyscall()` |
| 23 | `KeyAvailableIEnumReferenceIdentity` | `GetSystemBasicViaSyscall()` |
| 24 | `setTargetFrameworkNameNullableComparer` | `GetMacFingerprint()` |
| 25 | `SidNameUseBoth` | `AddSetHwid()` wrapper (multi-value parse) |
| 26 | `WindowsDeviceGroupSoapFieldAttribute` | `AddSetHwid()` (multi-value dict insert) |
| 27 | `MAJORVERSIONVersionCompatibility` | `GetGpuNvmlUuidFingerprint()` |
| 28 | `TypeInformation...` | `GetMemorySerialFingerprint()` |
| 29 | `FromBaseCharArraygetSignature` | `GetPhysicalDiskSerialFingerprint()` |
| 30 | `AssemblyIsolationByUser...` | `GetSystemFileBasicViaSyscall()` |

Additional collectors (`GetCpuFingerprint`, `GetCpuProcessorIdFingerprint`, `GetComputerNameViaSyscall`, `GetCodeIntegrityViaSyscall`, `GetFirmwareFingerprint`, `TryReadFileBasicManaged`) are called through VM bytecode function pointers that the decompiler could not resolve to named references.

---

## Key Source Files

| File | Purpose |
|---|---|
| `MeterFrameInterval.cs` | Main HWID collector (all 30+ methods, ~45,498 lines) |
| `CollectFrameSamples.cs` | HWID data model (domain_sid, smbios_uuid, product_key) |
| `ForecastFrameLoadConstructor.cs` | HWID data model (gpu_identifier, tpm_endorsement) |
| `NormalizeFrameRateSynchronizer.cs` | HWID data model (kernel_timestamp, machine_certificate) |
| `CheckFrameStabilityProxy.cs` | HWID data model (wifi_bssid, bitlocker_recovery_key) |
| `TuneFrameLatencyTransformer.cs` | HWID data model (audio_device_id, oauth_refresh_token) |
| `ForecastFrameLoad.cs` | SetupAPI struct definitions (SP_DEVINFO_DATA) |
| `CalculateFrameDelta.cs` | NT syscall dispatch layer used by syscall-based collectors |
