# Obfuscation Name Map

Complete mapping of obfuscated class names to their real purpose in RustSecure Core DLL. Every class that calls `goLRktYZPMUxZogV.JLKedGIqgARc()` (the string decryptor) is application logic; non-decryptor classes below are data models, interfaces, or native struct containers that are part of the same system.

---

## Core Infrastructure

| Obfuscated Name | Real Purpose | Key Evidence |
|---|---|---|
| **goLRktYZPMUxZogV** | String Decryptor | Static class; `JLKedGIqgARc(int)` decrypts strings by index; `YzpsUUKKgbaP()` initializes string table from embedded resource |
| **Entry** | Entry Point | Instantiates `SetFrameRateMediator` with `wss://rustsecure.ru/ws` [752280813] and `RSv1.HoNrj7...` [752280812], calls `.Start()` |
| **SetFrameRateMediator** | Main Runtime / Orchestrator | Wires up the entire system: DetectionManager, SynchronizeFrameUpdate, ScreenshotCaptureService, MeterFrameInterval, ControlFramePacingNotifier, RuntimeSecurityMonitor, BlendFrameUpdates, InspectFrameBufferObserver. Strings: `UnknownPlayer` [752280820], `https://t.me/rustsecure` [752280825], `Connected` [752280827] |

---

## Network / Reporting

| Obfuscated Name | Real Purpose | Key Evidence |
|---|---|---|
| **SynchronizeFrameUpdate** | WebSocket Reporter | Sends detections, screenshots, heartbeats. Strings [752280928-970]: `Heartbeat`, `ThreatDetected`, `PlayerConnected`, `RequestScreenshot`, `BanPlayer|`, `steamId`, `threatType`, `application/octet-stream`, `X-RS-SteamId`, `X-RS-RequestSig` |
| **StabilizeFrameTiming** | WebSocket Handshake / Crypto Session | ECDH key exchange. Strings [752280896-911]: `Socket is not connected`, `Server handshake signature mismatch`, `server-hello`, `Invalid server public key`, `ServerHello`, `nonce`, `pub`. String [752280944]=`client-hello`, [752280947]=`ClientHello` JSON |

---

## Detection System

| Obfuscated Name | Real Purpose | Key Evidence |
|---|---|---|
| **DetectionManager** | Detection Orchestrator | Holds references to HandleScan, KdmapperDetector, BepInExDetector, EmulatedMouseScanner, Il2cppOldHook, OldRustAssemblyLoadDetector. Has `InitializeOldRustDetectors` state machine. Tracks `_recentHandleSuspiciousByPid`, `_recentEtwSuspiciousByPid` |
| **RuntimeSecurityMonitor** | Anti-Debug Orchestrator | Calls InspectFrameBufferSerializer for: `NtQueryInformationProcessCheck_ProcessDebugFlags/Port/ObjectHandle`, `ParentProcessAntiDebug`, `NtCloseAntiDebug_InvalidHandle/ProtectedHandle`, `AntiDebugAttach`, `HideThreadsAntiDebug`, `NtSetDebugFilterStateAntiDebug`. Takes `Action<string, string, bool> reportThreat` |
| **InspectFrameBufferSerializer** | Anti-Debug Techniques | Implements individual anti-debug checks. Calls CalculateFrameDelta syscalls (`SyscallNtQueryInformationProcess`, `SyscallNtClose`), ValidateFrameRate wrappers, StabilizeFrameTimingCalculator for code allocation |
| **HandleScan** | Handle Scanner | Scans process handles for suspicious access. Calls `CalculateFrameDelta.SyscallNtQueryInformationProcess`, `ValidateFrameRate.OOBDDBCG3165`. Reports via InspectFrameBufferObserver |
| **SystemHandleScanner** | System Handle Enumerator | Calls `ValidateFrameRate.NCBKJGOP2826` (NtQuerySystemInformation) to enumerate all system handles. Uses `ForecastFrameLoad.SystemHandleTableEntryInfoEx` structs |
| **KdmapperDetector** | Kdmapper / Vulnerable Driver Detection | Detects kdmapper kernel exploits. Strings: `iqvw32/iqvw64e.sys`, `\\.\Nal`, `\device\nal`, `KnownVulnerableIqvw64eHashLoaded/InService`, `NalDevicePresent`, `KernelServiceCreated/Changed/DeletedQuickly` |
| **BepInExDetector** | BepInEx Mod Framework Detection | Monitors for BepInEx modding framework. Inner class `LoadedModuleSnapshot`. Strings: `BepInEx`, `plugins`, `patchers`, `*.dll` |
| **EmulatedMouseScanner** | Input Emulation Detection | Detects emulated/injected mouse input. Strings: `injected_mouse_move_stream`, `sustained_injected_move_stream`, `burst_short_window`, `high_injected_rate`, `lower_il_injected`, `move_without_button_pattern`, `remote_session` |
| **Il2cppOldHook** | IL2CPP / Mono Hook Detection | Hooks `mono_assembly_foreach` via inline hooking. Uses SmoothFrameTransitionRepository Mono delegates. Has `HasPassiveScannerExports`, `HasInlineHookExports`, `OnMonoAssembly` callback |
| **OldRustMonoNativeHook\<T\>** | Native Inline Hook Engine | Generic class. Builds trampolines, steals prologue bytes, writes JMP stubs. Uses `ValidateFrameRate.PFGCPBGH1001` (VirtualProtectEx), `DZNOTDRO9831` (FlushInstructionCache). Strings [752281296-99]=`Failed to protect/decode/encode trampoline` |
| **OldRustAssemblyLoadDetector** | Assembly Load Monitor | Fires `OnDetection` event. Iterates loaded .NET assemblies checking for suspicious loads |
| **InterpolateFrameValues** | Injected Thread Detector | Calls `CalculateFrameDelta.SyscallNtQuerySystemInformation` twice. Detects threads injected into game process |
| **ProjectFramePerformance** | CLR Hook / Guard Page Detector | Strings: `X` [752280674], `,nt=0x` [752280972], `new=0x` [752280973]. Uses VirtualProtectEx. Detects hooks on CLR methods and guard page manipulation |
| **BlendFrameUpdates** | Window Scanner / Overlay Detector | `StartMonitoring` async. Uses EnumWindows, GetClassName, GetWindowRect. Detects debugger/cheat windows by title: `cheat engine`, `ida`, `x64dbg`, `dnspy`, `windbg`, `ollydbg` |
| **AssessFrameQuality** | Process Scanner / Hash Checker | References ValidateFrameRate, StabilizeFrameTimingCalculator. Scans running processes, computes SHA256 hashes |
| **AssessFrameQualityDecorator** | Process Access / Overlay Detector Wrapper | Wraps AssessFrameQuality, adds overlay detection logic. String [752280612]=`|` (separator) |
| **DetectFrameDrops** | ETW Event Log Reader | Reads Windows Event Log / ETW traces for suspicious kernel events |

---

## Native / Syscall Layer

| Obfuscated Name | Real Purpose | Key Evidence |
|---|---|---|
| **CalculateFrameDelta** | NT Syscall Stub Layer | Nested `Syscall` class. Methods: `SyscallNtQueryInformationFile/Process/Thread`, `SyscallNtQuerySystemInformation`, `SyscallNtQueryVirtualMemory`, `SyscallNtCreateFile`, `SyscallNtClose`, `SyscallNtQueryValueKey`, `SyscallNtOpenKey`, `SyscallNtProtectVirtualMemory`. String [752280704]=`ntdll.dll` |
| **CalculateFrameDeltaRepository** | Syscall Safe Wrapper | `Safe` method wraps CalculateFrameDelta syscalls with error handling |
| **StabilizeFrameTimingCalculator** | Module / ProcAddress Resolution | `LowLevelGetModuleHandle`, `LowLevelGetProcAddress`, `AllocateCode`, `FreeCode`, `InstallHookCLR`, `InstallOrUninstallHook`. PEB-walking module resolution without API calls |
| **ValidateFrameRate** | Win32 API Shim / Dispatch Engine | Massive obfuscated dispatch tables (~28K lines). Wraps all Win32/NT calls through TXTSYSNF5632 delegates. Only direct DllImport: `ZeroMemory`. XOR-based string decryption. Methods named `XXXX####` pattern |
| **TXTSYSNF5632** | Win32 API Delegate Hub | 50+ delegate types for kernel32/user32/advapi32 functions. Each has obfuscated name: `FZQWUCBU3356`=VirtualQuery, `YBRLMFQF2130`=VirtualProtectEx, `WTVBXQNT7328`=DuplicateHandle, `LCASPXEU2790`=FindWindow, `UPUSRVSF3098`=EnumWindows, plus NVML GPU and ETW functions |
| **SmoothFrameTransitionRepository** | NT Syscall + Mono Delegate Hub | 30+ delegate types: NT syscalls (`SysNtQuery*`, `SysNtCreate*`, `SysNtClose`, `SysNtProtect*`), Mono runtime functions (`MonoAssembly*`, `MonoImage*`, `MonoRuntime*`), ETW callbacks, `HandleScannerCallback` |
| **ForecastFrameLoad** | Native Struct / Enum Definitions | 40+ native struct definitions: `MEMORY_BASIC_INFORMATION`, `SYSTEM_HANDLE_TABLE_ENTRY_INFO`, `IMAGE_DOS/NT_HEADERS`, `PEB`, `CONTEXT`, `OBJECT_ATTRIBUTES`, `UNICODE_STRING`, `SP_DEVINFO_DATA`, `DXGI_SWAP_CHAIN_DESC` |
| **InspectFrameBuffer** | Syscall Result Parser | Parses results from CalculateFrameDeltaRepository.Safe calls |

---

## Screenshot / Capture

| Obfuscated Name | Real Purpose | Key Evidence |
|---|---|---|
| **ScreenshotCaptureService** | Screenshot Service | Implements IScreenshotCaptureService. Contains `_dxgi` (DxgiDuplicator) and `_wgc` (MonitorFramePerformance). `CaptureOnce` tries both methods. `ReadGameWindowDisplayAffinity` checks anti-capture flags |
| **IScreenshotCaptureService** | Screenshot Service Interface | `CaptureOnce(CaptureMethod preferredMethod = None, int timeoutMs = 250)` |
| **DxgiDuplicator** | DXGI Desktop Duplication Capture | Uses SharpDX: Factory1, Adapter1, Output1, OutputDuplication, Texture2D staging. `TryCapturePng` acquires frames, copies to staging texture. Strings [752280736-38]=`DXGI AcquireNextFrame failed`, `DXGI frame timeout`, `DXGI could not recover` |
| **MonitorFramePerformance** | Windows Graphics Capture (WGC/GDI Fallback) | Bitmap-based capture fallback. `TryCapturePng` with GDI BitBlt. Strings [752280716-759]=`Bitmap capture failed: BitBlt/CreateCompatibleDC/CreateCompatibleBitmap/GetWindowRect/...` |
| **CaptureMethod** | Capture Method Enum | `None`, `DxgiDuplication`, `WgcFallback` |
| **ExtrapolateFrameDataInvoker** | Screenshot Result DTO | Fields: success bool, path string, method CaptureMethod, timestamp DateTime, image bytes, dimensions |

---

## Data Collection

| Obfuscated Name | Real Purpose | Key Evidence |
|---|---|---|
| **MeterFrameInterval** | HWID Collector | ~45,498 lines. Collects 30+ hardware identifiers via registry, WMI, syscalls, SetupAPI, NVML. See `06_hwid_algorithm.md` for full details |
| **ControlFramePacingNotifier** | Steam ID Resolver | `TryGetSteamId(out ulong, out string)`. Loads steam_api64.dll/ValveAPI64.dll, resolves `SteamAPI_ISteamUser_GetSteamID`, `SteamAPI_GetHSteamPipe/User`, `SteamInternalFindOrCreateUserInterface`. Has memory safety checks |
| **MergeFrameBuffers** | Steam Local Accounts Parser | Parses `loginusers.vdf`. Strings: `loginusers.vdf was not found` [752280784], `No Steam accounts were found` [752280785] |
| **AccumulateFrameStats** | System Fingerprinting / Integrity | Uses X509Certificates, cryptography, Registry. System integrity verification |

---

## Logging / Utility

| Obfuscated Name | Real Purpose | Key Evidence |
|---|---|---|
| **InspectFrameBufferObserver** | Logger | Methods: `Error(int code, Exception)`, `Error(int code, string)`, `Info(int code, string)`, `Write(string line)`. AES-GCM encrypted log files (BouncyCastle). Writes to `RustSecure.log` / `RustSecure_fail.log`. Key: `RseSec2026KeyForDebugLogsEncryption!` |
| **MonitorFramePerformanceOptimizer** | Path Utility | `IsPathInTemp` and file path validation helpers |
| **OptimizeFrameDeliveryManager** | Temp Path Checker | Calls `MonitorFramePerformanceOptimizer.IsPathInTemp` |
| **OptimizeFrameDeliveryConverter** | Detection Event Wrapper | Wraps detection events for reporting pipeline |
| **EstimateFrameLatencyFacade** | Window Enumeration Facade | Wraps `ValidateFrameRate.NHGVNTPT1230`, `VDXMVAHZ6112`. Has `EnumWindowsCallback`. Provides window enumeration to BlendFrameUpdates |
| **EvaluateFramePacingAllocator** | Thread-Safe Detection Runner | VM dispatch with thread synchronization for running detection checks |
| **CombineFrameData** | Assembly Metadata Inspector | Strings: `AssemblyLoadNullAssembly` [752281282], `AssemblyLocationEmpty/Invalid/LoadedWithout/Outside` [752281308-11]. Checks assembly loading integrity |
| **CombineFrameDataProcessor** | Module Hash Resolver | Calls `StabilizeFrameTimingCalculator.LowLevelGetModuleHandle`. Module hash/path resolution |
| **SetFrameRateCoordinator** | Old Rust Hook Coordinator | References GovernFramePacing, PredictFrameTiming, TrackFrameMetrics. Coordinates Mono/IL2CPP hook installation |
| **NormalizeFrameRateBuilder** | Session / Config Builder | Configuration management, isolated from native interop |

---

## Data Models (No Decryptor -- Support Classes)

| Obfuscated Name | Real Purpose | Key Evidence |
|---|---|---|
| **CollectFrameSamples** | HWID Data Model | Fields: `domain_sid`, `hwid_smbios_uuid`, `windows_product_key` |
| **ForecastFrameLoadConstructor** | HWID Data Model | Fields: `hwid_gpu_identifier`, `hwid_tpm_endorsement` |
| **NormalizeFrameRateSynchronizer** | Session Data Model | Fields: `hwid_kernel_timestamp`, `machine_certificate`, `last_heartbeat_timestamp`, `sync_checkpoint` |
| **CheckFrameStabilityProxy** | Network Data Model | Fields: `packet_sequence_number`, `cache_invalidation_time`, `hwid_wifi_bssid`, `bitlocker_recovery_key` |
| **TuneFrameLatencyTransformer** | Extended Data Model | Fields: `hwid_gpu_identifier`, `hwid_audio_device_id`, `machine_certificate`, `oauth_refresh_token` |
| **PredictFrameTiming** | Hook Method Info | Fields: `ClassInfo` (GovernFramePacing), `MethodName` (string), `ParamCount` (int) |
| **ManageFrameSync** | Sync State Model | Companion to CollectFrameSamples (same namespace) |
| **MonitorFramePerformanceFactory** | Detection Event Info | Used by OldRustAssemblyLoadDetector `OnDetection` event |
| **ThrottleFrameRateSynchronizer** | Detection Interface | Interface for throttled detection checks |
| **GovernFramePacing** | Hook Class Info | Data model for IL2CPP/Mono hook class metadata |
| **TrackFrameMetrics** | Hook Metrics | Data model for tracking hook performance |
| **ControlFramePacing** | Pacing State | State tracking for detection pacing |
| **VerifyFrameSyncDispatcher** | Sync Verification | Verification dispatch helper |

---

## Architecture Diagram

```
Entry
  |
  v
SetFrameRateMediator (Main Runtime)
  |
  +-- SynchronizeFrameUpdate (WebSocket Reporter)
  |     +-- StabilizeFrameTiming (ECDH Handshake)
  |
  +-- DetectionManager (Detection Orchestrator)
  |     +-- HandleScan (Handle Scanner)
  |     |     +-- SystemHandleScanner (System Handle Enumerator)
  |     +-- KdmapperDetector (Kernel Exploit Detection)
  |     +-- BepInExDetector (Mod Framework Detection)
  |     +-- EmulatedMouseScanner (Input Emulation Detection)
  |     +-- Il2cppOldHook (IL2CPP/Mono Hook Detection)
  |     |     +-- OldRustMonoNativeHook<T> (Inline Hook Engine)
  |     +-- OldRustAssemblyLoadDetector (Assembly Load Monitor)
  |     +-- InterpolateFrameValues (Injected Thread Detector)
  |
  +-- RuntimeSecurityMonitor (Anti-Debug Orchestrator)
  |     +-- InspectFrameBufferSerializer (Anti-Debug Techniques)
  |     +-- ProjectFramePerformance (CLR Hook/Guard Page Detection)
  |
  +-- BlendFrameUpdates (Window Scanner / Overlay Detector)
  |     +-- EstimateFrameLatencyFacade (Window Enum Facade)
  |     +-- AssessFrameQuality (Process Scanner)
  |           +-- AssessFrameQualityDecorator (Overlay Detector)
  |
  +-- ScreenshotCaptureService (Screenshot Service)
  |     +-- DxgiDuplicator (DXGI Capture)
  |     +-- MonitorFramePerformance (GDI/WGC Capture)
  |
  +-- MeterFrameInterval (HWID Collector)
  +-- ControlFramePacingNotifier (Steam ID Resolver)
  +-- MergeFrameBuffers (Steam Accounts Parser)
  +-- DetectFrameDrops (ETW Event Reader)
  +-- InspectFrameBufferObserver (Logger)

Native Layer:
  CalculateFrameDelta (NT Syscall Stubs)
    +-- CalculateFrameDeltaRepository (Safe Wrapper)
    +-- InspectFrameBuffer (Result Parser)
  StabilizeFrameTimingCalculator (Module/ProcAddress Resolution)
  ValidateFrameRate (Win32 API Shim)
    +-- TXTSYSNF5632 (Win32 Delegate Hub)
  SmoothFrameTransitionRepository (NT + Mono Delegate Hub)
  ForecastFrameLoad (Native Struct Definitions)
```

---

## Summary Statistics

- **Total application classes identified**: 51
- **Classes using string decryptor**: 41
- **Data model / support classes**: 13
- **Detection modules**: 16
- **Native/syscall layer classes**: 8
- **Network/reporting classes**: 2
- **Screenshot/capture classes**: 6
- **Previously known mappings verified**: 20/20 correct
- **New mappings discovered**: 31
