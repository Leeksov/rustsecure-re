# RustSecure — Reverse Engineering

Static reverse engineering of **RustSecure** — a client-side anti-cheat agent for the game Rust.

## Architecture

```
RustSecure.exe (loader)
  ├── Obfuscation: Agile.NET / CliSecure (VM + method splitting + string encryption)
  ├── Downloads encrypted payloads from https://rustsecure.ru/api/loader/{core,native}
  ├── HWID licensing + Steam/OAuth auth
  ├── Manual DLL injection into RustClient.exe
  │
  ├── native_decrypted.dll (39 KB, x64 native)
  │     └── CLR Host Bridge: loads .NET CLR v4.0.30319 into game process
  │         calls RustSecure.Core.Entry.Init()
  │
  └── core_decrypted.dll (19 MB, managed .NET)
        └── RustSecure.Core — the actual "anti-cheat" engine
            ├── 13 detection modules (see bypass/)
            ├── Direct NT syscalls (bypasses usermode hooks)
            ├── 25+ HWID identifiers
            ├── WebSocket telemetry: wss://rustsecure.ru/ws
            ├── Screenshot capture + upload
            └── Embedded: BouncyCastle, Iced.Intel, SharpDX.Direct3D11
```

## Key Findings

| Item | Value |
|------|-------|
| AES Key (loader strings) | `hnYcSF4fEX2OR3iSJlF3tfw15geCn9uQ` |
| AES IV | `2U0mqd3VL3bX7OBn` |
| Shared Secret | `R260iT7ujsI58aTxAExVby6qea3L056h6SfnEr2BLKbmY2vlvm` |
| Server API | `https://rustsecure.ru/api/loader/{core,native}` |
| WebSocket | `wss://rustsecure.ru/ws` |
| Telegram | `https://t.me/rustsecure` |
| Loader strings | 347 decrypted (see `data/decrypted_strings.txt`) |
| Core strings | 801 decrypted (see `data/core_decrypted_strings.txt`) |

## Detection Modules (Core DLL)

| # | Module | What it detects |
|---|--------|----------------|
| 04 | Anti-Debug | 18 techniques (PEB, NtQuery*, FindWindow, DR regs, timing, PageGuard) |
| 05 | Anti-VM/Sandbox | Code Integrity, Secure Boot, disk vendor, WMI |
| 06 | Syscall Infrastructure | 15 direct NT syscalls bypassing usermode hooks |
| 07 | HWID Collection | 25+ identifiers (rs.hwid.v1 format) |
| 08 | Handle Scanning | NtQuerySystemInformation handle enumeration |
| 09 | Kdmapper Detection | Kernel driver mapper via Event Log correlation |
| 10 | BepInEx Detection | Folder scan, module snapshot, SHA256 |
| 11 | Emulated Mouse Scanner | WH_MOUSE_LL hook detecting injected input |
| 12 | IL2CPP/Mono Hooks | Runtime hook detection + AssemblyLoad monitoring |
| 13 | DXGI Duplication | Desktop duplication API detection |
| 14 | Screenshot Capture | Server-requested DXGI/WGC/GDI capture |
| 15 | Window/Process Scan | EnumWindows for cheat tools (CE, x64dbg, IDA) |
| 16 | WebSocket telemetry | Threat reports, bans, screenshot requests |

See `bypass/` for detailed analysis and bypass methods for each module.

## Repository Structure

```
docs/           — analysis reports (loader, server API, Core DLL, protections)
bypass/         — bypass journal: one file per detection mechanism (04-16)
scripts/        — Python/C# tools (string decryptors, deobfuscators, payload downloaders)
data/           — decrypted strings, delegate maps, type definitions
payloads/       — encrypted server payloads + HTTP headers
samples/        — original binaries (RustSecure.exe, RustSecure.Core.dll)
decrypted/      — decrypted payloads (core_decrypted.dll, native_decrypted.dll)
re_analysis/    — working directory (raw scripts, intermediate outputs)
```

## Tools Required

- **Python 3** + `dnfile`, `dncil`, `pycryptodome`
- **ilspycmd** (ILSpy CLI): `dotnet tool install --global ilspycmd --version 8.2.0.7535`
  - Requires `DOTNET_ROLL_FORWARD=Major` on .NET 8
- **Mono** for reflective string decryption: `brew install mono`
- **IDA Pro** for native_decrypted.dll analysis

## Regenerating Decompiled Output

```bash
export PATH="$PATH:$HOME/.dotnet/tools"
export DOTNET_ROLL_FORWARD=Major
ilspycmd -p -o re_analysis/decomp samples/RustSecure.exe
ilspycmd -p -o re_analysis/decomp_core decrypted/core_decrypted.dll
```

## Bypass Tools

### Static Patcher
```bash
python3 bypass/patcher.py decrypted/core_decrypted.dll decrypted/core_patched.dll
```
Patches 8 methods in Core DLL (Entry::Init, DetectionManager::Initialize, RuntimeSecurityMonitor::Start, etc.) — replaces IL bodies with `ret`/`ldnull;ret`. All 13 detection modules become dead code.

### Runtime Bypass
```bash
mcs -unsafe -target:library bypass/RuntimeBypass.cs -out:RuntimeBypass.dll
```
C# DLL that hooks `AppDomain.AssemblyLoad`, intercepts Core DLL loading, and swaps detection method pointers to no-op stubs via JIT patching. Deploy alongside the CLR bridge.

## Credits

Analysis performed with:
- **[IDA Pro](https://hex-rays.com/)** + **[IDA MCP](https://github.com/mrexodia/ida-mcp-server)** — native DLL reverse engineering
- **[ILSpy CLI (ilspycmd)](https://github.com/icsharpcode/ILSpy)** — .NET decompilation
- **[Claude Opus](https://anthropic.com/claude)** — AI-assisted analysis and automation
- **[dnfile](https://github.com/malwarefrontier/dnfile)** + **[dncil](https://github.com/mandiant/dncil)** — .NET metadata parsing
- **[Mono](https://www.mono-project.com/)** — reflective string decryption on macOS

## Safety Rule

**NEVER run any binary.** All analysis is static only (Python + dnfile/dncil, ilspycmd, IDA, mono reflection on patched binaries).
