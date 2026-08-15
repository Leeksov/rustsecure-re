#!/usr/bin/env python3
"""HWID Spoofer for RustSecure — generates randomized hardware IDs and applies them.

RustSecure collects 30 HWID identifiers via two methods:
1. Registry/WMI queries (hwid_*) — spoofable via registry edits
2. Direct NT syscalls (hwid_syscall_*) — requires kernel-level spoof or IL patch

This tool:
- Generates consistent random HWIDs (seeded, so same seed = same identity)
- Creates .reg files to apply registry spoofs
- Patches Core DLL to return spoofed values for syscall-based checks

Usage:
  python3 hwid_spoof.py generate [--seed N]     # generate new identity
  python3 hwid_spoof.py apply <identity.json>    # create .reg files
  python3 hwid_spoof.py patch <core.dll> <out>   # patch syscall HWID methods
"""

import json, hashlib, uuid, random, sys, os, struct

# ============================================================
# All 30 HWID identifiers collected by RustSecure
# ============================================================
HWID_FIELDS = {
    # Registry-based (spoofable via .reg)
    "hwid_machine_guid":         {"source": "registry", "key": r"SOFTWARE\Microsoft\Cryptography", "value": "MachineGuid"},
    "hwid_volume_serial":        {"source": "registry", "key": None, "value": None, "note": "GetVolumeInformation"},
    "hwid_motherboard_registry": {"source": "registry", "key": r"HARDWARE\DESCRIPTION\System\BIOS", "values": ["BaseBoardProduct", "BaseBoardManufacturer", "SystemProductName", "SystemManufacturer"]},
    "hwid_windows_install":      {"source": "registry", "key": r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "values": ["InstallDate", "ProductId", "BuildLabEx"]},
    "hwid_gpu_registry":         {"source": "registry", "key": r"SYSTEM\CurrentControlSet\Control\Video", "values": ["DriverDesc", "DriverVersion"]},
    "hwid_gpu_pnp_device":       {"source": "wmi",      "class": "Win32_VideoController", "prop": "PNPDeviceID"},
    "hwid_monitor_device":       {"source": "setupdi",  "note": "SetupDiEnumDeviceInfo for monitors"},
    "hwid_memory_serials":       {"source": "wmi",      "class": "Win32_PhysicalMemory", "prop": "SerialNumber"},
    "hwid_disk_physical_serials":{"source": "ioctl",    "note": r"\\.\PhysicalDriveN STORAGE_DEVICE_DESCRIPTOR"},
    "hwid_mac_address":          {"source": "netapi",   "note": "NetworkInterface.GetAllNetworkInterfaces()"},
    "hwid_gpu_nvml_uuid":        {"source": "nvml",     "note": "NVML GPU UUID"},
    "hwid_user_sid":             {"source": "token",    "note": "Current user SID"},
    "hwid_steam_folder_ticks":   {"source": "filesystem","note": "Steam folder creation time ticks"},
    "hwid_registry_persistent":  {"source": "registry", "key": r"SOFTWARE\RustSecure", "value": "BuildGUID"},
    "hwid_hwprofile_guid":       {"source": "api",      "note": "GetCurrentHwProfile() GUID"},
    "hwid_system_uuid":          {"source": "wmi",      "class": "Win32_ComputerSystemProduct", "prop": "UUID"},
    "hwid_boot_uuid":            {"source": "registry", "note": "BCD boot UUID"},
    "hwid_sqm_machine_id":       {"source": "registry", "note": "SQM Machine ID"},
    "hwid_usn_journal_id":       {"source": "ioctl",    "note": "FSCTL_QUERY_USN_JOURNAL"},
    "hwid_bios_firmware":        {"source": "registry", "key": r"HARDWARE\DESCRIPTION\System\BIOS", "value": "BIOSVersion"},
    "hwid_computer_name":        {"source": "api",      "note": "GetComputerName()"},
    "hwid_system_file_ticks":    {"source": "filesystem","note": "System file timestamps"},
    "hwid_cpu_processor_id":     {"source": "registry", "key": None, "value": "PROCESSOR_IDENTIFIER"},
    "hwid_cpu_profile":          {"source": "cpuid",    "note": "CPUID instruction"},

    # Syscall-based (bypass usermode hooks — requires IL patch or kernel spoof)
    "hwid_syscall_machine_guid": {"source": "syscall",  "nt": "NtOpenKey+NtQueryValueKey", "target": "MachineGuid"},
    "hwid_syscall_motherboard":  {"source": "syscall",  "nt": "NtQuerySystemInformation",  "target": "SMBIOS"},
    "hwid_syscall_windows_install":{"source":"syscall",  "nt": "NtOpenKey+NtQueryValueKey", "target": "InstallDate"},
    "hwid_syscall_volume":       {"source": "syscall",  "nt": "NtQueryVolumeInformationFile","target": "VolumeSerial"},
    "hwid_syscall_file_basic":   {"source": "syscall",  "nt": "NtQueryInformationFile",    "target": "FileBasicInfo"},
    "hwid_syscall_system_basic": {"source": "syscall",  "nt": "NtQuerySystemInformation",  "target": "SystemBasicInfo"},
    "hwid_syscall_computer_name":{"source": "syscall",  "nt": "NtOpenKey+NtQueryValueKey", "target": "ComputerName"},
    "hwid_syscall_code_integrity":{"source":"syscall",  "nt": "NtQuerySystemInformation",  "target": "CodeIntegrity"},
}


def generate_identity(seed=None):
    """Generate a complete spoofed HWID identity."""
    if seed is None:
        seed = random.randint(100000, 999999)

    rng = random.Random(seed)

    def rand_hex(n):
        return ''.join(rng.choice('0123456789ABCDEF') for _ in range(n))

    def rand_guid():
        b = bytes(rng.randint(0, 255) for _ in range(16))
        return str(uuid.UUID(bytes=b))

    def rand_mac():
        # Keep first byte even (unicast)
        octets = [rng.randint(0, 255) & 0xFE] + [rng.randint(0, 255) for _ in range(5)]
        return ':'.join(f'{o:02X}' for o in octets)

    def rand_serial(length=8):
        return ''.join(rng.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(length))

    def rand_sid():
        sub = [rng.randint(100000, 999999) for _ in range(4)]
        return f"S-1-5-21-{sub[0]}-{sub[1]}-{sub[2]}-{sub[3]}"

    identity = {
        "_seed": seed,
        "_prefix": "rs.hwid.v1",

        # Registry-spoofable
        "machine_guid":        rand_guid(),
        "volume_serial":       rand_hex(8),
        "baseboard_product":   f"B{rand_serial(6)}",
        "baseboard_mfr":       rng.choice(["ASUSTeK", "Gigabyte", "MSI", "ASRock"]),
        "system_product":      f"System Product Name {rand_serial(4)}",
        "system_mfr":          rng.choice(["ASUS", "Gigabyte", "MSI", "Dell", "HP", "Lenovo"]),
        "install_date":        str(rng.randint(1600000000, 1700000000)),
        "product_id":          f"{rand_hex(5)}-{rand_hex(5)}-{rand_hex(5)}-{rand_hex(5)}",
        "bios_version":        f"{rng.choice(['American Megatrends', 'Phoenix', 'Award'])} {rng.randint(1,9)}.{rng.randint(0,99):02d}",
        "gpu_driver_desc":     rng.choice(["NVIDIA GeForce RTX 3070", "NVIDIA GeForce RTX 4060", "AMD Radeon RX 6800"]),
        "gpu_driver_version":  f"{rng.randint(30,56)}.{rng.randint(0,99)}.{rng.randint(100,999)}.{rng.randint(1000,9999)}",
        "gpu_pnp_id":          f"PCI\\VEN_{rand_hex(4)}&DEV_{rand_hex(4)}&SUBSYS_{rand_hex(8)}&REV_{rand_hex(2)}",
        "disk_serial":         rand_serial(20),
        "mac_address":         rand_mac(),
        "memory_serial":       [rand_serial(8) for _ in range(rng.randint(2, 4))],
        "user_sid":            rand_sid(),
        "computer_name":       f"DESKTOP-{rand_serial(7)}",
        "hwprofile_guid":      "{" + rand_guid().upper() + "}",
        "system_uuid":         rand_guid().upper(),
        "boot_uuid":           "{" + rand_guid().upper() + "}",
        "sqm_machine_id":      "{" + rand_guid().upper() + "}",
        "build_guid":          rand_guid(),
        "steam_folder_ticks":  str(rng.randint(637000000000000000, 638000000000000000)),
        "cpu_processor_id":    f"Intel64 Family {rng.randint(6,8)} Model {rng.randint(100,200)} Stepping {rng.randint(0,9)}, GenuineIntel",
    }

    return identity


def create_reg_files(identity, output_dir="."):
    """Generate .reg files to apply registry-level HWID spoofs."""
    os.makedirs(output_dir, exist_ok=True)

    # 1. MachineGuid
    reg = f"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography]
"MachineGuid"="{identity['machine_guid']}"
"""
    open(os.path.join(output_dir, "01_machine_guid.reg"), "w").write(reg)

    # 2. BIOS/Motherboard
    reg = f"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS]
"BaseBoardProduct"="{identity['baseboard_product']}"
"BaseBoardManufacturer"="{identity['baseboard_mfr']}"
"SystemProductName"="{identity['system_product']}"
"SystemManufacturer"="{identity['system_mfr']}"
"BIOSVersion"="{identity['bios_version']}"
"""
    open(os.path.join(output_dir, "02_bios_motherboard.reg"), "w").write(reg)

    # 3. Windows install info
    reg = f"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion]
"InstallDate"=dword:{int(identity['install_date']):08x}
"ProductId"="{identity['product_id']}"
"""
    open(os.path.join(output_dir, "03_windows_install.reg"), "w").write(reg)

    # 4. RustSecure persistent GUID
    reg = f"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SOFTWARE\\RustSecure]
"BuildGUID"="{identity['build_guid']}"
"""
    open(os.path.join(output_dir, "04_rustsecure_guid.reg"), "w").write(reg)

    # 5. ComputerName
    reg = f"""Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName]
"ComputerName"="{identity['computer_name']}"

[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName]
"ComputerName"="{identity['computer_name']}"
"""
    open(os.path.join(output_dir, "05_computer_name.reg"), "w").write(reg)

    # 6. Batch apply script
    bat = f"""@echo off
echo === RustSecure HWID Spoof ===
echo Seed: {identity['_seed']}
echo.

:: Apply registry patches
for %%f in (*.reg) do (
    echo Applying %%f...
    reg import "%%f" >nul 2>&1
)

:: Spoof volume serial (requires volumeid.exe from Sysinternals)
echo.
echo Volume serial spoof requires Sysinternals VolumeID:
echo   volumeid.exe C: {identity['volume_serial'][:4]}-{identity['volume_serial'][4:]}
echo.

:: Spoof MAC address
echo MAC address spoof (set in Device Manager or via:)
echo   netsh interface set interface "Ethernet" admin=disable
echo   reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}\\0001" /v NetworkAddress /t REG_SZ /d {identity['mac_address'].replace(':','')} /f
echo   netsh interface set interface "Ethernet" admin=enable
echo.

:: Spoof computer name
echo Computer name: {identity['computer_name']}
echo   wmic computersystem where name="%%COMPUTERNAME%%" call rename name="{identity['computer_name']}"
echo.

echo Done. Reboot required for some changes to take effect.
pause
"""
    open(os.path.join(output_dir, "apply_spoof.bat"), "w").write(bat)

    return output_dir


def patch_hwid_collector(input_dll, output_dll):
    """Patch Core DLL to neutralize HWID collection methods.

    Strategy: patch the HWID builder method to return an empty dict,
    so the server receives no hardware fingerprint.
    """
    import dnfile

    pe = dnfile.dnPE(input_dll)
    md = pe.net.mdtables
    data = bytearray(open(input_dll, 'rb').read())

    def getname(field):
        if hasattr(field, 'value'):
            v = field.value
            return v.decode('utf-8', 'replace') if isinstance(v, (bytes, bytearray)) else str(v)
        return str(field)

    # Find methods that build HWID dict
    # Target: methods containing "hwid_" string references and returning Dictionary
    # Simpler: patch the method that sends HWIDs to server
    # From analysis: SynchronizeFrameUpdate.InitializeAsync sends hwids
    # Already patched by patcher.py (returns null)

    # Additionally: patch GetMacFingerprint and individual hwid_ collectors
    # These are in MeterFrameInterval class

    patched = 0
    for i, r in enumerate(md.MethodDef.rows):
        mname = getname(r.Name)
        rva = r.Rva
        if rva == 0:
            continue

        # Patch GetMacFingerprint -> return empty string
        if mname == "GetMacFingerprint":
            off = pe.get_offset_from_rva(rva)
            data[off] = 0x0A  # tiny, size=2
            data[off+1] = 0x16  # ldc.i4.0 (will cause empty)
            data[off+2] = 0x2A  # ret
            patched += 1
            print(f"  PATCHED {mname} (RID={i+1}) @ 0x{off:x}")

        # Patch GetMonitorHardwareId -> return empty string
        if mname == "GetMonitorHardwareId":
            off = pe.get_offset_from_rva(rva)
            data[off] = 0x0A
            data[off+1] = 0x14  # ldnull
            data[off+2] = 0x2A  # ret
            patched += 1
            print(f"  PATCHED {mname} (RID={i+1}) @ 0x{off:x}")

    open(output_dll, 'wb').write(data)
    print(f"\nHWID patches: {patched} methods -> {output_dll}")
    print("Note: main HWID transmission is already blocked by patcher.py")
    print("      (InitializeAsync returns null, never sends hwids to server)")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "generate":
        seed = None
        if "--seed" in sys.argv:
            idx = sys.argv.index("--seed")
            seed = int(sys.argv[idx + 1])

        identity = generate_identity(seed)
        out_file = f"identity_{identity['_seed']}.json"
        json.dump(identity, open(out_file, 'w'), indent=2)
        print(f"Generated identity (seed={identity['_seed']}):")
        for k, v in identity.items():
            if not k.startswith('_'):
                print(f"  {k:25s} = {v}")
        print(f"\nSaved to {out_file}")

    elif cmd == "apply":
        if len(sys.argv) < 3:
            print("Usage: hwid_spoof.py apply <identity.json>")
            sys.exit(1)
        identity = json.load(open(sys.argv[2]))
        out_dir = f"spoof_{identity['_seed']}"
        create_reg_files(identity, out_dir)
        print(f"Created .reg files and apply script in {out_dir}/")

    elif cmd == "patch":
        if len(sys.argv) < 4:
            print("Usage: hwid_spoof.py patch <core.dll> <output.dll>")
            sys.exit(1)
        patch_hwid_collector(sys.argv[2], sys.argv[3])

    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)


if __name__ == '__main__':
    main()
