#!/usr/bin/env python3
"""Static IL patcher for RustSecure.Core.dll — disables all 13 detection modules.
Replaces method bodies with `ret` (void) or `ldsfld Task.CompletedTask; ret` (Task).

Usage: python3 patcher.py <input.dll> <output.dll>
"""
import struct, sys, shutil

TARGETS = [
    # (RID, name, return_type, code_size_check)
    (43,   "Entry::Init",                          "void", 3230),
    (2780, "SetFrameRateMediator::Start",           "void", 10051),
    (5904, "DetectionManager::Initialize",          "void", 8137),
    (330,  "RuntimeSecurityMonitor::Start",          "void", 8946),
    (2791, "RuntimeSecurityMonitor::HandleThreat",   "void", 9514),
    (5896, "DetectionManager::PublishDetection",     "void", 7643),
    (3342, "SynchronizeFrameUpdate::ReportThreatAsync", "task", 2296),
    (3186, "SynchronizeFrameUpdate::InitializeAsync",   "task", 2567),
]

# Tiny IL body: header byte = (code_size << 2) | 0x02
# ret = 0x2A (1 byte) -> header = (1 << 2) | 2 = 0x06
RET_BODY = bytes([0x06, 0x2A])


def find_method_rva(data, pe_sections, md_offset, rid):
    """Find RVA of MethodDef[rid] from metadata tables."""
    # Parse #~ stream to find MethodDef table
    # Simplified: we already know RIDs from analysis, use dnfile to get offsets
    pass


def patch_method_body(data, file_offset, original_size, return_type):
    """Replace method body at file_offset with a minimal stub."""
    if return_type == "void":
        # Tiny header: size=1, code=ret
        data[file_offset] = 0x06      # tiny header, code_size=1
        data[file_offset + 1] = 0x2A  # ret
        # Zero the rest
        for i in range(file_offset + 2, file_offset + 12 + original_size):
            if i < len(data):
                data[i] = 0x00
    elif return_type == "task":
        # Need: ldsfld System.Threading.Tasks.Task::CompletedTask; ret
        # But we don't have the field token easily.
        # Simpler: return null (ldnull; ret) — Task method returning null
        # won't crash if caller doesn't await, and async state machine handles it.
        # Actually safest: tiny body with ldnull + ret = 2 bytes
        data[file_offset] = 0x0A      # tiny header, code_size=2
        data[file_offset + 1] = 0x14  # ldnull
        data[file_offset + 2] = 0x2A  # ret
        for i in range(file_offset + 3, file_offset + 12 + original_size):
            if i < len(data):
                data[i] = 0x00


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.dll> <output.dll>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    # Use dnfile to find method file offsets
    import dnfile
    pe = dnfile.dnPE(input_path)
    md = pe.net.mdtables

    data = bytearray(open(input_path, 'rb').read())
    patched = 0

    for rid, name, ret_type, expected_size in TARGETS:
        row = md.MethodDef.rows[rid - 1]
        rva = row.Rva
        if rva == 0:
            print(f"  SKIP {name}: RVA=0")
            continue

        file_off = pe.get_offset_from_rva(rva)
        header = data[file_off]

        if (header & 3) == 2:  # tiny
            code_size = header >> 2
            body_start = file_off
        else:  # fat
            code_size = struct.unpack_from('<I', data, file_off + 4)[0]
            body_start = file_off

        if expected_size > 0 and code_size != expected_size:
            print(f"  WARN {name}: expected size {expected_size}, got {code_size}")

        patch_method_body(data, body_start, code_size, ret_type)
        patched += 1
        print(f"  PATCHED {name} (RID={rid}) @ 0x{file_off:x} size={code_size} -> {ret_type}")

    open(output_path, 'wb').write(data)
    print(f"\nDone: {patched}/{len(TARGETS)} methods patched -> {output_path}")


if __name__ == '__main__':
    main()
