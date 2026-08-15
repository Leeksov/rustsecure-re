#!/usr/bin/env python3
# Extract AES key + IV strings for the 112-string table in RustSecure.exe.
# key gen bytecode field:  GroupsgetLevel.AsynchronousgetImpersonationLevel
# iv  gen bytecode field:  getHasShutdownStartedRegisteredHandlers.LASTCALENDARClosedDelegateOnly
# Each mini-VM: read blob, per "load" instr XOR num11 data bytes with single byte b2, concat -> UTF8 string.
import struct, dnfile, sys, os

PE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples", "RustSecure.exe")
pe = dnfile.dnPE(PE)
md = pe.net.mdtables

# --- build field-name -> (rid) map from Field table ---
def fname(rid):  # rid is 1-based
    row = md.Field.rows[rid-1]
    n = row.Name
    try: return n.value.decode('utf-8','replace') if hasattr(n,'value') else str(n)
    except: return str(n)

# --- FieldRVA: field rid -> rva; sizes from delta of sorted RVAs ---
frvas = [(r.Field.row_index, r.Rva) for r in md.FieldRva.rows]
rva_sorted = sorted(set(r for _,r in frvas))
def size_of(rva):
    i = rva_sorted.index(rva)
    if i+1 < len(rva_sorted): return rva_sorted[i+1]-rva
    return 0x40  # last one, cap

def blob_for_fieldname(target):
    for rid, rva in frvas:
        if fname(rid) == target:
            off = pe.get_offset_from_rva(rva)
            sz  = size_of(rva)
            return bytes(pe.__data__[off:off+sz]), rva, sz
    return None, None, None

def emulate(blob):
    """Faithful replica of sFiJMQXSvoLu/SKxcWzQVNbkE mini-VM."""
    ptr = 0
    stack = []
    num3 = 4
    halt = False
    guard = 0
    while not halt and guard < 100000:
        guard += 1
        b = blob[ptr]; ptr += 1
        if 1 <= b <= 3:
            if b == 2:      # concat top two
                s = stack[-2] + stack[-1]; stack[-2] = s; stack.pop(); ptr += 8; continue
            if b == 3:      # end
                break
            if b == 1:      # nop
                continue
        # load-string instruction (b not in 1..3)
        b2 = blob[ptr]                       # xor key
        p = ptr + 4                          # skip 4
        num11 = struct.unpack_from('<i', blob, p + 4)[0]  # length at ptr+8
        p += 8                               # data start = ptr+12
        data = bytes((blob[p+i] ^ b2) for i in range(num11))
        ptr = p + num11
        stack.append(decode_str(data))
    return stack[-1] if stack else ""

def decode_str(data):
    # new string((char*)buf): UTF-16LE until null
    s = data.decode('utf-16-le','replace')
    z = s.find('\x00')
    return s[:z] if z>=0 else s

for label, field in [("KEY","AsynchronousgetImpersonationLevel"),
                     ("IV","LASTCALENDARClosedDelegateOnly")]:
    blob, rva, sz = blob_for_fieldname(field)
    print(f"\n===== {label}  field={field} =====")
    if blob is None:
        print("  FIELD NOT FOUND"); continue
    print(f"  rva=0x{rva:x} size={sz}")
    print(f"  raw: {blob.hex()}")
    try:
        s = emulate(blob)
        print(f"  emulated string: {s!r}  (len={len(s)})")
        print(f"  utf8 bytes: {s.encode('utf-8').hex()}  (len={len(s.encode('utf-8'))})")
    except Exception as e:
        print(f"  emulate error: {e}")
    # brute single-byte XOR over whole blob as fallback view
    print("  -- single-byte XOR printable scan --")
    for k in range(256):
        dec = bytes(c ^ k for c in blob)
        printable = sum(1 for c in dec if 32 <= c < 127)
        if printable >= max(16, int(sz*0.6)):
            txt = ''.join(chr(c) if 32<=c<127 else '.' for c in dec)
            print(f"    xor 0x{k:02x} ({printable}/{sz}): {txt}")
