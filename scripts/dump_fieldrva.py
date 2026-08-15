# -*- coding: utf-8 -*-
"""Dump ALL FieldRVA static fields: rid, name, RVA, size (gap to next RVA), preview hex."""
import dnfile, os
from dncil.cil.body.reader import read_method_body_from_bytes

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples", "RustSecure.exe")
raw = open(PATH, "rb").read()
pe = dnfile.dnPE(PATH)
md = pe.net.mdtables

def S(x):
    if isinstance(x, bytes): return x.decode("latin1", "replace")
    if hasattr(x, "value"): return S(x.value)
    return str(x)

# collect all FieldRVA: (rid, name, rva)
entries = []
for r in md.FieldRva.rows:
    rid = r.Field.row_index
    frow = r.Field.row
    nm = S(frow.Name.value) if hasattr(frow.Name, "value") else S(frow.Name)
    rva = r.Rva
    entries.append((rid, nm, rva))

entries.sort(key=lambda e: e[2])
print(f"[*] total FieldRVA fields: {len(entries)}")

# compute sizes from gaps (assume sorted by RVA; a field's size = next RVA - its RVA)
import bisect
rvas = [e[2] for e in entries]
for i, (rid, nm, rva) in enumerate(entries):
    nxt = rvas[i+1] if i+1 < len(rvas) else None
    size = (nxt - rva) if nxt else 0
    off = pe.get_offset_from_rva(rva)
    data = raw[off:off+min(size,64)] if (off and size) else raw[off:off+64] if off else b""
    tag = ""
    if data[:2] == b"MZ": tag = " [MZ DLL]"
    elif data[:8] == b"\x89PNG\r\n\x1a\n": tag = " [PNG]"
    elif size in (16,24,32,64): tag = " <== KEY/IV/SECRET SIZE!"
    elif size and size > 100 and size < 4096: tag = " [enc-string?]"
    print(f"  rid={rid:4d} RVA=0x{rva:08x} size={size:5d} {nm}{tag}")
    if tag and "SIZE" in tag:
        print(f"       hex = {data.hex()}")
