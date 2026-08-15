# -*- coding: utf-8 -*-
"""dnfile-based analysis of RustSecure.exe v4."""
import dnfile, struct, re, os

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples", "RustSecure.exe")
raw = open(PATH, "rb").read()
pe = dnfile.dnPE(PATH)
md = pe.net.mdtables

def S(x):
    return x.decode("latin1", "replace") if isinstance(x, bytes) else str(x)

print("=== SECTIONS ===")
for s in pe.sections:
    print(f"  {S(s.Name)} vaddr=0x{s.VirtualAddress:x} vsize=0x{s.Misc_VirtualSize:x} rawptr=0x{s.PointerToRawData:x} rawsize=0x{s.SizeOfRawData:x}")

# ---- field owner map ----
field_owner = {}
for t in md.TypeDef.rows:
    owner = S(t.TypeNamespace) + "." + S(t.TypeName)
    for f in (t.FieldList or []):
        field_owner[f.row_index] = owner

print("\n=== FIELDRVA count=%d ===" % len(md.FieldRva.rows))
for r in md.FieldRva.rows:
    rva = r.Rva
    fidx = r.Field.row_index
    f = md.Field.rows[fidx - 1]
    fname = S(f.Name)
    owner = field_owner.get(fidx, "?")
    off = pe.get_offset_from_rva(rva)
    blob = raw[off:off+64] if off is not None else b""
    ascii_ = "".join(chr(c) if 32 <= c < 127 else "." for c in blob)
    print(f"  RVA=0x{rva:08x} off=0x{off:08x} field={fname} owner={owner}")
    print(f"      hex={blob.hex()}  ascii={ascii_}")

print("\n=== MANIFEST RESOURCES ===")
for r in md.ManifestResource.rows:
    print(f"  name={S(r.Name)} offset=0x{r.Offset:x} flags=0x{r.Flags:x} impl={r.Implementation}")

print("\n=== METHODDEFS (name + RVA) ===")
for r in md.MethodDef.rows:
    print(f"  [0x{r.row_index:06x}] RVA=0x{r.Rva:08x} {S(r.Name)}")

print("\nDONE")
