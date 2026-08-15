# -*- coding: utf-8 -*-
"""Dump full IL of key methods by name."""
import dnfile, sys, os
from dncil.cil.body.reader import read_method_body_from_bytes

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples", "RustSecure.exe")
raw = open(PATH, "rb").read()
pe = dnfile.dnPE(PATH)
md = pe.net.mdtables

def S(x):
    return x.decode("latin1", "replace") if isinstance(x, bytes) else str(x)

memref = {}
for i, r in enumerate(md.MemberRef.rows):
    c = getattr(r.Class, "row", None)
    cn = "?"
    if c is not None:
        if hasattr(c, "TypeName"): cn = S(getattr(c, "TypeNamespace", "")) + "." + S(c.TypeName)
        elif hasattr(c, "Name"): cn = S(c.Name)
    memref[0x0A000000 | (i+1)] = cn + "::" + S(r.Name)
method = {}
for i, r in enumerate(md.MethodDef.rows):
    method[0x06000000 | (i+1)] = S(r.Name)
field = {}
for i, r in enumerate(md.Field.rows):
    field[0x04000000 | (i+1)] = S(r.Name)
typeref = {}
for i, r in enumerate(md.TypeRef.rows):
    typeref[0x01000000 | (i+1)] = S(r.TypeNamespace) + "." + S(r.TypeName)
string_tokens = {}

def fmt_op(op):
    if hasattr(op, "value"): op = op.value
    if isinstance(op, int):
        hi = op >> 24; rid = op & 0xFFFFFF
        if hi == 0x0A: return f"call {memref.get(op,'?')}"
        if hi == 0x06: return f"[MD {rid:04x}] {method.get(op,'?')}"
        if hi == 0x04: return f"[FLD {rid:04x}] {field.get(op,'?')}"
        if hi == 0x70: return f'ldstr "{string_tokens.get(op, hex(rid))}"'
        if hi == 0x02: return f"TypeDef(0x{rid:x})"
        if hi == 0x01: return f"[{typeref.get(op,'TypeRef')}]"
        if hi == 0x1B: return f"TypeSpec(0x{rid:x})"
        return f"0x{op:08x}"
    return str(op)

# build method name -> rid
name2rid = {}
for i, r in enumerate(md.MethodDef.rows, start=1):
    nm = S(r.Name)
    name2rid.setdefault(nm, i)

# user strings (#US) for ldstr resolution
try:
    us = pe.net.user_strings
except Exception:
    us = None

targets = sys.argv[1:] if len(sys.argv) > 1 else []
if not targets:
    targets = ["AesEncryptCbc", "EncryptLine", "Sha256", "Hmac", "DecryptPayload",
               "ComputeSignature", "BuildMacInput", "HmacSha256", "DownloadCorePayload",
               "DownloadNativePayload", "DownloadAndDecryptPayload", "Base64UrlDecode"]

for t in targets:
    rid = name2rid.get(t)
    if rid is None:
        print(f"\n### {t}: NOT FOUND")
        continue
    m = md.MethodDef.rows[rid-1]
    off = pe.get_offset_from_rva(m.Rva)
    if off is None:
        print(f"\n### {t}: no RVA")
        continue
    body = read_method_body_from_bytes(raw[off:off+200000])
    print(f"\n### {t} [0x{rid:06x}] RVA=0x{m.Rva:08x}")
    for insn in body.instructions:
        # resolve ldstr operand
        op = insn.operand
        if insn.mnemonic == "ldstr" and hasattr(op, "value"):
            tok = op.value
            rid_ = tok & 0xFFFFFF
            try:
                s = us.get(rid_) if us else None
                sv = s.value if s else None
            except Exception:
                sv = None
            print(f"  {insn.offset:04X}  ldstr           \"{sv}\"")
            continue
        print(f"  {insn.offset:04X}  {insn.mnemonic:14s} {fmt_op(op)}")

print("\nDONE")
