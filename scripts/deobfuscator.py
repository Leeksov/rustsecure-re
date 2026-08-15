# -*- coding: utf-8 -*-
"""RustSecure deobfuscator — Stage 1: build delegate-array map (field -> [method rids]).
   Obfuscation: static IntPtr[] fields hold function pointers (ldftn); dispatch via calli."""
import dnfile, json, sys, os
from dncil.cil.body.reader import read_method_body_from_bytes

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples", "RustSecure.exe")
raw = open(PATH, "rb").read()
pe = dnfile.dnPE(PATH)
md = pe.net.mdtables

def S(x):
    return x.decode("latin1", "replace") if isinstance(x, bytes) else str(x)

method_name = {}
for i, r in enumerate(md.MethodDef.rows, start=1):
    method_name[i] = S(r.Name)
field_name = {}
for i, r in enumerate(md.Field.rows, start=1):
    field_name[i] = S(r.Name)

def opval(insn):
    op = insn.operand
    return getattr(op, "value", op)

# delegate_map[field_rid] = [ (idx, method_rid), ... ]
delegate_map = {}

for i, m in enumerate(md.MethodDef.rows, start=1):
    off = pe.get_offset_from_rva(m.Rva)
    if off is None: continue
    try:
        body = read_method_body_from_bytes(raw[off:off+200000])
    except Exception:
        continue
    insns = body.instructions
    for j, insn in enumerate(insns):
        if insn.mnemonic != "newarr": continue
        op = opval(insn)
        if not (isinstance(op, int) and (op >> 24) == 0x01):  # TypeRef
            continue
        # look back for ldc.i4 count, look forward for stsfld
        cnt = None
        for k in range(j-1, max(0, j-4), -1):
            if insns[k].mnemonic.startswith("ldc.i4"):
                cnt = opval(insns[k]); break
        field_rid = None
        for k in range(j+1, min(len(insns), j+6)):
            if insns[k].mnemonic == "stsfld":
                fo = opval(insns[k])
                if isinstance(fo, int) and (fo >> 24) == 0x04:
                    field_rid = fo & 0xFFFFFF
                break
        if field_rid is None: continue
        # now find ldsfld <field> + ldc.i4 <idx> + ldftn <method> + stelem.i
        entries = {}
        for k in range(j+1, len(insns)):
            if insns[k].mnemonic == "ldsfld":
                fo = opval(insns[k])
                if not (isinstance(fo, int) and (fo & 0xFFFFFF) == field_rid): continue
                # next: ldc.i4 idx, ldftn method, stelem.i
                idx = None; mth = None
                for kk in range(k+1, min(len(insns), k+5)):
                    if insns[kk].mnemonic.startswith("ldc.i4"):
                        idx = opval(insns[kk]); break
                for kk in range(k+1, min(len(insns), k+6)):
                    if insns[kk].mnemonic == "ldftn":
                        mo = opval(insns[kk])
                        if isinstance(mo, int) and (mo >> 24) == 0x06:
                            mth = mo & 0xFFFFFF
                        break
                if idx is not None and mth is not None:
                    entries[idx] = mth
        if entries:
            delegate_map.setdefault(field_rid, {}).update(entries)

# report
print("[*] delegate-array fields:", len(delegate_map))
total = 0
for fr in sorted(delegate_map):
    e = delegate_map[fr]
    total += len(e)
    mx = max(e) if e else -1
    # check contiguity
    missing = [x for x in range(mx+1) if x not in e]
    flag = "" if not missing else f"  MISSING={missing}"
    print(f"  FLD[{fr}] {field_name.get(fr,'?')}  entries={len(e)}  max_idx={mx}{flag}")
print("[*] total method slots:", total)

# save
out = {str(k): {str(i): v for i, v in delegate_map[k].items()} for k in delegate_map}
json.dump(out, open(os.path.join(os.path.dirname(__file__), "delegate_map.json"), "w"), indent=1)
print("[*] saved delegate_map.json")
