#!/usr/bin/env python3
"""
Decrypt RustSecure anti-cheat encrypted log files.

RSLD1 (loader logs): hex-encoded
  Format: version(1) + kdf_salt(16) + aes_iv(16) + ciphertext + hmac(32)
  Key derivation per line:
    sha256  = SHA256(masterKey || kdf_salt)
    enc_key = HMAC-SHA256(key=sha256, data=UTF8("enc"))
    mac_key = HMAC-SHA256(key=sha256, data=UTF8("mac"))
  Master key: UTF8("RustSecureLoaderLogKey.2026.v1") = 30 bytes

RSLG2 (core logs): base64-encoded
  Format: version(1) + kdf_salt(16) + aes_iv(16) + ciphertext + hmac(32)
  Key string: "RseSec2026KeyForDebugLogsEncryption!" (core string [752280829])
"""

import hashlib
import hmac
import base64
import sys
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ---------- Config ----------
LOADER_MASTER_KEY = b"RustSecureLoaderLogKey.2026.v1"   # 30 bytes
CORE_MASTER_KEY   = b"RseSec2026KeyForDebugLogsEncryption!"  # 36 bytes

LOADER_LOG = "/Users/leeksov/Downloads/AyuGram Desktop/logs.log"
CORE_LOG   = "/Users/leeksov/Downloads/AyuGram Desktop/RustSecure.log"
OUT_LOADER = "/Users/leeksov/Desktop/reversesmth/rustac/data/logs_decrypted.txt"
OUT_CORE   = "/Users/leeksov/Desktop/reversesmth/rustac/data/rustsecure_log_decrypted.txt"


# ---------- Key derivation ----------
def derive_keys(master_key: bytes, kdf_salt: bytes):
    """Derive enc_key and mac_key from master key and per-line salt."""
    sha = hashlib.sha256(master_key + kdf_salt).digest()
    enc_key = hmac.new(sha, b"enc", hashlib.sha256).digest()
    mac_key = hmac.new(sha, b"mac", hashlib.sha256).digest()
    return enc_key, mac_key


def verify_hmac(mac_key: bytes, data: bytes, expected_mac: bytes) -> bool:
    """Verify HMAC-SHA256."""
    computed = hmac.new(mac_key, data, hashlib.sha256).digest()
    return hmac.compare_digest(computed, expected_mac)


# ---------- Decrypt RSLD1 ----------
def decrypt_rsld1_line(line: str, master_key: bytes) -> Optional[str]:
    """Decrypt a single RSLD1: hex-encoded line."""
    line = line.strip()
    if line.startswith("﻿"):
        line = line[1:]
    if not line.startswith("RSLD1:"):
        return None

    try:
        raw = bytes.fromhex(line[6:])
    except ValueError:
        return None

    if len(raw) < 65:  # 1 + 16 + 16 + 0 + 32
        return f"[TOO_SHORT: {len(raw)} bytes]"

    version   = raw[0]
    kdf_salt  = raw[1:17]
    aes_iv    = raw[17:33]
    ct        = raw[33:-32]
    hmac_val  = raw[-32:]

    if len(ct) % 16 != 0:
        return f"[BAD_CT_LEN: {len(ct)} not mod 16]"

    enc_key, mac_key = derive_keys(master_key, kdf_salt)

    try:
        cipher = AES.new(enc_key, AES.MODE_CBC, aes_iv)
        pt = unpad(cipher.decrypt(ct), 16)
        return pt.decode("utf-8", errors="replace")
    except Exception as e:
        return f"[DECRYPT_ERROR: {e}]"


# ---------- Decrypt RSLG2 ----------
def decrypt_rslg2_line(line: str, master_key: bytes) -> Optional[str]:
    """Decrypt a single RSLG2: base64-encoded line."""
    line = line.strip()
    if line.startswith("﻿"):
        line = line[1:]
    if not line.startswith("RSLG2:"):
        return None

    try:
        raw = base64.b64decode(line[6:])
    except Exception:
        return None

    if len(raw) < 65:
        return f"[TOO_SHORT: {len(raw)} bytes]"

    version   = raw[0]
    kdf_salt  = raw[1:17]
    aes_iv    = raw[17:33]
    ct        = raw[33:-32]
    hmac_val  = raw[-32:]

    if len(ct) % 16 != 0:
        return f"[BAD_CT_LEN: {len(ct)} not mod 16]"

    enc_key, mac_key = derive_keys(master_key, kdf_salt)

    try:
        cipher = AES.new(enc_key, AES.MODE_CBC, aes_iv)
        pt = unpad(cipher.decrypt(ct), 16)
        return pt.decode("utf-8", errors="replace")
    except Exception as e:
        return f"[DECRYPT_ERROR: {e}]"


# ---------- Main ----------
def main():
    print("=" * 70)
    print("RustSecure Log Decryptor")
    print("=" * 70)

    # ---- RSLD1 (loader logs) ----
    print(f"\n[*] Decrypting RSLD1 loader logs: {LOADER_LOG}")
    with open(LOADER_LOG, "r", encoding="utf-8-sig") as f:
        loader_lines = [l.strip() for l in f if l.strip()]
    print(f"    {len(loader_lines)} lines")

    decrypted_loader = []
    ok_count = 0
    for line in loader_lines:
        result = decrypt_rsld1_line(line, LOADER_MASTER_KEY)
        if result and not result.startswith("["):
            ok_count += 1
        decrypted_loader.append(result if result else f"[PARSE_ERROR]")

    print(f"    Decrypted: {ok_count}/{len(loader_lines)} lines OK")
    if ok_count > 0:
        print(f"    First line: {decrypted_loader[0][:120]}")

    with open(OUT_LOADER, "w", encoding="utf-8") as f:
        f.write(f"# RSLD1 Loader logs decrypted ({ok_count}/{len(loader_lines)} OK)\n")
        f.write(f"# Key: SHA256(UTF8('RustSecureLoaderLogKey.2026.v1') || kdf_salt) -> HMAC('enc')\n")
        f.write(f"# Format: version(1) + salt(16) + iv(16) + AES-CBC-ciphertext + HMAC-SHA256(32)\n")
        f.write(f"# Source: {LOADER_LOG}\n\n")
        for d in decrypted_loader:
            f.write(d + "\n")
    print(f"[+] Saved to {OUT_LOADER}")

    # ---- RSLG2 (core logs) ----
    print(f"\n[*] Decrypting RSLG2 core logs: {CORE_LOG}")
    with open(CORE_LOG, "r", encoding="utf-8-sig") as f:
        core_lines = [l.strip() for l in f if l.strip()]
    print(f"    {len(core_lines)} lines")

    decrypted_core = []
    ok_count = 0
    for line in core_lines:
        result = decrypt_rslg2_line(line, CORE_MASTER_KEY)
        if result and not result.startswith("["):
            ok_count += 1
        decrypted_core.append(result if result else f"[PARSE_ERROR]")

    print(f"    Decrypted: {ok_count}/{len(core_lines)} lines OK")
    if ok_count > 0:
        print(f"    First line: {decrypted_core[0][:120]}")

    if ok_count == 0:
        print("[*] Core key didn't work. Trying loader key on RSLG2...")
        decrypted_core = []
        ok_count2 = 0
        for line in core_lines:
            result = decrypt_rslg2_line(line, LOADER_MASTER_KEY)
            if result and not result.startswith("["):
                ok_count2 += 1
            decrypted_core.append(result if result else f"[PARSE_ERROR]")
        if ok_count2 > 0:
            ok_count = ok_count2
            print(f"    Loader key works! {ok_count}/{len(core_lines)} OK")
            print(f"    First line: {decrypted_core[0][:120]}")

    with open(OUT_CORE, "w", encoding="utf-8") as f:
        f.write(f"# RSLG2 Core logs decrypted ({ok_count}/{len(core_lines)} OK)\n")
        f.write(f"# Format: version(1) + salt(16) + iv(16) + AES-CBC-ciphertext + HMAC-SHA256(32)\n")
        f.write(f"# Source: {CORE_LOG}\n\n")
        for d in decrypted_core:
            f.write(d + "\n")
    print(f"[+] Saved to {OUT_CORE}")

    print(f"\n{'='*70}")
    print("Done.")


if __name__ == "__main__":
    main()
