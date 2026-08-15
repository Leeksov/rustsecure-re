#!/usr/bin/env python3
"""
RustSecure standalone WebSocket client (pure Python + mono crypto bridge).
Connects to the anticheat server without the game.

Requires: pip install websockets requests
Also requires: mono + compiled crypto_bridge.exe (uses Core DLL's real crypto)

Usage:
  # First compile the bridge:
  mcs -unsafe scripts/crypto_bridge.cs -out:scripts/crypto_bridge.exe

  # Run:
  python3 scripts/ws_client.py <steamid64> [--upload image.png]
"""

import asyncio, json, base64, time, sys, os, subprocess, argparse

try:
    import websockets
except ImportError:
    print("pip install websockets"); sys.exit(1)

try:
    import requests
except ImportError:
    requests = None

WS_URL = "wss://rustsecure.ru/ws"
UPLOAD_URL = "https://rustsecure.ru/api/ingest/screenshot"
BRIDGE_EXE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crypto_bridge.exe")


class CryptoBridge:
    """Subprocess bridge to Core DLL crypto via mono."""

    def __init__(self):
        if not os.path.exists(BRIDGE_EXE):
            raise FileNotFoundError(f"Compile first: mcs -unsafe scripts/crypto_bridge.cs -out:{BRIDGE_EXE}")
        self.proc = subprocess.Popen(
            ["mono", BRIDGE_EXE],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1)
        # Wait for READY
        self.proc.stderr.readline()

    def _cmd(self, line: str) -> str:
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        return self.proc.stdout.readline().strip()

    def genkey(self):
        """Generate X25519 keypair. Returns (private_hex, public_hex)."""
        r = self._cmd("GENKEY").split()
        return r[1], r[2]

    def ecdh(self, priv_hex: str, peer_pub_hex: str) -> str:
        """Compute ECDH shared secret. Returns hex."""
        r = self._cmd(f"ECDH {priv_hex} {peer_pub_hex}").split()
        return r[1]

    def derive(self, shared_hex: str, cn_hex: str, sn_hex: str):
        """Configure session from ECDH. Returns (enc_key_hex, session_id)."""
        r = self._cmd(f"DERIVE {shared_hex} {cn_hex} {sn_hex}").split()
        return r[1], r[2]

    def protect(self, plaintext: str) -> str:
        """Encrypt message. Returns envelope string."""
        r = self._cmd(f"PROTECT {plaintext}")
        return r[4:]  # strip "ENC "

    def unprotect(self, envelope: str) -> str:
        """Decrypt message. Returns plaintext or None."""
        r = self._cmd(f"UNPROTECT {envelope}")
        if r.startswith("DEC "): return r[4:]
        return None

    def sig(self, prefix: str, *parts: str) -> str:
        """Compute handshake signature."""
        r = self._cmd(f"SIG {prefix} {' '.join(parts)}")
        return r[4:]  # strip "SIG "

    def close(self):
        self.proc.stdin.close()
        self.proc.wait()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64url_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


async def run(steam_id: str, upload_image: str = None):
    crypto = CryptoBridge()
    print(f"[+] Crypto bridge started")

    # Generate keypair
    priv_hex, pub_hex = crypto.genkey()
    pub_b64 = b64url(bytes.fromhex(pub_hex))
    print(f"[+] Keypair generated")

    # Generate nonce
    nonce = os.urandom(16)
    nonce_b64 = b64url(nonce)
    ts = int(time.time())

    # Compute handshake signature via bridge
    sig = crypto.sig("client-hello", pub_b64, nonce_b64, str(ts))

    # Connect
    print(f"[*] Connecting to {WS_URL}...")
    async with websockets.connect(WS_URL) as ws:
        # Send ClientHello
        hello = json.dumps({
            "type": "ClientHello",
            "pub": pub_b64,
            "nonce": nonce_b64,
            "ts": ts,
            "sig": sig
        })
        await ws.send(hello)
        print("[>] ClientHello")

        # Receive ServerHello
        resp = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
        print(f"[<] ServerHello")

        if resp.get("type") != "ServerHello":
            print(f"[!] Unexpected: {resp.get('type')}")
            return

        server_pub_b64 = resp["pub"]
        server_pub_hex = b64url_dec(server_pub_b64).hex()

        # ECDH shared secret
        shared_hex = crypto.ecdh(priv_hex, server_pub_hex)
        print(f"[+] ECDH complete")

        # Derive session keys
        server_nonce_hex = b64url_dec(resp["nonce"]).hex()
        enc_key, session_id = crypto.derive(shared_hex, nonce.hex(), server_nonce_hex)
        print(f"[+] Session: {session_id[:20]}...")

        # Send PlayerConnected
        pc_msg = json.dumps({
            "type": "PlayerConnected",
            "steamId": steam_id,
            "playerName": "Player",
            "hwids": {}
        })
        encrypted = crypto.protect(pc_msg)
        await ws.send(encrypted)
        print(f"[>] PlayerConnected")

        # Listen loop
        print(f"[*] Listening... (Ctrl+C to stop)")
        while True:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=60)
                decrypted = crypto.unprotect(raw)

                if decrypted:
                    print(f"[<] {decrypted[:200]}")

                    if "RequestScreenshotV2" in decrypted:
                        parts = decrypted.split("|")
                        if len(parts) >= 6:
                            req_id = parts[1]
                            sig_val = parts[5]
                            print(f"\n[!!!] SCREENSHOT REQUEST")
                            print(f"  RequestId: {req_id}")
                            print(f"  Signature: {sig_val}")

                            if upload_image and requests:
                                png = open(upload_image, "rb").read() if os.path.exists(upload_image) else b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
                                url = f"{UPLOAD_URL}?method=dxgi&width=1920&height=1080&affinity=0"
                                r = requests.post(url, data=png, headers={
                                    "X-RS-SteamId": steam_id,
                                    "X-RS-RequestId": req_id,
                                    "X-RS-RequestSig": sig_val,
                                    "Content-Type": "application/octet-stream",
                                }, timeout=10)
                                print(f"  Upload: {r.status_code} {r.text[:80]}")

                    elif "BanPlayer" in decrypted:
                        print(f"\n[!!!] BAN: {decrypted}")

                else:
                    print(f"[<] (raw) {raw[:60]}...")

            except asyncio.TimeoutError:
                # Heartbeat
                hb = json.dumps({"type": "Heartbeat", "steamId": steam_id})
                encrypted = crypto.protect(hb)
                await ws.send(encrypted)
                print(f"[>] Heartbeat")

            except websockets.ConnectionClosed as e:
                print(f"[!] Connection closed: {e}")
                break

    crypto.close()


def main():
    parser = argparse.ArgumentParser(description="RustSecure standalone WS client")
    parser.add_argument("steamid", help="SteamID64")
    parser.add_argument("--upload", help="Image to upload on screenshot request")
    args = parser.parse_args()

    try:
        asyncio.run(run(args.steamid, args.upload))
    except KeyboardInterrupt:
        print("\n[*] Stopped")


if __name__ == "__main__":
    main()
