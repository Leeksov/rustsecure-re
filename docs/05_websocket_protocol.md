# RustSecure WebSocket Protocol (v3)

Reconstructed from decompiled Core DLL classes:
- `SynchronizeFrameUpdate` (high-level anti-cheat coordinator / message builder)
- `StabilizeFrameTiming` (low-level WebSocket client, encryption, reconnection)
- `AssessFrameQualityDecorator` (ECDH handshake, ChaCha20-Poly1305 session crypto, HMAC)

All obfuscated string references below are resolved via the decrypted string table (`core_decrypted_strings.txt`).

---

## 1. Connection Establishment

### Endpoint

```
wss://rustsecure.ru/ws
```

String `[752280813]`. The client also accepts `ws://` and `wss://` scheme prefixes (`[752280976]`, `[752280982]`).

### Transport

Standard `System.Net.WebSockets.ClientWebSocket`. TLS is configured once (static `_tlsConfigured` flag). A `SemaphoreSlim` pair guards connection state (`_stateLock`) and send serialisation (`_sendLock`).

### Constructor Flow

```
SynchronizeFrameUpdate(webSocketUrl, sharedSecret)
  -> creates StabilizeFrameTiming(webSocketUrl, sharedSecret)
       -> creates AssessFrameQualityDecorator(sharedSecret)
            _masterSecret = UTF8.GetBytes(sharedSecret)
            _encKey = new byte[0]  (empty until ECDH completes)
            _sessionId = ""
            _sendSeq = 0, _recvSeq = 0
       -> stores _serverUrl, creates _stateLock(1,1), _sendLock(1,1)
  -> builds screenshot upload URL from WebSocket URL
  -> creates _recentThreats dedup dictionary
  -> subscribes HandleServerCommand to client.CommandReceived event
```

### Screenshot Upload URL Derivation

`BuildScreenshotUploadUrl(webSocketUrl)` replaces the `/ws` path suffix with `/api/ingest/screenshot` (`[752280941]`) and upgrades `ws://` to `http://`, `wss://` to `https://`.

Result: `https://rustsecure.ru/api/ingest/screenshot`

---

## 2. ECDH Handshake (v3)

After the raw WebSocket connects (`EnsureConnectedAsync`), a custom handshake establishes an encrypted session. The protocol version is `v3` (`[752280074]`).

### 2.1 Client Hello

The client:
1. Generates an ephemeral X25519 private key (32 bytes) via `GenerateEphemeralPrivateKey()` (uses `Org.BouncyCastle.Math.EC.Rfc7748.X25519`).
2. Derives the public key with `DerivePublicKey(privateKey)`.
3. Generates a 16-byte random nonce (`clientNonce`).
4. Base64URL-encodes the public key and nonce.
5. Computes a handshake signature:
   ```
   sig = ComputeHandshakeSignature("client-hello", clientPubB64, clientNonceB64, timestampStr)
   ```
   This is `HMAC-SHA256(masterSecret, "client-hello" + "|" + clientPubB64 + "|" + clientNonceB64 + "|" + timestampStr)`, Base64URL-encoded.
6. Sends the ClientHello message as raw JSON (not encrypted):

```json
{
  "type": "ClientHello",
  "pub": "<base64url-encoded X25519 public key>",
  "nonce": "<base64url-encoded 16-byte nonce>",
  "ts": <unix_timestamp_seconds>,
  "sig": "<base64url-encoded HMAC-SHA256>"
}
```

Constructed by string concatenation from `[752280947]` `{"type":"ClientHello","pub":"`, `[752280946]` `","nonce":"`, `[752280909]` `","ts":`, `[752280908]` `,"sig":"`, `[752280948]` `"}`.

### 2.2 Server Hello

The client receives a JSON response and parses it:

1. Checks `type` field (`[752280910]`) equals `"ServerHello"` (`[752280905]`).
   - If missing or wrong type: throws `"Invalid handshake response type"` (`[752280904]`).
   - If response is empty: throws `"Server handshake response is empty"` (`[752280911]`).
2. Extracts fields:
   - `pub` (`[752280907]`): server's X25519 public key (must be exactly 32 bytes when decoded).
   - `nonce` (`[752280906]`): server nonce.
   - `ts` (`[752280901]`): server timestamp (int64).
   - `sig` (`[752280900]`): server signature.
3. Validates server public key length == 32 bytes.
   - If invalid: throws `"Invalid server public key"` (`[752280903]`).
4. Verifies the server signature:
   ```
   VerifyHandshakeSignature("server-hello", serverSig, clientPubB64, serverPubB64, clientNonceB64, serverNonceB64, serverTs)
   ```
   This recomputes `HMAC-SHA256(masterSecret, "server-hello" + "|" + part1 + "|" + part2 + ...)` and compares using `FixedTimeEquals` (constant-time comparison).
   - If mismatch: throws `"Server handshake signature mismatch"` (`[752280897]`).

### 2.3 Session Key Derivation

After signature verification:

1. Computes the ECDH shared secret:
   ```
   ecdhShared = X25519.ScalarMult(clientPrivateKey, serverPublicKey)
   ```
   via `GenerateSharedSecret(clientPrivate, serverPubBytes)`.

2. Derives session material with `ConfigureSessionFromEcdh(ecdhShared, clientNonce, serverNonce)`:
   - Concatenates `salt = clientNonce || serverNonce` (or similar byte combination).
   - Uses HKDF-Expand (HMAC-SHA256 based) with domain labels:
     - `"rs-v3-enc"` (`[752280078]`): derives the 32-byte encryption key (`_encKey`).
     - `"rs-v3-sid"` (`[752280073]`): derives the session ID string (`_sessionId`).
     - `"rs-v3-salt"` (`[752280079]`): derives additional keying material.
   - Resets sequence counters: `_sendSeq = 0`, `_recvSeq = 0`.

Validation checks during this process:
- `"ecdhShared is invalid"` (`[752280082]`)
- `"peerPublicKey is invalid"` (`[752280083]`)
- `"privateKey is invalid"` (`[752280080]`)
- `"clientNonce is invalid"` (`[752280077]`)
- `"serverNonce is invalid"` (`[752280076]`)

### 2.4 Crypto Primitives

| Primitive | Implementation |
|-----------|---------------|
| Key exchange | X25519 (RFC 7748) via BouncyCastle |
| HMAC | HMAC-SHA256 (System.Security.Cryptography.HMACSHA256) |
| AEAD encryption | ChaCha20-Poly1305 (BouncyCastle `Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305`) |
| Key derivation | HKDF-Expand (custom, HMAC-SHA256 based) |
| Encoding | Base64URL (no padding) |

---

## 3. Message Framing

### 3.1 Encrypted Messages (Post-Handshake)

`SendAsync(messageType, dataJson)` is the primary send path:

1. Builds the plaintext JSON envelope via `BuildMessageJson(messageType, dataJson)`:
   ```json
   {"type":"<messageType>","data":<dataJson>,"timestamp":"<ISO8601>"}
   ```
   Constructed from `[752280955]` `{"type":"`, `[752280954]` `","data":`, `[752280949]` `,"timestamp":"`, with the timestamp being `DateTime.UtcNow` formatted as ISO 8601.

2. Encrypts with `SendEncryptedPayloadAsync(plainJson)`:
   - Calls `_protector.Protect(plainJson)` which:
     - Increments `_sendSeq`.
     - Constructs AAD (additional authenticated data) from `sessionId + "|" + sendSeq + "|" + recvSeq`.
     - Encrypts using ChaCha20-Poly1305 with:
       - Key: `_encKey` (32 bytes, derived from ECDH)
       - Nonce: derived from sequence number
       - AAD: as above
     - Returns Base64URL-encoded ciphertext with appended auth tag.
   - Wraps the ciphertext into a framing envelope (the exact wire format is the `v3.` prefix followed by the encrypted blob).

3. Sends via `SendRawAsync(json)` which writes to the WebSocket as a text message.

### 3.2 Plain Messages

`SendPlainAsync(messageType, dataJson)` sends messages without encryption. Used for specific message types where encryption is not required. The JSON structure is the same as `BuildMessageJson`.

### 3.3 Receive Path

`ReceiveLoopAsync` continuously reads from the WebSocket:
1. `ReceiveMessageAsync` reads a complete text message (4096-byte buffer).
2. The `_protector.TryUnprotect(envelopeText, out plainText)` attempts decryption:
   - Validates sequence numbers (server's `recvSeq` must be > client's `_recvSeq`).
   - Decrypts using ChaCha20-Poly1305 with the same key/AAD scheme.
   - Updates `_recvSeq`.
3. On successful decryption, fires `CommandReceived` event.
4. `HandleServerCommand` in `SynchronizeFrameUpdate` dispatches based on command content.

---

## 4. Message Types

### 4.1 Client -> Server Messages

#### PlayerConnected
Sent after `InitializeAsync(steamId, playerName, hwids)` completes.

```
messageType: "PlayerConnected"  [752280936]
data: BuildPlayerConnectedJson(steamId, playerName, hwids)
```

JSON body structure:
```json
{
  "steamId": "<17-digit SteamID64>",
  "playerName": "<player display name>",
  "hwids": {
    "hwid_machine_guid": "<value>",
    "hwid_disk_physical_serials": "<value>",
    "hwid_mac_address": "<value>",
    ...
  }
}
```

Constructed from:
- `[752280966]` `"steamId":"`
- `[752280960]` `"playerName":"`
- `[752280962]` `,"hwids":{`

The HWID dictionary includes all collected hardware identifiers (see `core_decrypted_strings.txt` entries `[752280616]` through `[752280672]`).

#### PlayerDisconnected
Sent on player disconnect.

```
messageType: "PlayerDisconnected"  [752280942]
data: BuildJson("steamId", <steamId>)
```

```json
{"steamId": "<SteamID64>"}
```

#### ThreatDetected
Sent when the anti-cheat detects a security violation. Deduplication via `IsDuplicateThreat` prevents repeat reports within a configurable window (`_limitConfig802`).

```
messageType: "ThreatDetected"  [752280939]
data: BuildJson("threatType", <threatType>, "details", <details>)
```

```json
{"threatType": "<threat_category>", "details": "<detailed_description>"}
```

Threat type values include categories like debugger detection, hook detection, suspicious processes, BepInEx detection, etc.

#### Heartbeat
Sent periodically by a `System.Threading.Timer` (`_heartbeatTimer`). Skipped if `_banReceived` is true or `_steamId` is empty.

```
messageType: "Heartbeat"  [752280932]
data: BuildJson("steamId", <steamId>)
```

```json
{"steamId": "<SteamID64>"}
```

#### LocalAccountsCaptured
Sent in response to a `RequestLocalAccounts` server command.

```
messageType: "LocalAccountsCaptured"  [752280935]
data: BuildLocalAccountsJson(requestId, steamId, steamIds, sourcePath, error)
```

```json
{
  "requestId": "<request_id>",
  "steamId": "<SteamID64>",
  "steamIds": ["<id1>", "<id2>", ...],
  "sourcePath": "<path_to_loginusers.vdf>",
  "error": "<error_message_or_empty>"
}
```

Constructed from:
- `[752280989]` `"requestId":"`
- `[752280966]` `"steamId":"`
- `[752280988]` `"steamIds":[`
- `[752280991]` `,"sourcePath":"`
- `[752280990]` `,"error":"`

### 4.2 Server -> Client Messages (Control Commands)

Server commands arrive as raw strings through the `CommandReceived` event and are dispatched by `HandleServerCommand`. The command format uses pipe-delimited tokens for commands with arguments.

#### BanPlayer

```
BanPlayer|<steamId>
```

String prefix: `[752280968]` `BanPlayer|`

Behavior:
1. Sets `_banReceived = true`.
2. Fires `BanReceived` event with the ban reason `"Banned by RustSecure."` (`[752280971]`).
3. Subsequent heartbeats are suppressed.

#### RequestScreenshot (v1)

```
RequestScreenshot
```

String: `[752280969]` `RequestScreenshot`

Simple screenshot request without parameters. Fires `ScreenshotRequested` event.

#### RequestScreenshotV2

```
RequestScreenshotV2|<requestId>|<issuedUnix>|<expiresUnix>|<reason>|<signature>|<preferredMethod>
```

String prefix: `[752280975]` `RequestScreenshotV2|`

Parsed by `TryParseScreenshotRequestV2(command, out ScreenshotRequest request)` into:

```csharp
struct ScreenshotRequest {
    string RequestId;
    long   IssuedUnix;
    long   ExpiresUnix;
    string Reason;
    string Signature;
    string PreferredMethod;  // "DXGI", "WGC", "Manual", etc.
}
```

The signature is verified using `ComputeScreenshotSignature(sharedSecret, steamId, requestId, issuedUnix, expiresUnix, reason, preferredMethod)` which computes HMAC-SHA256 over those fields using the shared secret. Comparison is constant-time via `FixedTimeEquals`.

#### RequestLocalAccounts

```
RequestLocalAccounts|<requestId>
```

String prefix: `[752280974]` `RequestLocalAccounts|`

Fires `LocalAccountsRequested` event. The client collects Steam account information from `loginusers.vdf` and responds with `LocalAccountsCaptured`.

#### AssFucker

```
AssFucker
```

String: `[752280970]` `AssFucker`

Fires `AssFuckerReceived` event. Purpose unclear from decompilation -- likely a developer test/easter egg command or an immediate forced action.

---

## 5. Screenshot Request/Upload Flow

### 5.1 Trigger

1. Server sends `RequestScreenshotV2|...` command.
2. `HandleServerCommand` parses it, verifies the HMAC signature, checks expiry.
3. Fires `ScreenshotRequested(requestId, reason, signature, preferredMethod)` event.
4. The anti-cheat capture subsystem captures the game window (via DXGI duplication, Windows Graphics Capture, or GDI BitBlt).
5. Calls `ReportScreenshotAsync(reason, pngBytes, width, height, method, affinityFlag, requestId, requestSig)`.

### 5.2 Upload

`TryUploadScreenshotAsync` performs an HTTP PUT/POST to the screenshot upload endpoint:

**URL construction:**
```
https://rustsecure.ru/api/ingest/screenshot?method=<method>&width=<width>&height=<height>&affinity=<affinityFlag>
```

Query parameters from strings:
- `[752280934]` `?method=`
- `[752280928]` `&width=`
- `[752280931]` `&height=`
- `[752280930]` `&affinity=`

**HTTP headers:**
| Header | Value | String ID |
|--------|-------|-----------|
| `X-RS-SteamId` | Player's SteamID64 | `[752280957]` |
| `X-RS-RequestId` | Request ID from server command | `[752280956]` |
| `X-RS-RequestSig` | HMAC signature from server command | `[752280959]` |
| `Content-Type` | `application/octet-stream` | `[752280958]` |

**Body:** Raw PNG bytes as `ByteArrayContent`.

**Response handling:**
- Success: status code 2xx.
- Failure: logs `"status=<statusCode>"` via error channel (`[752280953]`).
- Timeout/cancellation: logs `"Screenshot upload canceled or timed out: "` (`[752280952]`).

### 5.3 Signature Verification

`ComputeScreenshotSignature(sharedSecret, steamId, requestId, issuedUnix, expiresUnix, reason, preferredMethod)`:
- Computes HMAC-SHA256 over the concatenation of all parameters.
- The shared secret is the key.
- Result is Base64URL-encoded.
- Comparison uses `FixedTimeEquals` to prevent timing attacks.

---

## 6. Heartbeat Mechanism

### Timer Setup

During `InitializeAsync`, after the `PlayerConnected` message is sent:

```csharp
_heartbeatTimer = new Timer(async (_) => {
    await SendHeartbeatAsync();
}, null, interval, interval);
```

The timer interval is determined by a static field (`_limitConfig802` / TimeSpan). The exact value is set in the static constructor and could not be fully resolved from the obfuscated code, but typical anti-cheat heartbeat intervals range from 15-60 seconds.

### Heartbeat Logic (`SendHeartbeatAsync`)

1. Check `_banReceived` -- if true, skip (no heartbeat after ban).
2. Check `_steamId` is not null/empty -- if empty, skip.
3. Send encrypted message:
   ```
   messageType: "Heartbeat"
   data: {"steamId": "<SteamID64>"}
   ```

### Teardown

On disconnect (`DisconnectAsync`):
1. Dispose `_heartbeatTimer`.
2. Set `_heartbeatTimer = null`.

---

## 7. HMAC Signature Computation

### Handshake Signatures

`ComputeHandshakeSignature(prefix, parts[])`:
```
message = prefix + "|" + parts[0] + "|" + parts[1] + "|" + ...
signature = Base64UrlEncode(HMAC-SHA256(masterSecret, UTF8(message)))
```

Where `masterSecret = UTF8.GetBytes(sharedSecret)`.

The shared secret is the static string `[752280812]`:
```
RSv1.HoNrj7uosYTypvYR58Zq4YJ3d5RtI8AqtnnjB6qG5YfH3WY9dpNE1Hx1hbv
```

### Handshake Signature Verification

`VerifyHandshakeSignature(prefix, signature, parts[])`:
1. Recomputes the signature the same way as `ComputeHandshakeSignature`.
2. Compares using `FixedTimeEquals` (constant-time string comparison).

### Screenshot Request Signatures

`ComputeScreenshotSignature(sharedSecret, steamId, requestId, issuedUnix, expiresUnix, reason, preferredMethod)`:
- Concatenates all parameters with a separator.
- Computes `HMAC-SHA256(UTF8(sharedSecret), UTF8(concatenated))`.
- Returns Base64URL-encoded result.

### Message Encryption Signatures (Protect/Unprotect)

Post-handshake messages use ChaCha20-Poly1305 AEAD:
- AAD: `sessionId + "|" + sendSeq + "|" + recvSeq` (UTF8 bytes) -- from `[752280612]` pipe separator.
- Key: 32-byte `_encKey` derived from ECDH.
- Nonce: derived from sequence number.
- Auth tag: 128-bit (16 bytes), appended to ciphertext.

---

## 8. Reconnection and Error Handling

### Reconnection

`ForceReconnectAsync` (`_003CForceReconnectAsync_003Ed__24`):
- Disposes the current WebSocket.
- Creates a new `ClientWebSocket`.
- Calls `EnsureConnectedAsync` which:
  1. Checks if socket state is `WebSocketState.Open`.
  2. If not, connects to `_serverUrl`.
  3. Performs a fresh ECDH handshake.
  4. Starts a new `ReceiveLoopAsync` in the background.

### Connection State

`LimitEnabled823` property checks if `_client.State == WebSocketState.Open`.

### Error Handling

- `"Socket is not connected"` (`[752280896]`) -- thrown when attempting to send on a closed connection.
- `"Secure session is not established"` (`[752281037]`) -- thrown when attempting encrypted send before handshake completes.
- `"Closing"` (`[752280951]`) -- logged during graceful disconnect.

---

## 9. Protocol Summary Diagram

```
Client (RustSecure Core DLL)              Server (rustsecure.ru)
    |                                          |
    |--- WSS Connect -----------------------> |
    |                                          |
    |--- ClientHello {pub, nonce, ts, sig} --> |
    |<-- ServerHello {pub, nonce, ts, sig} --- |
    |                                          |
    |   [ECDH key exchange completes]          |
    |   [Session key derived via HKDF]         |
    |   [All further messages encrypted]       |
    |                                          |
    |--- PlayerConnected {steamId, name, ----> |
    |        hwids}                            |
    |                                          |
    |--- Heartbeat {steamId} ----------------> |  (periodic timer)
    |--- Heartbeat {steamId} ----------------> |
    |                                          |
    |--- ThreatDetected {type, details} -----> |  (on detection)
    |                                          |
    |<-- RequestScreenshotV2|id|issued|... --- |
    |--- [HTTP PUT screenshot to /api/...] --> |  (separate HTTP)
    |                                          |
    |<-- RequestLocalAccounts|requestId ------- |
    |--- LocalAccountsCaptured {ids,...} -----> |
    |                                          |
    |<-- BanPlayer|steamId ------------------- |
    |   [sets _banReceived, stops heartbeat]   |
    |                                          |
    |--- PlayerDisconnected {steamId} -------> |
    |--- WSS Close -------------------------> |
```

---

## 10. Key Observations

1. **Shared secret is hardcoded**: The HMAC key `RSv1.HoNrj7uosYTypvYR58Zq4YJ3d5RtI8AqtnnjB6qG5YfH3WY9dpNE1Hx1hbv` is embedded in the binary. This means anyone with the binary can forge handshake signatures, though forward secrecy is provided by the ephemeral ECDH exchange.

2. **Forward secrecy**: Despite the static shared secret, the X25519 ECDH exchange provides forward secrecy for session encryption. Compromising the shared secret does not retroactively decrypt captured sessions.

3. **Sequence numbers prevent replay**: Both `_sendSeq` and `_recvSeq` are included in the AEAD AAD, preventing message replay and reordering.

4. **Screenshot signatures are tied to request parameters**: The HMAC covers `steamId`, `requestId`, timestamps, reason, and method -- preventing forged screenshot requests.

5. **Deduplication**: `IsDuplicateThreat` suppresses repeat threat reports within a time window, reducing server load.

6. **Ban is one-way**: Once `_banReceived` is set, heartbeats stop and the flag is volatile (thread-safe). The ban message `"Banned by RustSecure."` is the only reason ever sent to the game client.

7. **HTTP upload is separate from WebSocket**: Screenshots are uploaded via a standard HTTP PUT/POST with custom `X-RS-*` headers, not through the WebSocket channel. This avoids sending large binary payloads over the encrypted WebSocket.

8. **User-Agent header**: `[752280945]` references `User-Agent`, suggesting the WebSocket or HTTP client sets a custom User-Agent string.
