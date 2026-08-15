// ws_proxy.cs - Mono-based WebSocket proxy that uses Core DLL's actual crypto
// Compile: mcs -unsafe ws_proxy.cs -r:System.Net.Http.dll -out:ws_proxy.exe
// Run: mono ws_proxy.exe <steamid>

using System;
using System.IO;
using System.Net.WebSockets;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

class WsProxy
{
    static Type _cryptoType;
    static object _cryptoInst;
    static MethodInfo _protect, _tryUnprotect, _genPriv, _derivePub, _genShared, _configSession;
    static MethodInfo _computeHandshakeSig, _verifyHandshakeSig;

    static void Main(string[] args)
    {
        string steamId = args.Length > 0 ? args[0] : "76561198012345678";
        string uploadImage = args.Length > 1 ? args[1] : null;

        var asm = Assembly.LoadFrom("../decrypted/core_decrypted.dll");
        foreach (var t in asm.GetTypes())
        {
            var ms = t.GetMethods(BindingFlags.Public | BindingFlags.Instance);
            bool a = false, b = false;
            foreach (var m in ms) { if (m.Name == "Protect") a = true; if (m.Name == "ConfigureSessionFromEcdh") b = true; }
            if (a && b) { _cryptoType = t; break; }
        }

        _cryptoInst = _cryptoType.GetConstructors()[0].Invoke(new object[] {
            "RSv1.HoNrj7uosYTypvYR58Zq4YJ3d5RtI8AqtnnjB6qG5YfH3WY9dpNE1Hx1hbv"
        });

        _protect = _cryptoType.GetMethod("Protect");
        _tryUnprotect = _cryptoType.GetMethod("TryUnprotect");
        _genPriv = _cryptoType.GetMethod("GenerateEphemeralPrivateKey");
        _derivePub = _cryptoType.GetMethod("DerivePublicKey");
        _genShared = _cryptoType.GetMethod("GenerateSharedSecret");
        _configSession = _cryptoType.GetMethod("ConfigureSessionFromEcdh");
        _computeHandshakeSig = _cryptoType.GetMethod("ComputeHandshakeSignature",
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
        _verifyHandshakeSig = _cryptoType.GetMethod("VerifyHandshakeSignature",
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);

        Console.Error.WriteLine("[+] Crypto type: " + _cryptoType.Name);
        Console.Error.WriteLine("[+] Methods loaded: Protect=" + (_protect != null) +
            " GenPriv=" + (_genPriv != null) + " ComputeSig=" + (_computeHandshakeSig != null));

        RunAsync(steamId, uploadImage).GetAwaiter().GetResult();
    }

    static string B64Url(byte[] d) => Convert.ToBase64String(d).Replace("+", "-").Replace("/", "_").TrimEnd('=');
    static byte[] B64UrlDec(string s) { s = s.Replace("-","+").Replace("_","/"); switch(s.Length%4){case 2:s+="==";break;case 3:s+="=";break;} return Convert.FromBase64String(s); }

    static async Task RunAsync(string steamId, string uploadImage)
    {
        var ws = new ClientWebSocket();
        Console.Error.WriteLine("[*] Connecting to wss://rustsecure.ru/ws ...");
        await ws.ConnectAsync(new Uri("wss://rustsecure.ru/ws"), CancellationToken.None);
        Console.Error.WriteLine("[+] Connected");

        // ECDH handshake using Core DLL's actual crypto
        byte[] clientPrivate = (byte[])_genPriv.Invoke(_cryptoInst, null);
        byte[] clientPublic = (byte[])_derivePub.Invoke(_cryptoInst, new object[] { clientPrivate });
        byte[] clientNonce = new byte[16];
        new Random().NextBytes(clientNonce);
        long ts = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        string cpub = B64Url(clientPublic);
        string cnonce = B64Url(clientNonce);

        // Compute signature using Core DLL's method
        string sig;
        if (_computeHandshakeSig != null)
        {
            sig = (string)_computeHandshakeSig.Invoke(_cryptoInst, new object[] {
                "client-hello", new string[] { cpub, cnonce, ts.ToString() }
            });
        }
        else
        {
            // Fallback manual
            using (var hm = new System.Security.Cryptography.HMACSHA256(
                Encoding.UTF8.GetBytes("RSv1.HoNrj7uosYTypvYR58Zq4YJ3d5RtI8AqtnnjB6qG5YfH3WY9dpNE1Hx1hbv")))
            {
                byte[] sigBytes = hm.ComputeHash(Encoding.UTF8.GetBytes(
                    "client-hello|" + cpub + "|" + cnonce + "|" + ts));
                sig = B64Url(sigBytes);
            }
        }

        string hello = "{\"type\":\"ClientHello\",\"pub\":\"" + cpub + "\",\"nonce\":\"" + cnonce +
            "\",\"ts\":" + ts + ",\"sig\":\"" + sig + "\"}";
        Console.Error.WriteLine("[>] ClientHello sent");
        await SendText(ws, hello);

        string response = await RecvText(ws);
        Console.Error.WriteLine("[<] " + response.Substring(0, Math.Min(100, response.Length)));

        // Parse ServerHello
        // Simple JSON parsing (no dependency)
        string serverPub = ExtractJson(response, "pub");
        string serverNonce = ExtractJson(response, "nonce");

        byte[] spubBytes = B64UrlDec(serverPub);
        byte[] snonceBytes = B64UrlDec(serverNonce);

        // ECDH shared secret
        byte[] shared = (byte[])_genShared.Invoke(_cryptoInst, new object[] { clientPrivate, spubBytes });
        Console.Error.WriteLine("[+] ECDH shared secret: " + shared.Length + " bytes");

        // Configure session
        _configSession.Invoke(_cryptoInst, new object[] { shared, clientNonce, snonceBytes });
        Console.Error.WriteLine("[+] Session configured!");

        // Test: encrypt a message
        string testEnc = (string)_protect.Invoke(_cryptoInst, new object[] { "test" });
        Console.Error.WriteLine("[+] Protect('test') = " + testEnc.Substring(0, Math.Min(60, testEnc.Length)) + "...");

        // Send PlayerConnected
        string pcMsg = "{\"type\":\"PlayerConnected\",\"steamId\":\"" + steamId +
            "\",\"playerName\":\"Player\",\"hwids\":{}}";
        string encrypted = (string)_protect.Invoke(_cryptoInst, new object[] { pcMsg });
        await SendText(ws, encrypted);
        Console.Error.WriteLine("[>] PlayerConnected (encrypted)");

        // Listen for commands
        Console.Error.WriteLine("[*] Listening for server commands...");
        while (ws.State == WebSocketState.Open)
        {
            try
            {
                string msg = await RecvTextTimeout(ws, 60000);
                if (msg == null) {
                    // Send heartbeat
                    string hb = (string)_protect.Invoke(_cryptoInst, new object[] {
                        "{\"type\":\"Heartbeat\",\"steamId\":\"" + steamId + "\"}" });
                    await SendText(ws, hb);
                    Console.Error.WriteLine("[>] Heartbeat");
                    continue;
                }

                // Try to decrypt
                string decrypted = null;
                object[] unprotArgs = new object[] { msg, null };
                bool ok = (bool)_tryUnprotect.Invoke(_cryptoInst, unprotArgs);
                if (ok) decrypted = (string)unprotArgs[1];

                if (decrypted != null)
                {
                    Console.WriteLine("[CMD] " + decrypted);

                    if (decrypted.Contains("RequestScreenshotV2"))
                    {
                        string[] parts = decrypted.Split('|');
                        Console.WriteLine("\n!!! SCREENSHOT REQUEST !!!");
                        Console.WriteLine("  RequestId: " + (parts.Length > 1 ? parts[1] : "?"));
                        Console.WriteLine("  Signature: " + (parts.Length > 5 ? parts[5] : "?"));

                        if (parts.Length > 5)
                        {
                            // Upload!
                            Console.WriteLine("  Uploading fake screenshot...");
                            // Use curl since we don't have HttpClient easily
                            var psi = new System.Diagnostics.ProcessStartInfo("curl", 
                                "-s -X POST " +
                                "\"https://rustsecure.ru/api/ingest/screenshot?method=dxgi&width=1920&height=1080&affinity=0\" " +
                                "-H \"X-RS-SteamId: " + steamId + "\" " +
                                "-H \"X-RS-RequestId: " + parts[1] + "\" " +
                                "-H \"X-RS-RequestSig: " + parts[5] + "\" " +
                                "-H \"Content-Type: application/octet-stream\" " +
                                "--data-binary @" + (uploadImage ?? "/dev/null"));
                            psi.RedirectStandardOutput = true;
                            var p = System.Diagnostics.Process.Start(psi);
                            Console.WriteLine("  Upload: " + p.StandardOutput.ReadToEnd());
                        }
                    }
                    else if (decrypted.Contains("BanPlayer"))
                        Console.WriteLine("!!! BAN: " + decrypted);
                }
                else
                    Console.Error.WriteLine("[<] (undecryptable) " + msg.Substring(0, Math.Min(50, msg.Length)));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[!] " + ex.Message);
                break;
            }
        }
    }

    static string ExtractJson(string json, string key)
    {
        int i = json.IndexOf("\"" + key + "\"");
        if (i < 0) return null;
        i = json.IndexOf(":", i) + 1;
        while (i < json.Length && (json[i] == ' ' || json[i] == '"')) i++;
        int j = i;
        bool inStr = json[i-1] == '"';
        if (inStr) { j = json.IndexOf("\"", i); return json.Substring(i, j - i); }
        while (j < json.Length && json[j] != ',' && json[j] != '}') j++;
        return json.Substring(i, j - i).Trim();
    }

    static async Task SendText(ClientWebSocket ws, string text)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        await ws.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, CancellationToken.None);
    }

    static async Task<string> RecvText(ClientWebSocket ws)
    {
        var buf = new byte[65536];
        var result = await ws.ReceiveAsync(new ArraySegment<byte>(buf), CancellationToken.None);
        return Encoding.UTF8.GetString(buf, 0, result.Count);
    }

    static async Task<string> RecvTextTimeout(ClientWebSocket ws, int ms)
    {
        var cts = new CancellationTokenSource(ms);
        try
        {
            var buf = new byte[65536];
            var result = await ws.ReceiveAsync(new ArraySegment<byte>(buf), cts.Token);
            return Encoding.UTF8.GetString(buf, 0, result.Count);
        }
        catch (OperationCanceledException) { return null; }
    }
}
