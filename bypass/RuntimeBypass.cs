// RuntimeBypass.cs — In-memory bypass for RustSecure.Core.dll
// Loads alongside Core DLL via the same CLR bridge (native_decrypted.dll).
// Hooks AppDomain.AssemblyLoad to intercept Core loading, then patches
// detection methods in memory via JIT hook (MethodHandle swap).
//
// Compile: mcs -unsafe -target:library RuntimeBypass.cs -out:RuntimeBypass.dll
// Deploy: modify native bridge to load this DLL before Core, or inject separately.

using System;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

public static class RuntimeBypass
{
    // Target methods to neutralize (class substring -> method name)
    static readonly string[][] Targets = new string[][] {
        new[] { "Entry",                       "Init" },
        new[] { "SetFrameRateMediator",        "Start" },
        new[] { "DetectionManager",            "Initialize" },
        new[] { "DetectionManager",            "PublishDetection" },
        new[] { "RuntimeSecurityMonitor",      "Start" },
        new[] { "RuntimeSecurityMonitor",      "HandleThreat" },
        new[] { "SynchronizeFrameUpdate",      "ReportThreatAsync" },
        new[] { "SynchronizeFrameUpdate",      "InitializeAsync" },
    };

    static bool _initialized = false;

    // Call this from your loader before Core's Entry.Init() runs
    [DllExport("BypassInit", CallingConvention = CallingConvention.StdCall)]
    public static void BypassInit()
    {
        if (_initialized) return;
        _initialized = true;

        AppDomain.CurrentDomain.AssemblyLoad += OnAssemblyLoad;

        // If Core is already loaded, patch immediately
        foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
        {
            if (asm.GetName().Name == "RustSecure.Core")
            {
                PatchAssembly(asm);
                break;
            }
        }
    }

    static void OnAssemblyLoad(object sender, AssemblyLoadEventArgs args)
    {
        if (args.LoadedAssembly.GetName().Name == "RustSecure.Core")
        {
            PatchAssembly(args.LoadedAssembly);
        }
    }

    static void PatchAssembly(Assembly asm)
    {
        int patched = 0;
        foreach (var target in Targets)
        {
            string classHint = target[0];
            string methodName = target[1];

            foreach (var type in asm.GetTypes())
            {
                if (!type.Name.Contains(classHint) && !type.FullName.Contains(classHint))
                    continue;

                var methods = type.GetMethods(
                    BindingFlags.Public | BindingFlags.NonPublic |
                    BindingFlags.Static | BindingFlags.Instance);

                foreach (var method in methods)
                {
                    if (method.Name != methodName) continue;

                    try
                    {
                        // Find or create a replacement stub
                        MethodInfo stub = GetStub(method.ReturnType);
                        if (stub == null) continue;

                        // JIT both methods to get native code pointers
                        RuntimeHelpers.PrepareMethod(method.MethodHandle);
                        RuntimeHelpers.PrepareMethod(stub.MethodHandle);

                        // Swap the method pointer
                        SwapMethodBody(method, stub);
                        patched++;
                    }
                    catch { }
                }
            }
        }
    }

    static MethodInfo GetStub(Type returnType)
    {
        if (returnType == typeof(void))
            return typeof(Stubs).GetMethod("VoidStub",
                BindingFlags.Public | BindingFlags.Static);

        if (returnType == typeof(System.Threading.Tasks.Task))
            return typeof(Stubs).GetMethod("TaskStub",
                BindingFlags.Public | BindingFlags.Static);

        if (returnType == typeof(bool))
            return typeof(Stubs).GetMethod("BoolStub",
                BindingFlags.Public | BindingFlags.Static);

        return typeof(Stubs).GetMethod("NullStub",
            BindingFlags.Public | BindingFlags.Static);
    }

    static unsafe void SwapMethodBody(MethodInfo original, MethodInfo replacement)
    {
        // Get function pointers from method handles
        IntPtr origPtr = original.MethodHandle.GetFunctionPointer();
        IntPtr replPtr = replacement.MethodHandle.GetFunctionPointer();

        // Write a JMP from original to replacement (x64)
        // 0xFF 0x25 0x00000000 [8-byte absolute address]
        byte* p = (byte*)origPtr;

        // Make memory writable
        VirtualProtect(origPtr, (UIntPtr)14, 0x40, out uint oldProtect);

        // Write: jmp [rip+0] ; dq replPtr
        p[0] = 0xFF;
        p[1] = 0x25;
        *(int*)(p + 2) = 0; // RIP-relative offset = 0
        *(long*)(p + 6) = (long)replPtr;

        // Restore protection
        VirtualProtect(origPtr, (UIntPtr)14, oldProtect, out _);
    }

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);
}

// Stub methods — these replace the original detection methods
public static class Stubs
{
    public static void VoidStub() { }

    public static System.Threading.Tasks.Task TaskStub()
    {
        return System.Threading.Tasks.Task.CompletedTask;
    }

    public static bool BoolStub()
    {
        return false;
    }

    public static object NullStub()
    {
        return null;
    }
}
