using System;
using System.IO;
using System.Reflection;

class DownloadDecrypt
{
    static void Main()
    {
        var asm = Assembly.LoadFrom("RustSecure_patched.exe");
        var strType = asm.GetType("aubDoAbSXgGwxT.AykNWbWxBoNpvcDU");
        System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(strType.TypeHandle);

        var loaderType = asm.GetType(
            "InspectFrameBufferListener.NormalizeFrameRateSubscriber.getAceTypeVARFLAGFSOURCE.MyVideosDNN.SynchronizeFrameUpdateValidator");
        System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(loaderType.TypeHandle);

        // DownloadAndDecryptPayload(string endpoint, string path) -> byte[]
        MethodInfo dlMethod = null;
        foreach (var m in loaderType.GetMethods(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public)) {
            var ps = m.GetParameters();
            if (ps.Length == 2 && ps[0].ParameterType == typeof(string) && ps[1].ParameterType == typeof(string)
                && m.ReturnType == typeof(byte[]))
            { dlMethod = m; Console.Error.WriteLine("Found: " + m.Name); break; }
        }
        if (dlMethod == null) { Console.Error.WriteLine("Not found"); return; }

        string[][] targets = {
            new[]{"https://rustsecure.ru/api/loader/core", "/api/loader/core", "core_decrypted.dll"},
            new[]{"https://rustsecure.ru/api/loader/native", "/api/loader/native", "native_decrypted.dll"},
        };

        foreach (var t in targets)
        {
            Console.Error.WriteLine("\n=== Downloading " + t[0] + " ===");
            try {
                byte[] result = (byte[])dlMethod.Invoke(null, new object[]{t[0], t[1]});
                if (result != null && result.Length > 0) {
                    File.WriteAllBytes(t[2], result);
                    Console.WriteLine(t[2] + ": " + result.Length + " bytes");
                    Console.WriteLine("  Head: " + BitConverter.ToString(result, 0, Math.Min(32, result.Length)));
                } else {
                    Console.Error.WriteLine("  returned null/empty");
                }
            } catch (Exception ex) {
                var e = ex; while(e!=null){Console.Error.WriteLine(e.GetType().Name+": "+e.Message); e=e.InnerException;}
            }
        }
    }
}
