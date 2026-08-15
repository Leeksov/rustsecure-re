using System;
using System.IO;
using System.Reflection;
using System.Collections.Generic;

class CoreStringDecryptor
{
    static void Main()
    {
        try
        {
            var asm = Assembly.LoadFrom("../core_decrypted.dll");
            Console.Error.WriteLine("Assembly loaded: " + asm.FullName);

            var strType = asm.GetType("cTQsFfpIsQpYGt.goLRktYZPMUxZogV");
            if (strType == null) {
                // Try to find it by scanning
                foreach (var t in asm.GetTypes()) {
                    if (t.Name == "goLRktYZPMUxZogV" || t.Name.Contains("goLRktYZ")) {
                        strType = t; break;
                    }
                }
            }
            if (strType == null) { Console.Error.WriteLine("String type not found"); return; }
            Console.Error.WriteLine("Found type: " + strType.FullName);

            System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(strType.TypeHandle);

            var method = strType.GetMethod("JLKedGIqgARc", BindingFlags.Public | BindingFlags.Static);
            if (method == null) { Console.Error.WriteLine("Method not found"); return; }
            Console.Error.WriteLine("Method found");

            // All known integer arguments from the analysis
            int[] knownIds = {
                752280612, 752280674, 752280704, 752280739, 752280771, 752280773,
                752280777, 752280780, 752280781, 752280809, 752280812, 752280813,
                752280830, 752280864, 752280866, 752280867, 752280889, 752280892,
                752280893, 752280894, 752280895, 752280896, 752280911,
                752280932, 752280935, 752280936, 752280937, 752280939, 752280942,
                752280957, 752280964, 752280968, 752280971, 752280972, 752280973
            };

            // Also try a range scan around the known values
            var results = new SortedDictionary<int, string>();

            // First: known IDs
            foreach (var id in knownIds) {
                try {
                    var r = (string)method.Invoke(null, new object[] { id });
                    if (r != null) results[id] = r;
                } catch { }
            }

            // Range scan: 752280600 to 752281400
            for (int id = 752280600; id <= 752281400; id++) {
                if (results.ContainsKey(id)) continue;
                try {
                    var r = (string)method.Invoke(null, new object[] { id });
                    if (r != null) results[id] = r;
                } catch { }
            }

            Console.Error.WriteLine("Decrypted: " + results.Count + " strings");
            foreach (var kv in results) {
                Console.WriteLine("[{0}] {1}", kv.Key, kv.Value);
            }
        }
        catch (Exception ex) {
            var e = ex;
            while (e != null) { Console.Error.WriteLine(e.GetType().Name + ": " + e.Message); e = e.InnerException; }
        }
    }
}
