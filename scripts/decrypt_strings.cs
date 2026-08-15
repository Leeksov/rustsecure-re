// Compile with: mcs -unsafe decrypt_strings.cs
// Run with: mono decrypt_strings.exe
using System;
using System.Reflection;

class Decryptor
{
    static void Main()
    {
        try
        {
            string path = "../samples/RustSecure.exe";
            var asm = Assembly.LoadFrom(path);

            var type = asm.GetType("aubDoAbSXgGwxT.AykNWbWxBoNpvcDU");
            if (type == null) { Console.WriteLine("ERROR: Type not found"); return; }

            var method = type.GetMethod("awhuBmgthIGH",
                BindingFlags.Public | BindingFlags.Static);
            if (method == null) { Console.WriteLine("ERROR: Method not found"); return; }

            Console.WriteLine("=== Decrypting strings via reflection ===");
            for (int i = 0; i < 347; i++)
            {
                try
                {
                    var result = method.Invoke(null, new object[] { i });
                    Console.WriteLine("[{0,3}] {1}", i, result);
                }
                catch (TargetInvocationException ex)
                {
                    var inner = ex.InnerException;
                    Console.Error.WriteLine("[{0,3}] ERR: {1}: {2}", i,
                        inner.GetType().Name, inner.Message);
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("[{0,3}] ERR: {1}", i, ex.Message);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("FATAL: " + ex);
        }
    }
}
