// crypto_bridge.cs — stdin/stdout bridge to Core DLL's crypto
// Python sends commands, C# processes them using real Core crypto.
// Compile: mcs -unsafe crypto_bridge.cs -out:crypto_bridge.exe
// Usage: echo "DERIVE <shared_hex> <cn_hex> <sn_hex>" | mono crypto_bridge.exe

using System;
using System.IO;
using System.Reflection;
using System.Text;

class Bridge {
    static Type ct;
    static object inst;
    static MethodInfo genPriv, derivePub, genShared, configSession, protect, tryUnprotect, computeSig;
    static BindingFlags bf = BindingFlags.Public|BindingFlags.NonPublic|BindingFlags.Instance|BindingFlags.Static;

    static byte[] Hex(string s) { byte[] b=new byte[s.Length/2]; for(int i=0;i<b.Length;i++) b[i]=Convert.ToByte(s.Substring(i*2,2),16); return b; }
    static string ToHex(byte[] b) => BitConverter.ToString(b).Replace("-","").ToLower();

    static void Main() {
        var asm = Assembly.LoadFrom(Path.Combine(Path.GetDirectoryName(
            Assembly.GetExecutingAssembly().Location),"..", "decrypted", "core_decrypted.dll"));
        foreach (var t in asm.GetTypes()) {
            bool a=false,b=false;
            foreach (var m in t.GetMethods(bf)) { if(m.Name=="HkdfExpand")a=true; if(m.Name=="ConfigureSessionFromEcdh")b=true; }
            if(a&&b){ct=t;break;}
        }
        inst = ct.GetConstructors(bf)[0].Invoke(new object[]{
            "RSv1.HoNrj7uosYTypvYR58Zq4YJ3d5RtI8AqtnnjB6qG5YfH3WY9dpNE1Hx1hbv"});
        genPriv = ct.GetMethod("GenerateEphemeralPrivateKey",bf);
        derivePub = ct.GetMethod("DerivePublicKey",bf);
        genShared = ct.GetMethod("GenerateSharedSecret",bf);
        configSession = ct.GetMethod("ConfigureSessionFromEcdh",bf);
        protect = ct.GetMethod("Protect",bf);
        tryUnprotect = ct.GetMethod("TryUnprotect",bf);
        computeSig = ct.GetMethod("ComputeHandshakeSignature",bf);

        Console.Error.WriteLine("READY");
        string line;
        while ((line = Console.ReadLine()) != null) {
            try {
                var parts = line.Trim().Split(' ');
                switch(parts[0]) {
                    case "GENKEY": {
                        byte[] priv = (byte[])genPriv.Invoke(inst,null);
                        byte[] pub = (byte[])derivePub.Invoke(inst,new object[]{priv});
                        Console.WriteLine("KEY " + ToHex(priv) + " " + ToHex(pub));
                        break;
                    }
                    case "ECDH": { // ECDH <priv_hex> <peer_pub_hex>
                        byte[] sh = (byte[])genShared.Invoke(inst,new object[]{Hex(parts[1]),Hex(parts[2])});
                        Console.WriteLine("SHARED " + ToHex(sh));
                        break;
                    }
                    case "DERIVE": { // DERIVE <shared_hex> <cn_hex> <sn_hex>
                        inst = ct.GetConstructors(bf)[0].Invoke(new object[]{
                            "RSv1.HoNrj7uosYTypvYR58Zq4YJ3d5RtI8AqtnnjB6qG5YfH3WY9dpNE1Hx1hbv"});
                        configSession.Invoke(inst,new object[]{Hex(parts[1]),Hex(parts[2]),Hex(parts[3])});
                        byte[] ek = (byte[])ct.GetField("_encKey",bf).GetValue(inst);
                        string sid = (string)ct.GetField("_sessionId",bf).GetValue(inst);
                        Console.WriteLine("SESSION " + ToHex(ek) + " " + sid);
                        break;
                    }
                    case "PROTECT": { // PROTECT <plaintext>
                        string enc = (string)protect.Invoke(inst,new object[]{string.Join(" ",parts,1,parts.Length-1)});
                        Console.WriteLine("ENC " + enc);
                        break;
                    }
                    case "UNPROTECT": { // UNPROTECT <envelope>
                        object[] args = new object[]{parts[1], null};
                        bool ok = (bool)tryUnprotect.Invoke(inst, args);
                        Console.WriteLine(ok ? "DEC " + (string)args[1] : "FAIL");
                        break;
                    }
                    case "SIG": { // SIG <prefix> <part1> <part2> ...
                        string[] sigParts = new string[parts.Length-2];
                        Array.Copy(parts,2,sigParts,0,sigParts.Length);
                        string sig = (string)computeSig.Invoke(inst,new object[]{parts[1],sigParts});
                        Console.WriteLine("SIG " + sig);
                        break;
                    }
                    default: Console.WriteLine("ERR unknown command"); break;
                }
            } catch (Exception ex) {
                Console.WriteLine("ERR " + (ex.InnerException??ex).Message);
            }
            Console.Out.Flush();
        }
    }
}
