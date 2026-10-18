using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Siegel.Core.Native;

/// <summary>
/// Eigene dünne P/Invoke-Bindung des Kerns an libsodium 1.0.22 (NuGet „libsodium“, SPEC-WINDOWS W1/W2).
/// Nur die Funktionen, die der Kern braucht; Zeiger roh (die Aufrufer pinnen bzw. halten SecureBuffer-Leihen).
/// cdecl ausdrücklich, damit auch x86-Windows stimmt.
/// </summary>
internal static unsafe partial class Libsodium
{
    private const string Lib = "libsodium";

    /// <summary>crypto_pwhash_ALG_ARGON2ID13 (libsodium-Konstante 2).</summary>
    internal const int Argon2id13 = 2;

    private static readonly bool Ready = Init();

    /// <summary>Fehlt die native Bibliothek (Paketierungsfehler), bleibt es bei einem festen Code statt einer fremden
    /// Ausnahme mit Pfaden im Text.</summary>
    private static bool Init()
    {
        try
        {
            return sodium_init() >= 0;
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            return false;
        }
    }

    /// <summary>Vor jeder Krypto aufrufen. Scheitert sodium_init, gibt es nur einen festen Code (SPEC §1).</summary>
    internal static void EnsureReady()
    {
        if (!Ready) { throw new Siegel.Modell.SiegelException(Siegel.Modell.SiegelErrorCode.Crypto, "sodium.init"); }
    }

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    private static partial int sodium_init();

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial IntPtr sodium_version_string();

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_pwhash_alg_argon2id13();

    // Geschützter Speicher

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial IntPtr sodium_malloc(nuint size);

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void sodium_free(IntPtr ptr);

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int sodium_mprotect_readonly(IntPtr ptr);

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int sodium_mprotect_readwrite(IntPtr ptr);

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void sodium_memzero(byte* pnt, nuint len);

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int sodium_memcmp(byte* b1, byte* b2, nuint len);

    // Zufall

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial void randombytes_buf(byte* buf, nuint size);

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial uint randombytes_uniform(uint upperBound);

    // Argon2id

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_pwhash(byte* output, ulong outlen, byte* passwd, ulong passwdlen, byte* salt,
        ulong opslimit, nuint memlimit, int alg);

    // XChaCha20-Poly1305 (IETF)

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_aead_xchacha20poly1305_ietf_encrypt(byte* c, ulong* clen, byte* m, ulong mlen,
        byte* ad, ulong adlen, byte* nsec, byte* npub, byte* k);

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_aead_xchacha20poly1305_ietf_decrypt(byte* m, ulong* mlen, byte* nsec, byte* c,
        ulong clen, byte* ad, ulong adlen, byte* npub, byte* k);

    // Polsterung

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int sodium_pad(nuint* paddedBuflenP, byte* buf, nuint unpaddedBuflen, nuint blocksize,
        nuint maxBuflen);

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int sodium_unpad(nuint* unpaddedBuflenP, byte* buf, nuint paddedBuflen, nuint blocksize);

    // X25519

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_scalarmult_base(byte* q, byte* n);

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_scalarmult(byte* q, byte* n, byte* p);

    // BLAKE2b (Master-Tag §1.6, reuseTag §17)

    [LibraryImport(Lib)]
    [UnmanagedCallConv(CallConvs = [typeof(CallConvCdecl)])]
    internal static partial int crypto_generichash(byte* output, nuint outlen, byte* input, ulong inlen, byte* key,
        nuint keylen);
}
