using System.Runtime.InteropServices;
using Siegel.Modell;

namespace Siegel.Werkzeuge;

/// <summary>Dünne P/Invoke-Bindung an libsodium 1.0.22 (NuGet „libsodium“). Initialisiert genau einmal.</summary>
internal static unsafe partial class Sodium
{
    private const string Lib = "libsodium";

    private static readonly bool ready = sodium_init() >= 0;

    /// <summary>Vor jeder Krypto aufrufen; wirft, wenn libsodium nicht startet.</summary>
    internal static void EnsureReady()
    {
        if (!ready) { throw new SiegelException(SiegelErrorCode.Crypto, "sodium.init"); }
    }

    [LibraryImport(Lib)] private static partial int sodium_init();
    [LibraryImport(Lib)] internal static partial IntPtr sodium_version_string();

    // Zufall
    [LibraryImport(Lib)] internal static partial uint randombytes_uniform(uint upperBound);
    [LibraryImport(Lib)] internal static partial void randombytes_buf(byte* buffer, nuint size);

    // Geschützter Speicher
    [LibraryImport(Lib)] internal static partial IntPtr sodium_malloc(nuint size);
    [LibraryImport(Lib)] internal static partial void sodium_free(IntPtr pointer);
    [LibraryImport(Lib)] internal static partial int sodium_mprotect_readonly(IntPtr pointer);
    [LibraryImport(Lib)] internal static partial int sodium_mprotect_readwrite(IntPtr pointer);
    [LibraryImport(Lib)] internal static partial void sodium_memzero(byte* pointer, nuint length);
    [LibraryImport(Lib)] internal static partial int sodium_memcmp(byte* a, byte* b, nuint length);

    // Argon2id
    [LibraryImport(Lib)]
    internal static partial int crypto_pwhash(byte* output, ulong outputLength, byte* password, ulong passwordLength,
        byte* salt, ulong opsLimit, nuint memLimit, int algorithm);
    [LibraryImport(Lib)] internal static partial int crypto_pwhash_alg_argon2id13();
    [LibraryImport(Lib)] internal static partial nuint crypto_pwhash_argon2id_saltbytes();

    // ChaCha20 (RFC 7539)
    [LibraryImport(Lib)]
    internal static partial int crypto_stream_chacha20_ietf_xor(byte* output, byte* input, ulong length, byte* nonce,
        byte* key);
    [LibraryImport(Lib)]
    internal static partial int crypto_stream_chacha20_ietf_xor_ic(byte* output, byte* input, ulong length, byte* nonce,
        uint counter, byte* key);
    [LibraryImport(Lib)]
    internal static partial int crypto_stream_chacha20_ietf(byte* output, ulong length, byte* nonce, byte* key);

    // SHA-256, SHA-512, HMAC-SHA-256 (Zustände liegen beim Aufrufer in sodium_malloc-Speicher)
    [LibraryImport(Lib)] internal static partial nuint crypto_hash_sha256_statebytes();
    [LibraryImport(Lib)] internal static partial int crypto_hash_sha256_init(byte* state);
    [LibraryImport(Lib)] internal static partial int crypto_hash_sha256_update(byte* state, byte* input, ulong length);
    [LibraryImport(Lib)] internal static partial int crypto_hash_sha256_final(byte* state, byte* output);
    [LibraryImport(Lib)] internal static partial nuint crypto_hash_sha512_statebytes();
    [LibraryImport(Lib)] internal static partial int crypto_hash_sha512_init(byte* state);
    [LibraryImport(Lib)] internal static partial int crypto_hash_sha512_update(byte* state, byte* input, ulong length);
    [LibraryImport(Lib)] internal static partial int crypto_hash_sha512_final(byte* state, byte* output);
    [LibraryImport(Lib)] internal static partial nuint crypto_auth_hmacsha256_statebytes();
    [LibraryImport(Lib)] internal static partial int crypto_auth_hmacsha256_init(byte* state, byte* key, nuint keyLength);
    [LibraryImport(Lib)] internal static partial int crypto_auth_hmacsha256_update(byte* state, byte* input, ulong length);
    [LibraryImport(Lib)] internal static partial int crypto_auth_hmacsha256_final(byte* state, byte* output);

    /// <summary>Gleichverteilte Zahl in 0..&lt;obergrenze (ohne Modulo-Verzerrung).</summary>
    internal static uint Uniform(uint upperBound)
    {
        EnsureReady();
        return randombytes_uniform(upperBound);
    }

    /// <summary>Zufallsbytes für nicht geheime Werte (Nonces, Salze, Kennungen).</summary>
    internal static byte[] RandomBytes(int count)
    {
        EnsureReady();
        var result = new byte[count];
        if (count > 0)
        {
            fixed (byte* p = result) { randombytes_buf(p, (nuint)count); }
        }
        return result;
    }

    /// <summary>Best effort: verwalteten Puffer nullen.</summary>
    internal static void Wipe(Span<byte> buffer)
    {
        if (buffer.IsEmpty) { return; }
        fixed (byte* p = buffer) { sodium_memzero(p, (nuint)buffer.Length); }
    }
}
