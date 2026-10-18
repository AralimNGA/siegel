using Siegel.Modell;

namespace Siegel.Werkzeuge;

/// <summary>SHA-256, SHA-512 und HMAC-SHA-256 über libsodium; Zustände und Ausgaben in sodium_malloc-Speicher.</summary>
internal static unsafe class SodiumHash
{
    internal static Geheimpuffer Sha256(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b = default)
    {
        Sodium.EnsureReady();
        using var state = Geheimpuffer.Rechenflaeche((int)Sodium.crypto_hash_sha256_statebytes());
        using var zustand = state.Schreiben();
        var s = zustand.Zeiger;
        _ = Sodium.crypto_hash_sha256_init(s);
        Update256(s, a);
        Update256(s, b);
        return Geheimpuffer.Neu(32, ziel =>
        {
            fixed (byte* o = ziel)
            {
                if (Sodium.crypto_hash_sha256_final(s, o) != 0) { throw new SiegelException(SiegelErrorCode.Crypto, "kdbx.hash"); }
            }
        });
    }

    internal static Geheimpuffer Sha512(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b = default, ReadOnlySpan<byte> c = default)
    {
        Sodium.EnsureReady();
        using var state = Geheimpuffer.Rechenflaeche((int)Sodium.crypto_hash_sha512_statebytes());
        using var zustand = state.Schreiben();
        var s = zustand.Zeiger;
        _ = Sodium.crypto_hash_sha512_init(s);
        Update512(s, a);
        Update512(s, b);
        Update512(s, c);
        return Geheimpuffer.Neu(64, ziel =>
        {
            fixed (byte* o = ziel)
            {
                if (Sodium.crypto_hash_sha512_final(s, o) != 0) { throw new SiegelException(SiegelErrorCode.Crypto, "kdbx.hash"); }
            }
        });
    }

    /// <summary>HMAC-SHA-256 (öffentliche Ausgabe, z. B. Block-Prüfwerte).</summary>
    internal static byte[] HmacSha256(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
    {
        Sodium.EnsureReady();
        using var state = Geheimpuffer.Rechenflaeche((int)Sodium.crypto_auth_hmacsha256_statebytes());
        using var zustand = state.Schreiben();
        var s = zustand.Zeiger;
        var mac = new byte[32];
        fixed (byte* k = key)
        fixed (byte* m = message)
        fixed (byte* o = mac)
        {
            if (Sodium.crypto_auth_hmacsha256_init(s, k, (nuint)key.Length) != 0
                || (message.Length > 0 && Sodium.crypto_auth_hmacsha256_update(s, m, (ulong)message.Length) != 0)
                || Sodium.crypto_auth_hmacsha256_final(s, o) != 0)
            {
                throw new SiegelException(SiegelErrorCode.Crypto, "kdbx.hmac");
            }
        }
        return mac;
    }

    private static void Update256(byte* state, ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) { return; }
        fixed (byte* p = data) { _ = Sodium.crypto_hash_sha256_update(state, p, (ulong)data.Length); }
    }

    private static void Update512(byte* state, ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) { return; }
        fixed (byte* p = data) { _ = Sodium.crypto_hash_sha512_update(state, p, (ulong)data.Length); }
    }
}
