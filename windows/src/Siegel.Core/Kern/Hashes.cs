using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;

namespace Siegel.Core;

/// <summary>
/// SHA3-256 über BouncyCastle (auf macOS meldet .NET <c>SHA3_256.IsSupported = false</c>, SPEC-WINDOWS W2; derselbe
/// Code auf beiden Plattformen). <c>DoFinal</c> setzt den Zustand zurück (Keccak-Zustand genullt).
/// </summary>
internal sealed class Sha3Hasher
{
    internal const int Size = 32;

    private readonly Sha3Digest digest = new(256);

    internal Sha3Hasher Update(ReadOnlySpan<byte> data)
    {
        digest.BlockUpdate(data);
        return this;
    }

    internal Sha3Hasher Update(byte b)
    {
        digest.Update(b);
        return this;
    }

    internal void Final(Span<byte> output32) => digest.DoFinal(output32);

    internal byte[] Final()
    {
        var out32 = new byte[Size];
        digest.DoFinal(out32);
        return out32;
    }

    /// <summary>SHA3-256 eines Bereichs (nicht geheimes Ergebnis).</summary>
    internal static byte[] Of(ReadOnlySpan<byte> data) => new Sha3Hasher().Update(data).Final();

    /// <summary>SHA3-256 einer Folge von Teilen (nicht geheime Ergebnisse).</summary>
    internal static byte[] Hash(params ReadOnlySpan<byte[]> parts)
    {
        var h = new Sha3Hasher();
        foreach (var p in parts) { h.Update(p); }
        return h.Final();
    }
}

/// <summary>HKDF-SHA512 (<see cref="HKDF"/>, plattformneutral) mit Ausgabe in <see cref="SecureBuffer"/>.</summary>
internal static class Hkdf
{
    /// <summary><c>HKDF&lt;SHA512&gt;(ikm, salt, info, count)</c> wie CryptoKit <c>HKDF.deriveKey</c> (leeres Salz =
    /// HashLen Nullbytes, RFC 5869).</summary>
    internal static SecureBuffer Derive(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, int count)
    {
        var b = SecureBuffer.Scratch(count);
        try
        {
            using (var w = b.BorrowWritable())
            {
                HKDF.DeriveKey(HashAlgorithmName.SHA512, ikm, w.Span, salt, info);
            }
            b.Freeze();
            return b;
        }
        catch (CryptographicException)
        {
            b.Dispose();
            throw Fehler.Crypto("hkdf");
        }
        catch
        {
            b.Dispose();
            throw;
        }
    }

    internal static SecureBuffer Derive(SecureBuffer ikm, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, int count)
    {
        using var k = ikm.Borrow();
        return Derive(k.Span, salt, info, count);
    }
}

/// <summary>SHA-256 (Rücklese-Prüfung des Klartexts, §4).</summary>
internal static class Sha256Hash
{
    internal static byte[] Of(ReadOnlySpan<byte> data) => SHA256.HashData(data);
}
