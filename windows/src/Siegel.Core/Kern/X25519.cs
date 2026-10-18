using Siegel.Core.Native;

namespace Siegel.Core;

/// <summary>
/// X25519 über libsodium (<c>crypto_scalarmult</c>). Gleich wie CryptoKit <c>Curve25519.KeyAgreement</c>: Rohschlüssel
/// 32 Byte (Klammerung beim Rechnen), öffentlicher Schlüssel = u-Koordinate; ein gemeinsames Geheimnis aus lauter
/// Nullbytes (Null- und Kleinordnungspunkte) wird abgelehnt (libsodium liefert dann −1, CryptoKit wirft).
/// </summary>
internal static class X25519
{
    internal const int KeyBytes = 32;

    /// <summary>Öffentlicher Schlüssel zum Rohschlüssel. Nicht geheim.</summary>
    internal static unsafe byte[] PublicKey(SecureBuffer secret)
    {
        if (secret.Length != KeyBytes) { throw Fehler.Crypto("kem.x25519"); }
        Libsodium.EnsureReady();
        var pk = new byte[KeyBytes];
        int rc;
        using (var s = secret.Borrow())
        {
            fixed (byte* q = pk)
            fixed (byte* n = s.Span)
            {
                rc = Libsodium.crypto_scalarmult_base(q, n);
            }
        }
        if (rc != 0) { throw Fehler.Crypto("kem.x25519"); }
        return pk;
    }

    /// <summary>Gemeinsames Geheimnis; null bei Null-/Kleinordnungspunkt oder falscher Länge.</summary>
    internal static unsafe SecureBuffer? SharedSecret(SecureBuffer secret, ReadOnlySpan<byte> peerPublic)
    {
        if (secret.Length != KeyBytes || peerPublic.Length != KeyBytes) { return null; }
        Libsodium.EnsureReady();
        var output = SecureBuffer.Scratch(KeyBytes);
        try
        {
            int rc;
            using (var o = output.BorrowWritable())
            using (var s = secret.Borrow())
            {
                fixed (byte* q = o.Span)
                fixed (byte* n = s.Span)
                fixed (byte* p = peerPublic)
                {
                    rc = Libsodium.crypto_scalarmult(q, n, p);
                }
            }
            if (rc != 0)
            {
                output.Dispose();
                return null;
            }
            output.Freeze();
            return output;
        }
        catch
        {
            output.Dispose();
            throw;
        }
    }
}
