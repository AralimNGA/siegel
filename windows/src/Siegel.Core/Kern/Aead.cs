using Siegel.Core.Native;

namespace Siegel.Core;

/// <summary>XChaCha20-Poly1305-IETF (SPEC §1.4): 24-Byte-Zufallsnonce pro Verschlüsselung, 16-Byte-Tag.</summary>
internal static class Aead
{
    internal const int NonceBytes = 24;
    internal const int TagBytes = 16;
    internal const int KeyBytes = 32;

    /// <summary>nonce[24] ‖ ct[32] ‖ tag[16]</summary>
    internal const int WrappedBytes = 72;

    /// <summary>Verpackt einen 32-Byte-Schlüssel: nonce ‖ ct ‖ tag (72 Byte).</summary>
    internal static unsafe byte[] Wrap(SecureBuffer kek, SecureBuffer secret, ReadOnlySpan<byte> ad)
    {
        if (kek.Length != KeyBytes || secret.Length != KeyBytes) { throw Fehler.Crypto("aead.keyLength"); }
        Libsodium.EnsureReady();
        var output = new byte[WrappedBytes];
        Zufall.Fill(output.AsSpan(0, NonceBytes));
        int rc;
        using (var k = kek.Borrow())
        using (var m = secret.Borrow())
        {
            fixed (byte* op = output)
            fixed (byte* kp = k.Span)
            fixed (byte* mp = m.Span)
            fixed (byte* ap = ad)
            {
                ulong clen = 0;
                rc = Libsodium.crypto_aead_xchacha20poly1305_ietf_encrypt(op + NonceBytes, &clen, mp, KeyBytes, ap,
                    (ulong)ad.Length, null, op, kp);
            }
        }
        if (rc != 0) { throw Fehler.Crypto("aead.encrypt"); }
        return output;
    }

    /// <summary>Entpackt; null bei falschem Schlüssel/AD/manipulierten Bytes.</summary>
    internal static unsafe SecureBuffer? Unwrap(SecureBuffer kek, ReadOnlySpan<byte> blob, ReadOnlySpan<byte> ad)
    {
        if (kek.Length != KeyBytes || blob.Length != WrappedBytes) { return null; }
        var output = SecureBuffer.Scratch(KeyBytes);
        try
        {
            int rc;
            using (var o = output.BorrowWritable())
            using (var k = kek.Borrow())
            {
                fixed (byte* op = o.Span)
                fixed (byte* bp = blob)
                fixed (byte* kp = k.Span)
                fixed (byte* ap = ad)
                {
                    ulong mlen = 0;
                    rc = Libsodium.crypto_aead_xchacha20poly1305_ietf_decrypt(op, &mlen, null, bp + NonceBytes,
                        KeyBytes + TagBytes, ap, (ulong)ad.Length, bp, kp);
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

    /// <summary>Verschlüsselt einen Klartext-Puffer; liefert (nonce, ct ‖ tag).</summary>
    internal static unsafe (byte[] Nonce, byte[] Ciphertext) Seal(SecureBuffer key, SecureBuffer plaintext, ReadOnlySpan<byte> ad)
    {
        if (key.Length != KeyBytes) { throw Fehler.Crypto("aead.keyLength"); }
        Libsodium.EnsureReady();
        var nonce = Zufall.Bytes(NonceBytes);
        var ct = new byte[plaintext.Length + TagBytes];
        int rc;
        using (var k = key.Borrow())
        using (var m = plaintext.Borrow())
        {
            fixed (byte* cp = ct)
            fixed (byte* mp = m.Span)
            fixed (byte* kp = k.Span)
            fixed (byte* ap = ad)
            fixed (byte* np = nonce)
            {
                ulong clen = 0;
                rc = Libsodium.crypto_aead_xchacha20poly1305_ietf_encrypt(cp, &clen, mp, (ulong)m.Span.Length, ap,
                    (ulong)ad.Length, null, np, kp);
            }
        }
        if (rc != 0) { throw Fehler.Crypto("aead.encrypt"); }
        return (nonce, ct);
    }

    /// <summary>Entschlüsselt in <see cref="SecureBuffer"/>; null bei Authentisierungsfehler.</summary>
    internal static unsafe SecureBuffer? Open(SecureBuffer key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> ad)
    {
        if (key.Length != KeyBytes || nonce.Length != NonceBytes || ciphertext.Length < TagBytes) { return null; }
        var output = SecureBuffer.Scratch(ciphertext.Length - TagBytes);
        try
        {
            int rc;
            using (var o = output.BorrowWritable())
            using (var k = key.Borrow())
            {
                // Die Rechenfläche hat immer eine Adresse (mindestens 1 Byte reserviert); bei leerem Klartext liefert
                // fixed trotzdem null, das libsodium bei mlen 0 nicht anfasst.
                fixed (byte* op = o.Span)
                fixed (byte* cp = ciphertext)
                fixed (byte* kp = k.Span)
                fixed (byte* ap = ad)
                fixed (byte* np = nonce)
                {
                    ulong mlen = 0;
                    rc = Libsodium.crypto_aead_xchacha20poly1305_ietf_decrypt(op, &mlen, null, cp, (ulong)ciphertext.Length,
                        ap, (ulong)ad.Length, np, kp);
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
