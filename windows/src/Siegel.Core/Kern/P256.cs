using System.Security.Cryptography;

namespace Siegel.Core;

/// <summary>
/// P-256 (ECDH) für die Mac-Art des Eintrags-Gerätefaktors (§16.1: ephemeres k, ECDH mit dem öffentlichen
/// Eintrags-SE-Schlüssel) und die Form der Ablage des Vernichtungs-Passworts (zufälliger gültiger Punkt). Über
/// <see cref="ECDiffieHellman"/> (Windows CNG, macOS Security), gleich wie CryptoKit: öffentliche Schlüssel in x963
/// (0x04 ‖ X ‖ Y, 65 Byte), gemeinsames Geheimnis = x-Koordinate (32 Byte, <c>DeriveRawSecretAgreement</c>, nicht
/// gehasht). Ungültige Punkte lehnt der Import ab.
/// </summary>
internal static class P256
{
    internal const int PublicKeyBytes = 65;
    internal const int CoordinateBytes = 32;

    /// <summary>Gültiger unkomprimierter Punkt auf der Kurve?</summary>
    internal static bool IsValidPublicKey(ReadOnlySpan<byte> x963)
    {
        try
        {
            using var key = Import(x963);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>Öffentlichen Schlüssel einlesen; ungültig → <see cref="CryptographicException"/>.</summary>
    internal static ECDiffieHellman Import(ReadOnlySpan<byte> x963)
    {
        if (x963.Length != PublicKeyBytes || x963[0] != 0x04) { throw new CryptographicException("p256.encoding"); }
        var parameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = x963.Slice(1, CoordinateBytes).ToArray(), Y = x963.Slice(1 + CoordinateBytes, CoordinateBytes).ToArray() },
        };
        try
        {
            return ECDiffieHellman.Create(parameters);
        }
        catch (Exception e) when (e is ArgumentException or PlatformNotSupportedException)
        {
            throw new CryptographicException("p256.import");
        }
    }

    /// <summary>x963 eines Schlüssels.</summary>
    internal static byte[] Encode(ECDiffieHellman key)
    {
        var q = key.ExportParameters(includePrivateParameters: false).Q;
        if (q.X is not { Length: CoordinateBytes } x || q.Y is not { Length: CoordinateBytes } y)
        {
            throw new CryptographicException("p256.export");
        }
        return [0x04, .. x, .. y];
    }

    /// <summary>Ephemeres k erzeugen und ECDH mit <paramref name="peerX963"/>: (öffentliches k in x963, gemeinsames
    /// Geheimnis in <see cref="SecureBuffer"/>). Ungültiger Peer → <c>Crypto(invalidCode)</c>, Rechenfehler →
    /// <c>Crypto("entry.ecdh")</c>.</summary>
    internal static (byte[] EphemeralPublic, SecureBuffer Shared) EphemeralAgreement(ReadOnlySpan<byte> peerX963, string invalidCode)
    {
        ECDiffieHellman peer;
        try
        {
            peer = Import(peerX963);
        }
        catch (CryptographicException)
        {
            throw Fehler.Crypto(invalidCode);
        }
        using (peer)
        using (var ephemeral = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
        {
            byte[]? raw = null;
            try
            {
                raw = ephemeral.DeriveRawSecretAgreement(peer.PublicKey);
                if (raw.Length != CoordinateBytes) { throw Fehler.Crypto("entry.ecdh"); }
                return (Encode(ephemeral), SecureBuffer.Copy(raw));
            }
            catch (CryptographicException)
            {
                throw Fehler.Crypto("entry.ecdh");
            }
            finally
            {
                if (raw is not null) { CryptographicOperations.ZeroMemory(raw); }
            }
        }
    }

    /// <summary>Zufälliger gültiger Punkt (nicht geheim; Füllfeld der Ablage, §23.2 Nr. 3).</summary>
    internal static byte[] RandomPoint()
    {
        try
        {
            using var key = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            return Encode(key);
        }
        catch (Exception e) when (e is CryptographicException or PlatformNotSupportedException)
        {
            throw Fehler.Crypto("p256.random");
        }
    }
}
