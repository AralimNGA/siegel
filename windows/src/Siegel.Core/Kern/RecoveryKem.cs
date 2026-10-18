using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;

namespace Siegel.Core;

/// <summary>Öffentliche Hybrid-Schlüssel (Kopf bzw. Inhalt): ML-KEM-1024 (1568 B) und X25519 (32 B). Nicht geheim.</summary>
internal sealed class RecoveryPublicKeys : IEquatable<RecoveryPublicKeys>
{
    internal const int PkMBytes = 1568;
    internal const int PkXBytes = 32;

    private string? kitId;

    internal RecoveryPublicKeys(byte[] pkM, byte[] pkX)
    {
        PkM = pkM;
        PkX = pkX;
    }

    internal byte[] PkM { get; }
    internal byte[] PkX { get; }

    internal bool HasValidLengths => PkM.Length == PkMBytes && PkX.Length == PkXBytes;

    /// <summary>Kit-Kennung „XXXX-XXXX“ (nicht geheim).</summary>
    internal string KitId => kitId ??= RecoveryCodeCodec.KitId(PkM, PkX);

    public bool Equals(RecoveryPublicKeys? other) =>
        other is not null && PkM.AsSpan().SequenceEqual(other.PkM) && PkX.AsSpan().SequenceEqual(other.PkX);

    public override bool Equals(object? obj) => Equals(obj as RecoveryPublicKeys);

    public override int GetHashCode() => HashCode.Combine(PkX.Length > 0 ? PkX[0] : 0, PkM.Length);
}

/// <summary>Ergebnis des Kapselns: KEK und die beiden Chiffrate.</summary>
internal sealed class RecoveryEncapsulation(SecureBuffer kek, byte[] ctM, byte[] ctX) : IDisposable
{
    internal SecureBuffer Kek { get; } = kek;
    internal byte[] CtM { get; } = ctM;
    internal byte[] CtX { get; } = ctX;

    public void Dispose() => Kek.Dispose();
}

/// <summary>Geprüfte private Hybrid-Schlüssel samt den öffentlichen, zu denen sie passen. Der ML-KEM-Schlüssel liegt
/// in BouncyCastle-Objekten (verwalteter Speicher, nicht nullbar – ehrliche Grenze, SPEC-WINDOWS W2).</summary>
internal sealed class HybridPrivateKeys(MLKemPrivateKeyParameters skM, SecureBuffer skX, RecoveryPublicKeys pk) : IDisposable
{
    internal MLKemPrivateKeyParameters SkM { get; } = skM;
    internal SecureBuffer SkX { get; } = skX;
    internal RecoveryPublicKeys Pk { get; } = pk;

    public void Dispose() => SkX.Dispose();

    public override string ToString() => "HybridPrivateKeys(redacted)";
}

/// <summary>Hybrider Notfallschlüssel ML-KEM-1024 + X25519 (SPEC §1.3) und die Varianten mit Zusatzfeld (§16.1).</summary>
internal static class RecoveryKem
{
    internal const int RBytes = 32;
    internal const int CtMBytes = 1568;
    internal const int CtXBytes = 32;

    /// <summary>Feste Seed-Länge (FIPS 203: d ‖ z).</summary>
    internal const int SeedBytes = 64;

    /// <summary>HKDF-Infos für R bleiben in allen Formatversionen „Siegel v1 …“ (gedruckte Codes bleiben gültig, §13.2).</summary>
    internal static readonly byte[] SeedInfo = Bytes.Ascii("Siegel v1 recovery ML-KEM-1024 seed");
    internal static readonly byte[] X25519Info = Bytes.Ascii("Siegel v1 recovery X25519");

    /// <summary>Kombinierer-Label der Formatversion 1; v2 nimmt <c>Labels.HybridKem</c> („Siegel v2 hybrid KEM“).</summary>
    internal static readonly byte[] CombinerLabel = Bytes.Ascii("Siegel v1 hybrid KEM");

    private static MLKemParameters Params => MLKemParameters.ml_kem_1024;

    // MARK: Schlüssel

    /// <summary>ML-KEM-Schlüssel aus dem 64-Byte-Seed. Die Länge wird vorher geprüft (CryptoKit-Falle, §1.3).</summary>
    internal static MLKemPrivateKeyParameters MlkemPrivateKey(SecureBuffer seed)
    {
        if (seed.Length != SeedBytes) { throw Fehler.Crypto("mlkem.seedLength"); }
        var copy = new byte[SeedBytes];
        try
        {
            using (var s = seed.Borrow()) { s.Span.CopyTo(copy); }
            return MLKemPrivateKeyParameters.FromSeed(Params, copy);
        }
        catch (ArgumentException)
        {
            throw Fehler.Crypto("kem.keygen");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(copy);
        }
    }

    internal static SecureBuffer MlkemSeed(SecureBuffer ikm, ReadOnlySpan<byte> vaultId, ReadOnlySpan<byte> info) =>
        Hkdf.Derive(ikm, vaultId, info, SeedBytes);

    internal static SecureBuffer X25519Raw(SecureBuffer ikm, ReadOnlySpan<byte> vaultId, ReadOnlySpan<byte> info) =>
        Hkdf.Derive(ikm, vaultId, info, X25519.KeyBytes);

    /// <summary>pkM/pkX aus R ableiten (vaultID als HKDF-Salz).</summary>
    internal static RecoveryPublicKeys DerivePublicKeys(SecureBuffer r, ReadOnlySpan<byte> vaultId) =>
        DerivePublicKeys(r, vaultId, SeedInfo, X25519Info);

    /// <summary>Hybrid-Schlüsselpaar aus einem 32-Byte-Geheimnis mit eigenen HKDF-Infos (Notfall: R; Einträge §16.1:
    /// Karte q bzw. FIDO-Ausgabe y2 mit „Siegel v2 card entry …“/„Siegel v2 fido entry …“).</summary>
    internal static RecoveryPublicKeys DerivePublicKeys(SecureBuffer ikm, ReadOnlySpan<byte> vaultId, ReadOnlySpan<byte> seedInfo,
        ReadOnlySpan<byte> x25519Info)
    {
        byte[] pkM;
        using (var seed = MlkemSeed(ikm, vaultId, seedInfo))
        {
            pkM = MlkemPrivateKey(seed).GetPublicKeyEncoded();
        }
        byte[] pkX;
        using (var x = X25519Raw(ikm, vaultId, x25519Info))
        {
            pkX = X25519.PublicKey(x);
        }
        var pk = new RecoveryPublicKeys(pkM, pkX);
        if (!pk.HasValidLengths) { throw Fehler.Crypto("kem.keygen"); }
        return pk;
    }

    /// <summary>Ergibt R genau diese öffentlichen Schlüssel? (Zuerst das billige X25519, dann ML-KEM.)</summary>
    internal static bool Matches(SecureBuffer r, ReadOnlySpan<byte> vaultId, RecoveryPublicKeys expected)
    {
        try
        {
            using (var x = X25519Raw(r, vaultId, X25519Info))
            {
                if (!X25519.PublicKey(x).AsSpan().SequenceEqual(expected.PkX)) { return false; }
            }
            using var seed = MlkemSeed(r, vaultId, SeedInfo);
            return MlkemPrivateKey(seed).GetPublicKeyEncoded().AsSpan().SequenceEqual(expected.PkM);
        }
        catch (Siegel.Modell.SiegelException)
        {
            return false;
        }
    }

    /// <summary>Private Hybrid-Schlüssel aus einem 32-Byte-Geheimnis, nur wenn sie genau <paramref name="expected"/>
    /// ergeben; sonst null (falsches Geheimnis).</summary>
    internal static HybridPrivateKeys? PrivateKeys(SecureBuffer ikm, ReadOnlySpan<byte> vaultId, ReadOnlySpan<byte> seedInfo,
        ReadOnlySpan<byte> x25519Info, RecoveryPublicKeys expected)
    {
        SecureBuffer? skX = null;
        try
        {
            skX = X25519Raw(ikm, vaultId, x25519Info);
            if (!X25519.PublicKey(skX).AsSpan().SequenceEqual(expected.PkX)) { skX.Dispose(); return null; }
            // Wie CryptoKit (MLKEM1024.PublicKey(rawRepresentation:)): der erwartete Schlüssel muss gültig kodiert sein.
            _ = MLKemPublicKeyParameters.FromEncoding(Params, expected.PkM);
            MLKemPrivateKeyParameters skM;
            using (var seed = MlkemSeed(ikm, vaultId, seedInfo)) { skM = MlkemPrivateKey(seed); }
            if (!skM.GetPublicKeyEncoded().AsSpan().SequenceEqual(expected.PkM)) { skX.Dispose(); return null; }
            return new HybridPrivateKeys(skM, skX, expected);
        }
        catch (Exception e) when (e is ArgumentException or Siegel.Modell.SiegelException)
        {
            skX?.Dispose();
            return null;
        }
    }

    // MARK: Kapseln

    /// <summary>Kapseln für den recSlot: braucht nur die öffentlichen Schlüssel (nicht R).
    /// <paramref name="label"/> = Kombinierer-Label der Formatversion des Kopfes.</summary>
    internal static RecoveryEncapsulation Encapsulate(RecoveryPublicKeys pk, ReadOnlySpan<byte> label) =>
        Encapsulate(pk, label, context: null);

    /// <summary>Kapseln an beliebige Hybrid-Schlüssel mit Zusatzfeld (16 Byte nach dem Label, §16.1).</summary>
    internal static RecoveryEncapsulation Encapsulate(RecoveryPublicKeys pk, ReadOnlySpan<byte> label, byte[]? context)
    {
        byte[] ctM;
        var ssM = new byte[32];
        try
        {
            try
            {
                var pub = MLKemPublicKeyParameters.FromEncoding(Params, pk.PkM);
                var enc = new MLKemEncapsulator(Params);
                enc.Init(pub);
                ctM = new byte[enc.EncapsulationLength];
                if (ctM.Length != CtMBytes || enc.SecretLength != ssM.Length) { throw Fehler.Crypto("kem.encapsulate"); }
                enc.Encapsulate(ctM, 0, ctM.Length, ssM, 0, ssM.Length);
            }
            catch (Exception e) when (e is ArgumentException or InvalidOperationException)
            {
                throw Fehler.Crypto("kem.encapsulate");
            }
            using var ephemeral = SecureBuffer.Random(X25519.KeyBytes);
            var ctX = X25519.PublicKey(ephemeral);
            using var ssX = X25519.SharedSecret(ephemeral, pk.PkX) ?? throw Fehler.Crypto("kem.x25519");
            using var ssXLease = ssX.Borrow();
            var kek = Combine(label, context, ssM, ssXLease.Span, ctX, pk.PkX, ctM, pk.PkM);
            return new RecoveryEncapsulation(kek, ctM, ctX);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ssM);
        }
    }

    // MARK: Entkapseln

    /// <summary>Entkapseln mit R. Vor bestandener pk-Prüfung → <c>WrongRecoveryCode</c>, danach jedes Scheitern
    /// <c>corruptFile("rec.decapsulate")</c>.</summary>
    internal static SecureBuffer Decapsulate(SecureBuffer r, ReadOnlySpan<byte> vaultId, RecoveryPublicKeys pk, byte[] ctM,
        byte[] ctX, ReadOnlySpan<byte> label)
    {
        MLKemPrivateKeyParameters skM;
        byte[] derivedPkM;
        using (var seed = MlkemSeed(r, vaultId, SeedInfo))
        {
            skM = MlkemPrivateKey(seed);
            derivedPkM = skM.GetPublicKeyEncoded();
        }
        using var skX = X25519Raw(r, vaultId, X25519Info);
        var derivedPkX = X25519.PublicKey(skX);
        var codeKit = RecoveryCodeCodec.KitId(derivedPkM, derivedPkX);
        var vaultKit = pk.KitId;
        if (codeKit != vaultKit) { throw Fehler.WrongRecoveryCode(codeKit, vaultKit); }
        if (!derivedPkM.AsSpan().SequenceEqual(pk.PkM) || !derivedPkX.AsSpan().SequenceEqual(pk.PkX))
        {
            throw Fehler.WrongRecoveryCode(codeKit, vaultKit);
        }
        // pk-Prüfung bestanden: ab hier nur noch corruptFile.
        try
        {
            return DecapsulateCore(skM, skX, ctM, ctX, pk, label, context: null);
        }
        catch (Siegel.Modell.SiegelException)
        {
            throw Fehler.Corrupt("rec.decapsulate");
        }
    }

    /// <summary>Entkapseln mit schon geprüften privaten Schlüsseln (Kombinierer mit Zusatzfeld). Jedes Scheitern →
    /// <c>Crypto("kem.decapsulate")</c>; die Aufrufer bilden das auf ihren Fehler ab.</summary>
    internal static SecureBuffer Decapsulate(HybridPrivateKeys keys, byte[] ctM, byte[] ctX, ReadOnlySpan<byte> label,
        byte[]? context)
    {
        try
        {
            return DecapsulateCore(keys.SkM, keys.SkX, ctM, ctX, keys.Pk, label, context);
        }
        catch (Siegel.Modell.SiegelException)
        {
            throw Fehler.Crypto("kem.decapsulate");
        }
    }

    private static SecureBuffer DecapsulateCore(MLKemPrivateKeyParameters skM, SecureBuffer skX, byte[] ctM, byte[] ctX,
        RecoveryPublicKeys pk, ReadOnlySpan<byte> label, byte[]? context)
    {
        if (ctM.Length != CtMBytes || ctX.Length != CtXBytes) { throw Fehler.Crypto("kem.decapsulate"); }
        var ssM = new byte[32];
        try
        {
            try
            {
                var dec = new MLKemDecapsulator(Params);
                dec.Init(skM);
                dec.Decapsulate(ctM, 0, ctM.Length, ssM, 0, ssM.Length);
            }
            catch (Exception e) when (e is ArgumentException or InvalidOperationException)
            {
                throw Fehler.Crypto("kem.decapsulate");
            }
            using var ssX = X25519.SharedSecret(skX, ctX) ?? throw Fehler.Crypto("kem.decapsulate");
            using var x = ssX.Borrow();
            return Combine(label, context, ssM, x.Span, ctX, pk.PkX, ctM, pk.PkM);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ssM);
        }
    }

    // MARK: Kombinierer

    /// <summary>
    /// KEK = SHA3-256(label ‖ [context] ‖ ssM ‖ ssX ‖ ctX ‖ pkX ‖ SHA3-256(ctM) ‖ SHA3-256(pkM)). Generischer Kombinierer,
    /// feste Längen, genau diese Reihenfolge; ohne Zusatzfeld = §1.3 (Testvektor (c) und KEK v2 hängen daran).
    /// Nicht „vereinfachen“.
    /// </summary>
    internal static SecureBuffer Combine(ReadOnlySpan<byte> label, byte[]? context, ReadOnlySpan<byte> ssM, ReadOnlySpan<byte> ssX,
        ReadOnlySpan<byte> ctX, ReadOnlySpan<byte> pkX, ReadOnlySpan<byte> ctM, ReadOnlySpan<byte> pkM)
    {
        if ((context is not null && context.Length != 16) || ssM.Length != 32 || ssX.Length != 32 || ctX.Length != CtXBytes
            || pkX.Length != RecoveryPublicKeys.PkXBytes || ctM.Length != CtMBytes || pkM.Length != RecoveryPublicKeys.PkMBytes)
        {
            throw Fehler.Crypto("kem.combine");
        }
        var h = new Sha3Hasher().Update(label);
        if (context is not null) { h.Update(context); }
        h.Update(ssM).Update(ssX).Update(ctX).Update(pkX);
        h.Update(Sha3Hasher.Of(ctM)).Update(Sha3Hasher.Of(pkM));
        var output = SecureBuffer.Scratch(32);
        try
        {
            using (var o = output.BorrowWritable()) { h.Final(o.Span); }
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
