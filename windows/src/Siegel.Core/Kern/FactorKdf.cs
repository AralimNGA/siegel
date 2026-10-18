namespace Siegel.Core;

/// <summary>
/// Mehrfaktor-Ableitung (SPEC §13.1, Format v2). Faktor-Werte kommen roh (je 32 Byte); die HKDFs rechnet nur der Kern:
///   e = HKDF-SHA512(ECDH_SE, salt = vaultID, info = "Siegel v2 factor secure-enclave", 32)
///   c = HKDF-SHA512(q,       salt = vaultID, info = "Siegel v2 factor card", 32)
///   y = HKDF-SHA512(hmacOut, salt = vaultID, info = "Siegel v2 factor fido2", 32)
///   KEK_pw = HKDF-SHA512(ikm = p ‖ [e] ‖ [c] ‖ [y], salt = kdfSalt, info = "Siegel v2 kek" ‖ factorMask, 32)
/// mit p = Argon2id(pw). In Format v1 ist KEK_pw = p.
/// </summary>
internal static class FactorKdf
{
    internal static readonly byte[] SeInfo = Bytes.Ascii("Siegel v2 factor secure-enclave");
    internal static readonly byte[] CardInfo = Bytes.Ascii("Siegel v2 factor card");
    internal static readonly byte[] FidoInfo = Bytes.Ascii("Siegel v2 factor fido2");
    internal static readonly byte[] KekInfo = Bytes.Ascii("Siegel v2 kek");

    /// <summary>Prüfwert der FIDO-Entsperr-Ausgabe im verschlüsselten Inhalt (Schlüssel nur für Einträge eingerichtet).</summary>
    internal static readonly byte[] FidoCheckInfo = Bytes.Ascii("Siegel v2 fido check");

    internal const int FidoCheckBytes = 16;

    internal static byte[] Info(FactorKind kind) => kind switch
    {
        FactorKind.SecureEnclave => SeInfo,
        FactorKind.Card => CardInfo,
        _ => FidoInfo,
    };

    /// <summary>e, c bzw. y aus dem rohen Faktor-Wert.</summary>
    internal static SecureBuffer FactorKey(FactorSecret raw, FactorKind kind, ReadOnlySpan<byte> vaultId) =>
        Hkdf.Derive(raw.Storage, vaultId, Info(kind), 32);

    /// <summary>Fehlende Faktoren (<c>FactorMissing</c>, in Ableitungsreihenfolge) und eine falsche Karte
    /// (<c>WrongCard</c>, über die Karten-Kennung im Kopf) erkennen, bevor gerechnet wird. v1 kennt keine Faktoren.</summary>
    internal static void Precheck(VaultHeader header, FactorSecrets factors)
    {
        if (header.FormatVersion < 2) { return; }
        foreach (var kind in header.Factors.Kinds())
        {
            if (factors.Secret(kind) is null) { throw Fehler.FactorMissing(kind); }
        }
        if (header.FactorFields.CardTag is { } tag && factors.Card is { } q)
        {
            if (!CardCode.TagBytesFor(q, header.VaultId).AsSpan().SequenceEqual(tag)) { throw Fehler.WrongCard(); }
        }
    }

    /// <summary>KEK_pw aus p (Argon2-Ausgabe) und den Faktoren, die der Kopf verlangt. Zusätzliche Faktoren werden
    /// ignoriert. v1: eine Kopie von p.</summary>
    internal static SecureBuffer Kek(SecureBuffer p, VaultHeader header, FactorSecrets factors)
    {
        if (header.FormatVersion < 2)
        {
            using var l = p.Borrow();
            return SecureBuffer.Copy(l.Span);
        }
        Precheck(header, factors);
        var keys = new List<SecureBuffer>();
        try
        {
            foreach (var kind in header.Factors.Kinds())
            {
                var raw = factors.Secret(kind) ?? throw Fehler.FactorMissing(kind);
                keys.Add(FactorKey(raw, kind, header.VaultId));
            }
            return Kek(p, keys, header.Salt, (byte)header.Factors);
        }
        finally
        {
            foreach (var k in keys) { k.Dispose(); }
        }
    }

    /// <summary>KEK_pw = HKDF-SHA512(p ‖ Faktor-Schlüssel, salt = kdfSalt, info = "Siegel v2 kek" ‖ mask, 32).</summary>
    internal static SecureBuffer Kek(SecureBuffer p, IReadOnlyList<SecureBuffer> factorKeys, ReadOnlySpan<byte> salt, byte mask)
    {
        if (p.Length != Kdf.KeyBytes || factorKeys.Any(k => k.Length != 32)) { throw Fehler.Crypto("kek.length"); }
        using var ikm = Concatenate([p, .. factorKeys]);
        Span<byte> info = stackalloc byte[KekInfo.Length + 1];
        KekInfo.CopyTo(info);
        info[^1] = mask;
        return Hkdf.Derive(ikm, salt, info, 32);
    }

    /// <summary>Teile (je 32 Byte) aneinanderhängen, in <see cref="SecureBuffer"/>.</summary>
    internal static SecureBuffer Concatenate(IReadOnlyList<SecureBuffer> parts)
    {
        if (parts.Count == 0 || parts.Any(p => p.Length != 32)) { throw Fehler.Crypto("kek.length"); }
        var output = SecureBuffer.Scratch(32 * parts.Count);
        try
        {
            using (var o = output.BorrowWritable())
            {
                for (var i = 0; i < parts.Count; i++)
                {
                    using var s = parts[i].Borrow();
                    s.Span.CopyTo(o.Span.Slice(32 * i, 32));
                }
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

    /// <summary>Ganzer Passwortweg: Faktoren prüfen → KDF-Bereich → Argon2 (oder Cache) → Faktoren einrechnen.
    /// Liefert KEK und p (für die Migration v1 → v2 ohne zweites Argon2); beide gehören dem Aufrufer.</summary>
    internal static (SecureBuffer Kek, SecureBuffer P) DeriveKek(VaultHeader header, SecureBuffer password, FactorSecrets factors,
        KdfLimits limits, KekCache? cache)
    {
        Precheck(header, factors);
        SecureBuffer p;
        if (cache is not null)
        {
            // Kopie: der Cache behält seinen Puffer, der Aufrufer besitzt immer das Ergebnis.
            var cached = cache.Argon(header, password, limits);
            using var l = cached.Borrow();
            p = SecureBuffer.Copy(l.Span);
        }
        else
        {
            p = Kdf.DeriveKek(password, header.Salt, header.Kdf, limits);
        }
        try
        {
            return (Kek(p, header, factors), p);
        }
        catch
        {
            p.Dispose();
            throw;
        }
    }

    /// <summary>Prüfwert einer FIDO-Entsperr-Ausgabe (nicht umkehrbar, domänengetrennt von y).</summary>
    internal static byte[] FidoCheck(FactorSecret output, ReadOnlySpan<byte> vaultId)
    {
        using var c = Hkdf.Derive(output.Storage, vaultId, FidoCheckInfo, FidoCheckBytes);
        using var l = c.Borrow();
        return l.Span.ToArray();
    }
}

/// <summary>Öffentliche Hybrid-Schlüssel für den Eintrags-Schutz (SPEC §16.1): aus q bzw. der FIDO-Eintragsausgabe y2.</summary>
internal static class EntryKeyDerivation
{
    internal static readonly byte[] CardSeedInfo = Bytes.Ascii("Siegel v2 card entry ML-KEM-1024 seed");
    internal static readonly byte[] CardX25519Info = Bytes.Ascii("Siegel v2 card entry X25519");
    internal static readonly byte[] FidoSeedInfo = Bytes.Ascii("Siegel v2 fido entry ML-KEM-1024 seed");
    internal static readonly byte[] FidoX25519Info = Bytes.Ascii("Siegel v2 fido entry X25519");

    internal static RecoveryPublicKeys CardPublicKeys(FactorSecret q, ReadOnlySpan<byte> vaultId) =>
        RecoveryKem.DerivePublicKeys(q.Storage, vaultId, CardSeedInfo, CardX25519Info);

    internal static RecoveryPublicKeys FidoPublicKeys(FactorSecret entryOutput, ReadOnlySpan<byte> vaultId) =>
        RecoveryKem.DerivePublicKeys(entryOutput.Storage, vaultId, FidoSeedInfo, FidoX25519Info);
}

/// <summary>
/// Wiederverwendung der Argon2-Ausgabe bei gleichem Salz + gleichen Parametern (kein zweites Argon2, §4). Gespeichert
/// wird p (vor den Faktoren). Der Cache besitzt die Puffer; <see cref="Dispose"/> gibt alle frei.
/// </summary>
internal sealed class KekCache : IDisposable
{
    private readonly Lock gate = new();
    private readonly Dictionary<string, SecureBuffer> items = [];

    internal SecureBuffer Argon(VaultHeader header, SecureBuffer password, KdfLimits limits)
    {
        limits.Validate(header.Kdf);
        var w = new ByteWriter(32);
        w.Write(header.Salt);
        w.WriteU32(header.Kdf.OpsLimit);
        w.WriteU64(header.Kdf.MemLimitBytes);
        var key = Bytes.Hex(w.Written);
        lock (gate)
        {
            if (items.TryGetValue(key, out var hit)) { return hit; }
        }
        var p = Kdf.DeriveKek(password, header.Salt, header.Kdf, limits);
        lock (gate)
        {
            if (items.TryGetValue(key, out var raced))
            {
                p.Dispose();
                return raced;
            }
            items[key] = p;
        }
        return p;
    }

    public void Dispose()
    {
        lock (gate)
        {
            foreach (var p in items.Values) { p.Dispose(); }
            items.Clear();
        }
    }
}
