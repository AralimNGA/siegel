using Siegel.Core.Native;
using Siegel.Modell;

namespace Siegel.Core;

/// <summary>Ein geöffneter Tresor (noch ohne Sitzung). Besitzt DEK, Inhalt und ggf. den Migrations-KEK.</summary>
internal sealed class OpenedVault(VaultFile file, SecureBuffer dek, VaultContent content) : IDisposable
{
    internal VaultFile File { get; } = file;
    internal SecureBuffer Dek { get; } = dek;
    internal VaultContent Content { get; set; } = content;

    /// <summary>Nur bei Format v1 über den Passwortweg: KEK_pw für einen Kopf v2 mit demselben Salz und ohne Faktoren
    /// (<c>HKDF(p, kdfSalt, "Siegel v2 kek" ‖ 0)</c>), damit das erste Speichern ohne zweites Argon2 migrieren kann.</summary>
    internal SecureBuffer? MigrationKek { get; set; }

    public void Dispose()
    {
        Dek.Dispose();
        Content.Dispose();
        MigrationKek?.Dispose();
    }
}

/// <summary>Bauen und Öffnen von Tresordateien (SPEC §1–§3, §13).</summary>
internal static class VaultCrypto
{
    /// <summary>pwSlot und recSlot für einen (neuen) DEK. Kapselt auf die übergebenen, authentifizierten KOPF-Bytes
    /// (Labels der Formatversion des Kopfes).</summary>
    internal static VaultSlots MakeSlots(VaultHeader header, SecureBuffer kekPw, SecureBuffer dek)
    {
        var pwSlot = Aead.Wrap(kekPw, dek, VaultSlots.PwAd(header));
        using var enc = RecoveryKem.Encapsulate(header.Pk, header.Labels.HybridKem);
        var recSlot = Aead.Wrap(enc.Kek, dek, VaultSlots.RecAd(header));
        return new VaultSlots(pwSlot, enc.CtM, enc.CtX, recSlot);
    }

    /// <summary>Ganze Datei bauen. Liefert die Bytes und SHA-256 des JSON (für die Rücklese-Prüfung).</summary>
    internal static (byte[] Bytes, byte[] Digest) BuildFile(VaultHeader header, VaultSlots slots, ulong generation,
        SecureBuffer dek, VaultContent content, bool legacyV1Content = false)
    {
        var (padded, digest) = PayloadCodec.Encode(content, legacyV1Content);
        using (padded)
        {
            var ad = VaultFile.PayloadAdFor(header, slots, generation);
            var (nonce, ct) = Aead.Seal(dek, padded, ad);
            return (new VaultFile(header, slots, generation, nonce, ct).Serialize(), digest);
        }
    }

    /// <summary>Inhalt mit dem DEK entschlüsseln. Jeder Fehler ist CorruptFile. Die Stufe im Inhalt muss genau die
    /// Faktoren des Kopfes verlangen (beide werden immer zusammen geschrieben).</summary>
    internal static (VaultContent Content, byte[] Digest) DecryptPayload(VaultFile file, SecureBuffer dek)
    {
        using var padded = Aead.Open(dek, file.Nonce, file.Ciphertext, file.PayloadAd) ?? throw Fehler.Corrupt("payload.auth");
        var (content, digest) = PayloadCodec.Decode(padded);
        try
        {
            if (content.Level.Factors() != file.Header.Factors) { throw Fehler.Corrupt("payload.level"); }
            if (!content.DestructionKeysAvoid(file.Header)) { throw Fehler.Corrupt("payload.destruction"); }
            return (content, digest);
        }
        catch
        {
            content.Dispose();
            throw;
        }
    }

    /// <summary>Passwortweg: Faktoren vorhanden/Karte (FactorMissing/WrongCard) → KDF-Bereich → Argon2 (KdfFailed) →
    /// Faktoren einrechnen → pwSlot (WrongPassword: Passwort oder ein Faktor falsch) → Inhalt (CorruptFile).</summary>
    internal static OpenedVault OpenWithPassword(VaultFile file, SecureBuffer password, FactorSecrets? factors, KdfLimits limits,
        KekCache? cache = null)
    {
        var (kek, p) = FactorKdf.DeriveKek(file.Header, password, factors ?? new FactorSecrets(), limits, cache);
        using (p)
        using (kek)
        {
            var dek = Aead.Unwrap(kek, file.Slots.PwSlot, VaultSlots.PwAd(file.Header)) ?? throw Fehler.WrongPassword();
            try
            {
                var (content, _) = DecryptPayload(file, dek);
                var opened = new OpenedVault(file, dek, content);
                if (file.Header.FormatVersion == 1)
                {
                    opened.MigrationKek = FactorKdf.Kek(p, [], file.Header.Salt, 0);
                }
                return opened;
            }
            catch
            {
                dek.Dispose();
                throw;
            }
        }
    }

    /// <summary>Notfallweg: Kit-Prüfung (WrongRecoveryCode), danach jedes Scheitern CorruptFile.</summary>
    internal static OpenedVault OpenWithRecovery(VaultFile file, SecureBuffer r)
    {
        using var kek = RecoveryKem.Decapsulate(r, file.Header.VaultId, file.Header.Pk, file.Slots.CtM, file.Slots.CtX,
            file.Header.Labels.HybridKem);
        var dek = Aead.Unwrap(kek, file.Slots.RecSlot, VaultSlots.RecAd(file.Header)) ?? throw Fehler.Corrupt("rec.slot");
        try
        {
            var (content, _) = DecryptPayload(file, dek);
            return new OpenedVault(file, dek, content);
        }
        catch
        {
            dek.Dispose();
            throw;
        }
    }

    /// <summary>Neuer Kopf (v2, neues Salz), Argon2, KEK mit Faktoren, neuer DEK, neue Slots (Gegenstück zu
    /// <c>VaultStore.rekey</c>). Alle drei Teile gehören dem Aufrufer.</summary>
    internal static (VaultHeader Header, VaultSlots Slots, SecureBuffer Dek) Rekey(byte[] vaultId, KdfParameters kdf,
        HeaderFactorFields fields, RecoveryScheme scheme, RecoveryPublicKeys pk, SecureBuffer password, FactorSecrets factors,
        KdfLimits limits)
    {
        limits.Validate(kdf);
        var header = VaultHeader.V2(vaultId, kdf, Zufall.Bytes(Kdf.SaltBytes), fields, scheme, pk);
        FactorKdf.Precheck(header, factors);
        using var p = Kdf.DeriveKek(password, header.Salt, kdf, limits);
        using var kek = FactorKdf.Kek(p, header, factors);
        var dek = SecureBuffer.Random(Aead.KeyBytes);
        try
        {
            return (header, MakeSlots(header, kek, dek), dek);
        }
        catch
        {
            dek.Dispose();
            throw;
        }
    }
}

/// <summary>Master-Tag (SPEC §1.6): <c>crypto_generichash(key: HKDF(DEK, "Siegel v1 master tag", 32), pw)</c>.</summary>
internal static class MasterTag
{
    internal static readonly byte[] Info = Bytes.Ascii("Siegel v1 master tag");

    /// <summary>HKDF ohne Salz (wie CryptoKit ohne <c>salt:</c>).</summary>
    internal static SecureBuffer Key(SecureBuffer dek) => Hkdf.Derive(dek, [], Info, 32);

    internal static unsafe SecureBuffer Tag(SecureBuffer key, ReadOnlySpan<byte> password)
    {
        Libsodium.EnsureReady();
        var output = SecureBuffer.Scratch(32);
        try
        {
            int rc;
            using (var o = output.BorrowWritable())
            using (var k = key.Borrow())
            {
                fixed (byte* op = o.Span)
                fixed (byte* kp = k.Span)
                fixed (byte* pp = password)
                {
                    rc = Libsodium.crypto_generichash(op, 32, pp, (ulong)password.Length, kp, (nuint)k.Span.Length);
                }
            }
            if (rc != 0) { throw Fehler.Crypto("generichash"); }
            output.Freeze();
            return output;
        }
        catch
        {
            output.Dispose();
            throw;
        }
    }

    internal static SecureBuffer Tag(SecureBuffer key, SecureBuffer password)
    {
        using var l = password.Borrow();
        return Tag(key, l.Span);
    }

    /// <summary>Tag eines Eintragspassworts (gleich normalisiert wie das Master-Passwort); null bei Fehler.</summary>
    internal static SecureBuffer? TagOfEntryPassword(SecureBuffer key, string entryPassword)
    {
        try
        {
            using var pw = PasswordNormalizer.SecureBytes(entryPassword);
            return Tag(key, pw);
        }
        catch (SiegelException)
        {
            return null;
        }
    }

    /// <summary>Einträge, deren Passwort oder Verlaufswert dem Master-Passwort entspricht.</summary>
    internal static HashSet<Guid> Reuse(IEnumerable<VaultEntry> entries, SecureBuffer key, SecureBuffer masterTag)
    {
        var output = new HashSet<Guid>();
        foreach (var e in entries)
        {
            foreach (var p in new[] { e.Password }.Concat(e.History.Select(h => h.Password)))
            {
                if (p.Length == 0) { continue; }
                using var t = TagOfEntryPassword(key, p);
                if (t is not null && t.ConstantTimeEquals(masterTag))
                {
                    output.Add(e.Id);
                    break;
                }
            }
        }
        return output;
    }

    /// <summary>Kommt das (normalisierte) Passwort als Eintragspasswort vor? Vergleich über Tags mit Wegwerf-Schlüssel.</summary>
    internal static bool IsUsedByEntries(SecureBuffer password, IEnumerable<VaultEntry> entries)
    {
        using var k = SecureBuffer.Random(32);
        using var t = Tag(k, password);
        return Reuse(entries, k, t).Count > 0;
    }
}
