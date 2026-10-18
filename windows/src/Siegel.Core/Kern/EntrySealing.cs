using System.Security.Cryptography;
using Siegel.Core.Native;
using Siegel.Modell;
using Siegel.Werkzeuge;

namespace Siegel.Core;

/// <summary>
/// Eintrags-Schutz (SPEC §16.1), byte-genau wie EntrySealing.swift: Geheimteile pro Eintrag versiegeln, mit den Faktoren
/// aufdecken, Notfall-Umschläge und Notfall-Gruppen. Reine Kryptografie ohne Zustand.
/// <code>
///   base   = HKDF-SHA512(EBK, salt = entryID, info = "Siegel v2 entry dek", 32)
///   ss_se  = HKDF-SHA512(ECDH(k, seEntryPub), salt = entryID, info = "Siegel v2 entry se", 32), k ephemer (P-256)
///   ss_card/ss_fido = hybride Kapselung an cardPK/fidoPK, Kombinierer §1.3 mit entryID nach dem Label
///   K      = HKDF-SHA512(base ‖ [ss_se] ‖ [ss_card] ‖ [ss_fido], salt = entryID, info = "Siegel v2 entry key" ‖ s ‖ M, 32)
///   Blob   = XChaCha20-Poly1305(K, pad256(JSON), AD = "Siegel v2 entry" ‖ vaultID ‖ entryID ‖ s ‖ M)
///   vernichtbar (§23.1): V statt Eintrags-SE-Schlüssel, ss info "Siegel v2 entry destruction",
///                        K info "Siegel v2 entry key destructible", AD "Siegel v2 entry destructible", kein Umschlag.
/// </code>
/// Windows-Hello-Art (Version 1, SPEC-WINDOWS W4.1, neu in C#): statt ECDH eine Signatur über eine eintragsspezifische
/// Herausforderung (Blob-Feld <c>"hello": {"salt", "version"}</c> statt <c>"se"</c>):
/// <code>
///   challenge = SHA-256("Siegel v2 windows hello entry challenge" ‖ vaultID ‖ keyID ‖ entryID ‖ salt[32])
///   roh       = SHA-256("Siegel v2 windows hello entry" ‖ RSA-PKCS#1-v1.5-SHA-256-Signatur über challenge)  (Plattform)
///   ss_dev    = HKDF-SHA512(roh, salt = entryID, info = "Siegel v2 entry windows hello", 32)
///               (vernichtbar: info = "Siegel v2 entry destruction windows hello")
/// </code>
/// K, AD, Umschläge und Gruppen bleiben gleich.
/// </summary>
internal static class EntrySealing
{
    internal static readonly byte[] DekInfo = Bytes.Ascii("Siegel v2 entry dek");
    internal static readonly byte[] KeyInfo = Bytes.Ascii("Siegel v2 entry key");
    internal static readonly byte[] SeInfo = Bytes.Ascii("Siegel v2 entry se");
    internal static readonly byte[] CardLabel = Bytes.Ascii("Siegel v2 entry card");
    internal static readonly byte[] FidoLabel = Bytes.Ascii("Siegel v2 entry fido");
    internal static readonly byte[] EntryAd = Bytes.Ascii("Siegel v2 entry");
    internal static readonly byte[] RecoveryLabel = Bytes.Ascii("Siegel v2 entry recovery");
    internal static readonly byte[] GroupSeedInfo = Bytes.Ascii("Siegel v2 entry recovery ML-KEM-1024 seed");
    internal static readonly byte[] GroupX25519Info = Bytes.Ascii("Siegel v2 entry recovery X25519");
    internal static readonly byte[] KitLabel = Bytes.Ascii("Siegel v2 entry recovery kit");
    internal static readonly byte[] AnchorAd = Bytes.Ascii("Siegel v2 entry anchor");
    internal static readonly byte[] ReuseInfo = Bytes.Ascii("Siegel v2 reuse tag");
    internal static readonly byte[] DestructionInfo = Bytes.Ascii("Siegel v2 entry destruction");
    internal static readonly byte[] DestructibleKeyInfo = Bytes.Ascii("Siegel v2 entry key destructible");
    internal static readonly byte[] DestructibleAd = Bytes.Ascii("Siegel v2 entry destructible");

    // Windows-Hello-Art (W4.1)
    internal static readonly byte[] HelloChallengeLabel = Bytes.Ascii("Siegel v2 windows hello entry challenge");
    internal static readonly byte[] HelloRawLabel = Bytes.Ascii("Siegel v2 windows hello entry");
    internal static readonly byte[] HelloInfo = Bytes.Ascii("Siegel v2 entry windows hello");
    internal static readonly byte[] HelloDestructionInfo = Bytes.Ascii("Siegel v2 entry destruction windows hello");

    /// <summary>Schutz-Byte der Anker (Einträge haben 2…5).</summary>
    internal const byte AnchorProtection = 0;

    /// <summary>Polsterung der Geheimteile (verbirgt kleine Längenunterschiede auch vor dem Inhaber des DEK).</summary>
    internal const int SecretsBlock = 256;

    internal const int ReuseTagBytes = 16;

    /// <summary>Woher der Gerätefaktor eines Siegels kommt: Eintrags-Gerätefaktor (§16.1) oder Vernichtungsschlüssel V
    /// (§23.1), jeweils in der Mac-Art (P-256, <see cref="PublicKey"/>) oder der Windows-Hello-Art (ohne).</summary>
    internal sealed record SePart(bool Destruction, Guid KeyId, byte[]? PublicKey)
    {
        internal bool IsWindowsHello => PublicKey is null;

        internal byte[] Info => (Destruction, IsWindowsHello) switch
        {
            (false, false) => SeInfo,
            (false, true) => HelloInfo,
            (true, false) => DestructionInfo,
            (true, true) => HelloDestructionInfo,
        };

        internal byte[] KeyInfoLabel => Destruction ? DestructibleKeyInfo : KeyInfo;

        /// <summary>Faktoren, die für Einträge eingerichtet sein müssen (V ersetzt den Eintrags-Gerätefaktor).</summary>
        internal FactorSet Required(FactorSet mask) => Destruction ? mask & ~FactorSet.SecureEnclave : mask;

        /// <summary>Eintrags-Gerätefaktor des Inhalts (null = keiner eingerichtet).</summary>
        internal static SePart? ForEntries(EntryFactorKeys keys) =>
            keys.SecureEnclave is { } se ? new SePart(false, se.KeyId, se.PublicKey)
            : keys.WindowsHello is { } h ? new SePart(false, h.KeyId, null)
            : null;

        internal static SePart ForDestruction(DestructionConfig.VKeyInfo v) =>
            new(true, v.KeyId, v.IsWindowsHello ? null : v.PublicKey);
    }

    /// <summary>Öffentliches Material zum Versiegeln (kein Faktor nötig).</summary>
    internal sealed record Keys(byte[] VaultId, SecureBuffer Base, EntryFactorKeys Factors);

    internal static byte[] IdBytes(Guid id) => Bytes.OfGuid(id);

    internal static byte[] Ad(byte[] label, ReadOnlySpan<byte> vaultId, ReadOnlySpan<byte> id, byte s, FactorSet mask)
    {
        var w = new ByteWriter(label.Length + vaultId.Length + id.Length + 2);
        w.Write(label);
        w.Write(vaultId);
        w.Write(id);
        w.WriteByte(s);
        w.WriteByte((byte)mask);
        return w.ToArray();
    }

    /// <summary>Der Schutz verlangt eingerichtete Faktoren (§16): der erste fehlende in Ableitungsreihenfolge →
    /// <c>FactorMissing</c>.</summary>
    internal static void RequireEnrolled(FactorSet mask, EntryFactorKeys keys)
    {
        foreach (var kind in mask.Kinds())
        {
            if (!keys.Enrolled.Contains(kind)) { throw Fehler.FactorMissing(kind); }
        }
    }

    // MARK: Schlüssel

    internal static SecureBuffer BaseKey(SecureBuffer ebk, byte[] id) => Hkdf.Derive(ebk, id, DekInfo, 32);

    internal static SecureBuffer SeSecret(SecureBuffer ecdh, byte[] id, byte[] info)
    {
        if (ecdh.Length != 32) { throw Fehler.Crypto("entry.ecdh"); }
        return Hkdf.Derive(ecdh, id, info, 32);
    }

    /// <summary>K = HKDF-SHA512(base ‖ [ss_se] ‖ [ss_card] ‖ [ss_fido], salt = id, info = label ‖ s ‖ M, 32).</summary>
    internal static SecureBuffer EntryKey(IReadOnlyList<SecureBuffer> parts, byte[] id, byte s, FactorSet mask, byte[] info)
    {
        if (parts.Count != 1 + mask.Kinds().Count || parts.Any(p => p.Length != 32)) { throw Fehler.Crypto("entry.key"); }
        using var ikm = FactorKdf.Concatenate(parts);
        return Hkdf.Derive(ikm, id, [.. info, s, (byte)mask], 32);
    }

    /// <summary>Herausforderung der Windows-Hello-Art (32 Byte, nicht geheim).</summary>
    internal static byte[] HelloChallenge(ReadOnlySpan<byte> vaultId, Guid keyId, Guid id, ReadOnlySpan<byte> salt)
    {
        var w = new ByteWriter(HelloChallengeLabel.Length + 80);
        w.Write(HelloChallengeLabel);
        w.Write(vaultId);
        w.Write(Bytes.OfGuid(keyId));
        w.Write(Bytes.OfGuid(id));
        w.Write(salt);
        return SHA256.HashData(w.Written);
    }

    // MARK: Versiegeln (nur öffentliche Schlüssel; Windows Hello braucht das Material aus HelloSealing)

    /// <summary>Versiegelt <paramref name="plaintext"/> für Maske <paramref name="mask"/> (Eintrag: s = Schutz, Anker:
    /// s = 0) mit dem Eintrags-Gerätefaktor. Liefert Blob und K (gehört dem Aufrufer).</summary>
    internal static (SealedBlob Blob, SecureBuffer K) Seal(SecureBuffer plaintext, Guid id, byte s, FactorSet mask, byte[] adLabel,
        Keys keys, HelloSealing? hello) =>
        Seal(plaintext, id, s, mask, adLabel, keys, SePart.ForEntries(keys.Factors), hello);

    /// <summary>Vernichtbar versiegeln (§23.1): V statt Eintrags-Gerätefaktor, eigene Labels. Nur Schutz 4/5.</summary>
    internal static SealedBlob SealDestructible(SecureBuffer plaintext, Guid id, byte s, FactorSet mask, DestructionConfig.VKeyInfo v,
        Keys keys, HelloSealing? hello)
    {
        if (!mask.Contains(FactorKind.SecureEnclave) || !mask.Contains(FactorKind.Card)) { throw Fehler.NotAllowedAtLevel(); }
        var (blob, k) = Seal(plaintext, id, s, mask, DestructibleAd, keys, SePart.ForDestruction(v), hello);
        k.Dispose();
        return blob;
    }

    private static (SealedBlob Blob, SecureBuffer K) Seal(SecureBuffer plaintext, Guid id, byte s, FactorSet mask, byte[] adLabel,
        Keys keys, SePart? part, HelloSealing? hello)
    {
        RequireEnrolled(part?.Required(mask) ?? mask, keys.Factors);
        var idb = IdBytes(id);
        var parts = new List<SecureBuffer>();
        try
        {
            parts.Add(BaseKey(keys.Base, idb));
            byte[]? seEphemeral = null;
            HelloPart? helloPart = null;
            HybridCapsule? card = null;
            HybridCapsule? fido = null;
            if (mask.Contains(FactorKind.SecureEnclave))
            {
                if (part is null) { throw Fehler.FactorMissing(FactorKind.SecureEnclave); }
                if (part.PublicKey is { } pub)
                {
                    var (eph, shared) = P256.EphemeralAgreement(pub, "entry.sePublicKey");
                    using (shared) { parts.Add(SeSecret(shared, idb, part.Info)); }
                    seEphemeral = eph;
                }
                else
                {
                    // Windows Hello: ohne vorab geholte Signatur kein Versiegeln (W4.1).
                    if (hello is null) { throw Fehler.FactorMissing(FactorKind.SecureEnclave); }
                    var (salt, raw) = hello.Material(part.KeyId, id, keys.VaultId);
                    parts.Add(SeSecret(raw, idb, part.Info));
                    helloPart = new HelloPart(salt);
                }
            }
            if (mask.Contains(FactorKind.Card))
            {
                var c = keys.Factors.Card ?? throw Fehler.FactorMissing(FactorKind.Card);
                var enc = RecoveryKem.Encapsulate(c.Pk, CardLabel, idb);
                parts.Add(enc.Kek);
                card = new HybridCapsule(enc.CtM, enc.CtX);
            }
            if (mask.Contains(FactorKind.SecurityKey))
            {
                var k = keys.Factors.SecurityKey ?? throw Fehler.FactorMissing(FactorKind.SecurityKey);
                var enc = RecoveryKem.Encapsulate(k.Pk, FidoLabel, idb);
                parts.Add(enc.Kek);
                fido = new HybridCapsule(enc.CtM, enc.CtX);
            }
            var key = EntryKey(parts, idb, s, mask, part?.KeyInfoLabel ?? KeyInfo);
            try
            {
                var (nonce, ct) = Aead.Seal(key, plaintext, Ad(adLabel, keys.VaultId, idb, s, mask));
                return (new SealedBlob(new SealedFactors(seEphemeral, card, fido, helloPart), nonce, ct), key);
            }
            catch
            {
                key.Dispose();
                throw;
            }
        }
        finally
        {
            foreach (var p in parts) { p.Dispose(); }
        }
    }

    // MARK: Aufdecken (Faktoren über den Anbieter)

    /// <summary>Holt über den Anbieter genau die Faktoren der Maske (Reihenfolge Gerät, Karte, Schlüssel) und rechnet jeden
    /// sofort zu ss_… um; die Rohwerte werden danach freigegeben. Falsche Karte → <c>WrongCard</c>, falscher
    /// Sicherheitsschlüssel → <c>WrongPassword</c>. Liefert die ss-Werte (gehören dem Aufrufer).</summary>
    internal static async Task<List<SecureBuffer>> ReleaseAsync(SealedFactors factors, Guid id, FactorSet mask, EntryFactorKeys keys,
        byte[] vaultId, IEntryFactorProvider provider, SePart? part, CancellationToken cancellationToken)
    {
        RequireEnrolled(part?.Required(mask) ?? mask, keys);
        if (factors.Mask != mask) { throw Fehler.Corrupt("entry.sealed"); }
        var idb = IdBytes(id);
        var output = new List<SecureBuffer>();
        try
        {
            if (mask.Contains(FactorKind.SecureEnclave))
            {
                if (part is null) { throw Fehler.Corrupt("entry.sealed"); }
                if (!part.IsWindowsHello)
                {
                    var eph = factors.SeEphemeral ?? throw Fehler.Corrupt("entry.sealed");
                    using var raw = await Call(FactorKind.SecureEnclave,
                        () => provider.SecureEnclaveSharedSecretAsync(part.KeyId, eph, cancellationToken)).ConfigureAwait(false);
                    output.Add(SeSecret(raw.Storage, idb, part.Info));
                }
                else
                {
                    var hp = factors.Hello ?? throw Fehler.Corrupt("entry.sealed");
                    var challenge = HelloChallenge(vaultId, part.KeyId, id, hp.Salt);
                    using var raw = await Call(FactorKind.SecureEnclave,
                        () => provider.WindowsHelloSecretAsync(part.KeyId, challenge, cancellationToken)).ConfigureAwait(false);
                    output.Add(SeSecret(raw.Storage, idb, part.Info));
                }
            }
            if (mask.Contains(FactorKind.Card))
            {
                if (keys.Card is not { } card || factors.Card is not { } capsule) { throw Fehler.Corrupt("entry.sealed"); }
                using var q = await Call(FactorKind.Card, () => provider.CardSecretAsync(cancellationToken)).ConfigureAwait(false);
                if (!Bytes.ConstantTimeEqual(CardCode.TagBytesFor(q, vaultId), card.Tag)) { throw Fehler.WrongCard(); }
                using var sk = RecoveryKem.PrivateKeys(q.Storage, vaultId, EntryKeyDerivation.CardSeedInfo,
                    EntryKeyDerivation.CardX25519Info, card.Pk) ?? throw Fehler.WrongCard();
                output.Add(Decapsulate(sk, capsule, CardLabel, idb));
            }
            if (mask.Contains(FactorKind.SecurityKey))
            {
                if (keys.SecurityKey is not { } key || factors.Fido is not { } capsule) { throw Fehler.Corrupt("entry.sealed"); }
                using var y2 = await Call(FactorKind.SecurityKey,
                    () => provider.SecurityKeyOutputAsync(key.CredentialId, key.EntrySalt, cancellationToken)).ConfigureAwait(false);
                using var sk = RecoveryKem.PrivateKeys(y2.Storage, vaultId, EntryKeyDerivation.FidoSeedInfo,
                    EntryKeyDerivation.FidoX25519Info, key.Pk) ?? throw Fehler.WrongPassword();
                output.Add(Decapsulate(sk, capsule, FidoLabel, idb));
            }
            return output;
        }
        catch
        {
            foreach (var o in output) { o.Dispose(); }
            throw;
        }
    }

    /// <summary>Anbieter-Aufruf: SiegelException bleibt; Abbruch → <c>FactorCancelled</c>; alles andere →
    /// <c>FactorUnavailable(kind)</c> (fremde Fehlertexte gelangen nie nach aussen). Ein leeres Ergebnis ebenso.</summary>
    internal static async Task<FactorSecret> Call(FactorKind kind, Func<Task<FactorSecret>> body)
    {
        FactorSecret? result;
        try
        {
            result = await body().ConfigureAwait(false);
        }
        catch (SiegelException)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            throw Fehler.FactorCancelled();
        }
#pragma warning disable CA1031 // Jeder fremde Fehler des Anbieters wird bewusst auf einen festen Code abgebildet (SPEC §5).
        catch (Exception)
#pragma warning restore CA1031
        {
            throw Fehler.FactorUnavailable(kind);
        }
        return result ?? throw Fehler.FactorUnavailable(kind);
    }

    private static SecureBuffer Decapsulate(HybridPrivateKeys sk, HybridCapsule capsule, byte[] label, byte[] id)
    {
        try
        {
            return RecoveryKem.Decapsulate(sk, capsule.CtM, capsule.CtX, label, id);
        }
        catch (SiegelException)
        {
            throw Fehler.Corrupt("entry.sealed");
        }
    }

    /// <summary>Öffnet einen Blob mit den freigegebenen ss-Werten. null = ein Faktor stimmt nicht.</summary>
    internal static SecureBuffer? Open(SealedBlob blob, Guid id, byte s, FactorSet mask, byte[] adLabel, SecureBuffer ebk,
        byte[] vaultId, IReadOnlyList<SecureBuffer> released, byte[]? keyInfo = null)
    {
        var idb = IdBytes(id);
        using var b = BaseKey(ebk, idb);
        using var k = EntryKey([b, .. released], idb, s, mask, keyInfo ?? KeyInfo);
        return Aead.Open(k, blob.Nonce, blob.Ciphertext, Ad(adLabel, vaultId, idb, s, mask));
    }

    // MARK: Notfall-Umschläge und Gruppen

    /// <summary>K an die Notfall-Gruppe kapseln.</summary>
    internal static HybridWrap RecoveryWrap(SecureBuffer k, Guid id, byte s, FactorSet mask, RecoveryPublicKeys group, byte[] vaultId)
    {
        var idb = IdBytes(id);
        using var enc = RecoveryKem.Encapsulate(group, RecoveryLabel, idb);
        var wrapped = Aead.Wrap(enc.Kek, k, Ad(RecoveryLabel, vaultId, idb, s, mask));
        return new HybridWrap(new HybridCapsule(enc.CtM, enc.CtX), wrapped);
    }

    /// <summary>K aus dem Notfall-Umschlag (mit den privaten Schlüsseln der Gruppe). Jedes Scheitern →
    /// <c>CorruptFile("entry.recovery")</c>.</summary>
    internal static SecureBuffer OpenRecoveryWrap(HybridWrap w, Guid id, byte s, FactorSet mask, HybridPrivateKeys group, byte[] vaultId)
    {
        var idb = IdBytes(id);
        SecureBuffer kek;
        try
        {
            kek = RecoveryKem.Decapsulate(group, w.Capsule.CtM, w.Capsule.CtX, RecoveryLabel, idb);
        }
        catch (SiegelException)
        {
            throw Fehler.Corrupt("entry.recovery");
        }
        using (kek)
        {
            return Aead.Unwrap(kek, w.Wrapped, Ad(RecoveryLabel, vaultId, idb, s, mask)) ?? throw Fehler.Corrupt("entry.recovery");
        }
    }

    internal static RecoveryPublicKeys GroupPublicKeys(SecureBuffer ers, byte[] vaultId) =>
        RecoveryKem.DerivePublicKeys(ers, vaultId, GroupSeedInfo, GroupX25519Info);

    internal static HybridPrivateKeys? GroupPrivateKeys(SecureBuffer ers, byte[] vaultId, RecoveryPublicKeys expected) =>
        RecoveryKem.PrivateKeys(ers, vaultId, GroupSeedInfo, GroupX25519Info, expected);

    /// <summary>Neue Gruppe für eine Maske: ERS ziehen, Schlüsselpaar ableiten, ERS an das Kit kapseln und als Anker
    /// versiegeln. Die Kennung kommt aus <paramref name="hello"/> (stabil über die Runden der Windows-Hello-Art).</summary>
    internal static RecoveryGroup MakeGroup(FactorSet mask, Keys keys, RecoveryPublicKeys kit, HelloSealing? hello)
    {
        if (!VaultContent.ValidMasks.Contains(mask)) { throw Fehler.Crypto("entry.mask"); }
        var id = hello?.GroupId(mask) ?? Zufall.NewGuid();
        using var ers = SecureBuffer.Random(32);
        var pk = GroupPublicKeys(ers, keys.VaultId);
        var kitWrap = WrapToKit(ers, id, mask, kit, keys.VaultId);
        var (anchor, k) = Seal(ers, id, AnchorProtection, mask, AnchorAd, keys, hello);
        k.Dispose();
        return new RecoveryGroup(id, mask, pk, kitWrap, anchor);
    }

    /// <summary>ERS an das Kit (pkM/pkX des Kopfes) kapseln.</summary>
    internal static HybridWrap WrapToKit(SecureBuffer ers, Guid groupId, FactorSet mask, RecoveryPublicKeys kit, byte[] vaultId)
    {
        var gid = IdBytes(groupId);
        using var enc = RecoveryKem.Encapsulate(kit, KitLabel, gid);
        var wrapped = Aead.Wrap(enc.Kek, ers, Ad(KitLabel, vaultId, gid, AnchorProtection, mask));
        return new HybridWrap(new HybridCapsule(enc.CtM, enc.CtX), wrapped);
    }

    /// <summary>Private Kit-Schlüssel aus R (nur wenn R genau das Kit des Kopfes ergibt).</summary>
    internal static HybridPrivateKeys? KitPrivateKeys(SecureBuffer r, VaultHeader header) =>
        RecoveryKem.PrivateKeys(r, header.VaultId, RecoveryKem.SeedInfo, RecoveryKem.X25519Info, header.Pk);

    /// <summary>Notfall: private Schlüssel einer Gruppe über das Kit. Jedes Scheitern → <c>CorruptFile("entry.recovery")</c>.</summary>
    internal static HybridPrivateKeys OpenGroup(RecoveryGroup group, HybridPrivateKeys kit, byte[] vaultId)
    {
        var gid = IdBytes(group.Id);
        SecureBuffer kek;
        try
        {
            kek = RecoveryKem.Decapsulate(kit, group.Kit.Capsule.CtM, group.Kit.Capsule.CtX, KitLabel, gid);
        }
        catch (SiegelException)
        {
            throw Fehler.Corrupt("entry.recovery");
        }
        using (kek)
        {
            using var ers = Aead.Unwrap(kek, group.Kit.Wrapped, Ad(KitLabel, vaultId, gid, AnchorProtection, group.Mask))
                ?? throw Fehler.Corrupt("entry.recovery");
            return GroupPrivateKeys(ers, vaultId, group.Pk) ?? throw Fehler.Corrupt("entry.recovery");
        }
    }

    /// <summary>Anker freigeben: ERS einer Gruppe über die Faktoren ihrer Maske (eine Freigabe pro Gruppe).</summary>
    internal static async Task<SecureBuffer> ReleaseAnchorAsync(RecoveryGroup group, Keys keys, IEntryFactorProvider provider,
        CancellationToken cancellationToken)
    {
        var released = await ReleaseAsync(group.Anchor.Factors, group.Id, group.Mask, keys.Factors, keys.VaultId, provider,
            SePart.ForEntries(keys.Factors), cancellationToken).ConfigureAwait(false);
        SecureBuffer? ers;
        try
        {
            ers = Open(group.Anchor, group.Id, AnchorProtection, group.Mask, AnchorAd, keys.Base, keys.VaultId, released);
        }
        finally
        {
            foreach (var r in released) { r.Dispose(); }
        }
        if (ers is null) { throw Fehler.WrongPassword(); }
        using var check = ers.Length == 32 ? GroupPrivateKeys(ers, keys.VaultId, group.Pk) : null;
        if (check is null)
        {
            ers.Dispose();
            throw Fehler.Corrupt("entry.anchor");
        }
        return ers;
    }

    // MARK: Geheimteile als JSON (gepolstert, nur in SecureBuffer)

    /// <summary><c>{"history":[{"changed","password"}],"notes","password","totp"}</c> (sortiert, Swift-Zahlen), gepolstert
    /// auf Vielfache von 256 (immer ≥ 1 Byte).</summary>
    internal static SecureBuffer EncodeSecrets(EntrySecrets s)
    {
        using var w = new SecureJsonWriter();
        w.BeginObject();
        w.Key("history");
        w.BeginArray();
        foreach (var h in s.History)
        {
            w.BeginObject();
            w.Key("changed");
            w.Date(h.Changed);
            w.Key("password");
            w.String(h.Password);
            w.EndObject();
        }
        w.EndArray();
        w.Key("notes");
        w.String(s.Notes);
        w.Key("password");
        w.String(s.Password);
        w.Key("totp");
        w.String(s.Totp);
        w.EndObject();
        using var json = w.Borrow(out var unpadded);
        var padded = (unpadded / SecretsBlock + 1) * SecretsBlock;
        var buffer = SecureBuffer.Scratch(padded);
        try
        {
            using (var o = buffer.BorrowWritable())
            {
                json.Span[..unpadded].CopyTo(o.Span);
                Pad(o.Span, unpadded);
            }
            buffer.Freeze();
            return buffer;
        }
        catch
        {
            buffer.Dispose();
            throw;
        }
    }

    private static unsafe void Pad(Span<byte> buf, int unpadded)
    {
        Libsodium.EnsureReady();
        nuint result = 0;
        int rc;
        fixed (byte* p = buf)
        {
            rc = Libsodium.sodium_pad(&result, p, (nuint)unpadded, SecretsBlock, (nuint)buf.Length);
        }
        if (rc != 0 || result != (nuint)buf.Length) { throw Fehler.Io("entry.pad"); }
    }

    internal static unsafe EntrySecrets DecodeSecrets(SecureBuffer padded)
    {
        using var l = padded.Borrow();
        var buf = l.Span;
        if (buf.Length == 0 || buf.Length % SecretsBlock != 0) { throw Fehler.Corrupt("entry.padding"); }
        Libsodium.EnsureReady();
        nuint unpadded = 0;
        int rc;
        fixed (byte* p = buf)
        {
            rc = Libsodium.sodium_unpad(&unpadded, p, (nuint)buf.Length, SecretsBlock);
        }
        if (rc != 0) { throw Fehler.Corrupt("entry.padding"); }
        try
        {
            var o = JRead.Obj(JNode.Parse(buf[..(int)unpadded]));
            return new EntrySecrets
            {
                Password = JRead.Str(o.Required("password")),
                Notes = JRead.Str(o.Required("notes")),
                Totp = JRead.Str(o.Required("totp")),
                History = [.. JRead.Arr(o.Required("history")).Select(h =>
                {
                    var ho = JRead.Obj(h);
                    return new PasswordHistoryItem(JRead.Str(ho.Required("password")), JRead.Date(ho.Required("changed")));
                })],
            };
        }
        catch (SiegelException)
        {
            throw Fehler.Corrupt("entry.json");
        }
    }

    // MARK: Wiederverwendungs-Kennung (§17)

    /// <summary>HKDF-SHA512(EBK, info = "Siegel v2 reuse tag", 32), ohne Salz.</summary>
    internal static SecureBuffer ReuseKey(SecureBuffer ebk) => Hkdf.Derive(ebk, [], ReuseInfo, 32);

    /// <summary>reuseTag = crypto_generichash(key, OpaqueString(password))[0..&lt;16] (v4.4: dieselbe Abbildung wie das
    /// Master-Passwort). null bei leerem Passwort.</summary>
    internal static byte[]? ReuseTag(SecureBuffer key, string password)
    {
        if (password.Length == 0) { return null; }
        using var normalized = PasswordNormalizer.SecureBytes(password);
        return ReuseTagOfBytes(key, normalized);
    }

    /// <summary>Tag nach der Formel bis v4.3 (nur NFC). null, wenn er dem heutigen gleicht oder das Passwort leer ist.</summary>
    internal static byte[]? LegacyReuseTag(SecureBuffer key, string password)
    {
        if (password.Length == 0) { return null; }
        var nfc = PasswordNormalizer.NfcOnly(password);
        using var nfcBytes = PasswordNormalizer.Utf8(nfc);
        using var today = PasswordNormalizer.SecureBytes(password);
        if (nfcBytes.ConstantTimeEquals(today)) { return null; }
        return ReuseTagOfBytes(key, nfcBytes);
    }

    /// <summary>reuseTag schon normalisierter Bytes (Master-Passwort, §1.1). null bei leeren Bytes oder Fehler.</summary>
    internal static byte[]? ReuseTagOfBytes(SecureBuffer key, SecureBuffer bytes)
    {
        if (bytes.Length == 0) { return null; }
        try
        {
            using var t = MasterTag.Tag(key, bytes);
            using var l = t.Borrow();
            return l.Span[..ReuseTagBytes].ToArray();
        }
        catch (SiegelException)
        {
            return null;
        }
    }

    /// <summary>Metadaten zu einem (Klartext-)Passwort. <paramref name="previous"/> bleibt gültig, solange sich das
    /// Passwort nicht geändert hat; ohne frühere Metadaten gilt <paramref name="fallbackChanged"/> als letzte Änderung.</summary>
    internal static EntryMeta Meta(string password, EntryMeta? previous, SecureBuffer reuseKey, DateTimeOffset fallbackChanged,
        DateTimeOffset now)
    {
        var tag = ReuseTag(reuseKey, password);
        if (previous is not null && Bytes.Same(previous.Tag, tag) && (tag is null || previous.Strength is not null))
        {
            return previous;
        }
        // Tag noch nach der Formel bis v4.3 (v4.4): dasselbe Passwort, nur neu gerechnet – keine Passwortänderung.
        if (previous is { Tag: { } old } && LegacyReuseTag(reuseKey, password) is { } legacy && Bytes.ConstantTimeEqual(old, legacy))
        {
            var p = previous with { Tag = tag };
            if (p.Strength is not null) { return p; }
            previous = p;
        }
        int? strength = tag is null ? null : (int)PasswordStrength.Estimate(password).Level;
        var changed = previous is not null && !Bytes.Same(previous.Tag, tag) ? now : previous?.Changed ?? fallbackChanged;
        return new EntryMeta(tag, strength, Clock.Canonical(changed));
    }
}

/// <summary>Interne Meldung: Für die Windows-Hello-Art fehlen noch Signaturen; nichts wurde geschrieben. Der async-Weg holt
/// sie über den Anbieter und wiederholt die Änderung.</summary>
internal sealed class HelloMaterialNeededException : Exception
{
    internal HelloMaterialNeededException() : base("hello.material")
    {
    }
}

/// <summary>
/// Material der Windows-Hello-Art beim Versiegeln (W4.1). Eine Änderung läuft zuerst „sammelnd“: Wo eine Signatur fehlt,
/// merkt sich das Objekt die Anfrage (Schlüssel, Kennung, frisches Salz) und liefert einen Wegwerf-Wert; danach bricht
/// die Änderung ohne Schreiben ab (<see cref="HelloMaterialNeededException"/>). Der async-Weg holt alle Signaturen und
/// wiederholt die Änderung mit denselben Salzen und Gruppen-Kennungen. Besitzt alle Rohwerte (Dispose nullt).
/// </summary>
internal sealed class HelloSealing : IDisposable
{
    private readonly Lock gate = new();
    private readonly Dictionary<(Guid KeyId, Guid Id), (byte[] Salt, SecureBuffer Raw)> supplied = [];
    private readonly Dictionary<(Guid KeyId, Guid Id), (byte[] Salt, byte[] VaultId)> requests = [];
    private readonly Dictionary<FactorSet, Guid> groupIds = [];
    private readonly List<SecureBuffer> dummies = [];

    internal bool HasRequests
    {
        get { lock (gate) { return requests.Count > 0; } }
    }

    private readonly Dictionary<(Guid Original, int Index), Guid> replacementIds = [];

    /// <summary>Ersatz-Kennung für einen importierten Eintrag, dessen Kennung schon vergeben ist (über alle Runden gleich,
    /// Befund krypto-3). <paramref name="index"/> = Stelle im Import, damit gleiche Kennungen getrennt bleiben.</summary>
    internal Guid ReplacementId(Guid original, int index)
    {
        lock (gate)
        {
            if (!replacementIds.TryGetValue((original, index), out var id))
            {
                id = Zufall.NewGuid();
                replacementIds[(original, index)] = id;
            }
            return id;
        }
    }

    /// <summary>Kennung einer neuen Gruppe für diese Maske (über alle Runden gleich).</summary>
    internal Guid GroupId(FactorSet mask)
    {
        lock (gate)
        {
            if (!groupIds.TryGetValue(mask, out var id))
            {
                id = Zufall.NewGuid();
                groupIds[mask] = id;
            }
            return id;
        }
    }

    /// <summary>Salz und Rohwert für (Schlüssel, Kennung); fehlt er noch, eine Anfrage und ein Wegwerf-Wert. Der Puffer
    /// gehört diesem Objekt.</summary>
    internal (byte[] Salt, SecureBuffer Raw) Material(Guid keyId, Guid id, byte[] vaultId)
    {
        lock (gate)
        {
            if (supplied.TryGetValue((keyId, id), out var m)) { return m; }
            if (!requests.TryGetValue((keyId, id), out var r))
            {
                r = (Zufall.Bytes(HelloPart.SaltBytes), vaultId);
                requests[(keyId, id)] = r;
            }
            var dummy = SecureBuffer.Random(32);
            dummies.Add(dummy);
            return (r.Salt, dummy);
        }
    }

    /// <summary>Alle offenen Anfragen über den Anbieter beantworten (eine Signatur je Kennung).</summary>
    internal async Task FetchAsync(IEntryFactorProvider provider, CancellationToken cancellationToken)
    {
        List<KeyValuePair<(Guid KeyId, Guid Id), (byte[] Salt, byte[] VaultId)>> open;
        lock (gate)
        {
            open = [.. requests];
        }
        foreach (var (key, (salt, vaultId)) in open)
        {
            var challenge = EntrySealing.HelloChallenge(vaultId, key.KeyId, key.Id, salt);
            var raw = await EntrySealing.Call(FactorKind.SecureEnclave,
                () => provider.WindowsHelloSecretAsync(key.KeyId, challenge, cancellationToken)).ConfigureAwait(false);
            lock (gate)
            {
                requests.Remove(key);
                if (supplied.Remove(key, out var old)) { old.Raw.Dispose(); }
                supplied[key] = (salt, raw.Storage);
            }
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            foreach (var m in supplied.Values) { m.Raw.Dispose(); }
            supplied.Clear();
            foreach (var d in dummies) { d.Dispose(); }
            dummies.Clear();
            requests.Clear();
        }
    }
}
