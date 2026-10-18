using Siegel.Modell;

namespace Siegel.Core;

// Eintrags-Schutz im Inhalt (SPEC §16, §17, §23.1): versiegeln, Notfall-Gruppen pflegen, mit dem Notfallcode alles
// entsiegeln, Metadaten für den Bericht – wie VaultContent+Schutz.swift und VaultContent+Vernichtung.swift. Alle
// Methoden ändern genau diesen Inhalt (die Aufrufer arbeiten auf Kopien, transaktional).
internal sealed partial class VaultContent
{
    // MARK: Schlüssel

    /// <summary>Grundschlüssel sicherstellen (ältere Inhalte haben keinen; er entsteht beim ersten Speichern).</summary>
    internal SecureBuffer EnsureEntryKey()
    {
        EntryKey ??= EntryBaseKey.Generate();
        return EntryKey.Key;
    }

    internal EntrySealing.Keys SealingKeys(byte[] vaultId) =>
        new(vaultId, (EntryKey ?? throw Fehler.Crypto("entry.baseKey")).Key, EntryFactors);

    /// <summary>Schlüssel des reuseTag (gehört dem Aufrufer).</summary>
    internal SecureBuffer ReuseKey() => EntrySealing.ReuseKey((EntryKey ?? throw Fehler.Crypto("entry.baseKey")).Key);

    /// <summary>reuseTags des Master-Passworts (§17, v4.4); leer ohne Grundschlüssel. Zuerst der Tag der normalisierten
    /// Bytes; enthält die rohe Eingabe ein Zs-Zeichen ausser U+0020, dazu der Tag nach der Formel bis v4.3.</summary>
    internal List<byte[]> MasterReuseTags(SecureBuffer password, string? raw)
    {
        if (EntryKey is null) { return []; }
        using var rk = ReuseKey();
        var output = new List<byte[]>();
        if (EntrySealing.ReuseTagOfBytes(rk, password) is { } t) { output.Add(t); }
        if (raw is not null && EntrySealing.LegacyReuseTag(rk, raw) is { } legacy) { output.Add(legacy); }
        return output;
    }

    /// <summary>Faktorarten, an denen versiegelte Einträge hängen (vernichtbare hängen statt am Eintrags-Gerätefaktor an V).</summary>
    internal FactorSet SealedKinds
    {
        get
        {
            var s = FactorSet.None;
            foreach (var e in Entries.Where(e => e.SecretsSealed))
            {
                var mask = e.Protection.Factors();
                s |= Destructible.ContainsKey(e.Id) ? mask & ~FactorSet.SecureEnclave : mask;
            }
            return s;
        }
    }

    /// <summary>Gruppen, die versiegelte Einträge brauchen (in Maskenreihenfolge). Vernichtbare haben keinen Umschlag.</summary>
    internal List<RecoveryGroup> NeededRecoveryGroups
    {
        get
        {
            var used = new HashSet<FactorSet>();
            foreach (var e in Entries.Where(e => e.SecretsSealed && !Destructible.ContainsKey(e.Id))) { used.Add(e.Protection.Factors()); }
            return [.. RecoveryGroups.Where(g => used.Contains(g.Mask)).OrderBy(g => (byte)g.Mask)];
        }
    }

    /// <summary>Kennungen der vernichtbaren Einträge (auch gelöschte).</summary>
    internal HashSet<Guid> DestructibleIds => [.. Destructible.Keys];

    // MARK: Versiegeln

    /// <summary>Geheimteile von <c>Entries[i]</c> (Klartext) mit dessen Schutz versiegeln: Metadaten (§17), Blob,
    /// Notfall-Umschlag an die Gruppe der Maske (neu, falls es noch keine gibt). Danach sind die Felder leer.</summary>
    internal void Seal(int i, byte[] vaultId, RecoveryPublicKeys kit, DateTimeOffset now, HelloSealing? hello)
    {
        var e = Entries[i];
        var p = e.Protection;
        if (p <= EntryProtection.Normal || e.SecretsSealed) { throw Fehler.Crypto("entry.sealedState"); }
        var mask = p.Factors();
        EntrySealing.RequireEnrolled(mask, EntryFactors);
        EnsureEntryKey();
        var keys = SealingKeys(vaultId);
        using (var rk = EntrySealing.ReuseKey(keys.Base))
        {
            Meta[e.Id] = EntrySealing.Meta(e.Password, Meta.GetValueOrDefault(e.Id), rk, EstimatedPasswordChange(e), now);
        }
        using var plaintext = EntrySealing.EncodeSecrets(SecretsOf(e));
        var s = (byte)p;
        var (blob, k) = EntrySealing.Seal(plaintext, e.Id, s, mask, EntrySealing.EntryAd, keys, hello);
        using (k)
        {
            var group = RecoveryGroupFor(mask, keys, kit, hello);
            var recovery = EntrySealing.RecoveryWrap(k, e.Id, s, mask, group.Pk, vaultId);
            Sealed[e.Id] = new SealedSecrets(blob, recovery);
        }
        ClearSecrets(e);
    }

    private RecoveryGroup RecoveryGroupFor(FactorSet mask, EntrySealing.Keys keys, RecoveryPublicKeys kit, HelloSealing? hello)
    {
        if (RecoveryGroups.FirstOrDefault(g => g.Mask == mask) is { } existing) { return existing; }
        var g = EntrySealing.MakeGroup(mask, keys, kit, hello);
        RecoveryGroups.Add(g);
        return g;
    }

    /// <summary>Geheimteile von <c>Entries[i]</c> (Klartext, Schutz 4/5) vernichtbar versiegeln: an V, ohne Umschlag
    /// (§23.1). Stufe/Schutz &lt; 4 → <c>NotAllowedAtLevel</c>; kein V → <c>FactorMissing(secureEnclave)</c>.</summary>
    internal void SealDestructible(int i, byte[] vaultId, DateTimeOffset now, HelloSealing? hello)
    {
        var e = Entries[i];
        var p = e.Protection;
        if (e.SecretsSealed) { throw Fehler.Crypto("entry.sealedState"); }
        if (p < EntryProtection.Maximal || Level < SecurityLevel.Maximal) { throw Fehler.NotAllowedAtLevel(); }
        var v = Destruction?.VKey ?? throw Fehler.FactorMissing(FactorKind.SecureEnclave);
        var mask = p.Factors();
        EntrySealing.RequireEnrolled(mask & ~FactorSet.SecureEnclave, EntryFactors);
        EnsureEntryKey();
        var keys = SealingKeys(vaultId);
        using (var rk = EntrySealing.ReuseKey(keys.Base))
        {
            Meta[e.Id] = EntrySealing.Meta(e.Password, Meta.GetValueOrDefault(e.Id), rk, EstimatedPasswordChange(e), now);
        }
        using var plaintext = EntrySealing.EncodeSecrets(SecretsOf(e));
        var blob = EntrySealing.SealDestructible(plaintext, e.Id, (byte)p, mask, v, keys, hello);
        Sealed.Remove(e.Id);
        Destructible[e.Id] = blob;
        ClearSecrets(e);
    }

    private static void ClearSecrets(VaultEntry e)
    {
        e.Password = "";
        e.Notes = "";
        e.Totp = "";
        e.History = [];
        e.SecretsSealed = true;
    }

    internal static EntrySecrets SecretsOf(VaultEntry e) =>
        new() { Password = e.Password, Notes = e.Notes, Totp = e.Totp, History = [.. e.History] };

    /// <summary>Geheimteile in <c>Entries[i]</c> einsetzen (offen, beide Siegel entfernt); danach neu versiegeln.</summary>
    internal void ReplaceSecrets(int i, EntrySecrets s)
    {
        var id = Entries[i].Id;
        Entries[i] = Unsealed(Entries[i], s);
        Sealed.Remove(id);
        Destructible.Remove(id);
    }

    /// <summary>Letzte Passwortänderung ohne Metadaten: jüngster Verlaufseintrag, sonst das Anlegen.</summary>
    internal static DateTimeOffset EstimatedPasswordChange(VaultEntry e) =>
        e.History.Count > 0 ? e.History.Max(h => h.Changed) : e.Created;

    /// <summary>Kopie mit aufgedeckten Geheimteilen (Schutz bleibt, <c>SecretsSealed</c> aus).</summary>
    internal static VaultEntry Unsealed(VaultEntry e, EntrySecrets s)
    {
        var output = e.Copy();
        output.Password = s.Password;
        output.Notes = s.Notes;
        output.Totp = s.Totp;
        output.History = [.. s.History];
        output.SecretsSealed = false;
        return output;
    }

    // MARK: Notfall: alles entsiegeln

    /// <summary>Mit R alle versiegelten Einträge entsiegeln: Kit → Gruppen → Umschläge → Blobs. Vernichtbare Einträge
    /// fallen ganz weg (kein Notfallweg, §23.1). Nach bestandener Kit-Prüfung ist jedes Scheitern
    /// <c>CorruptFile("entry.recovery")</c>.</summary>
    internal void UnsealAll(SecureBuffer r, VaultHeader header)
    {
        DropDestructibleEntries();
        var needed = NeededRecoveryGroups;
        if (needed.Count > 0)
        {
            using var kitKeys = EntrySealing.KitPrivateKeys(r, header) ?? throw Fehler.Corrupt("entry.recovery");
            var groupKeys = new Dictionary<FactorSet, HybridPrivateKeys>();
            try
            {
                foreach (var g in needed) { groupKeys[g.Mask] = EntrySealing.OpenGroup(g, kitKeys, header.VaultId); }
                for (var i = 0; i < Entries.Count; i++)
                {
                    var e = Entries[i];
                    if (!e.SecretsSealed) { continue; }
                    if (!Sealed.TryGetValue(e.Id, out var x) || !groupKeys.TryGetValue(e.Protection.Factors(), out var gk))
                    {
                        throw Fehler.Corrupt("entry.recovery");
                    }
                    Entries[i] = Unsealed(e, OpenViaGroup(x, e, gk, header.VaultId));
                }
            }
            finally
            {
                foreach (var k in groupKeys.Values) { k.Dispose(); }
            }
        }
        if (Entries.Any(e => e.SecretsSealed)) { throw Fehler.Corrupt("entry.recovery"); }
        Sealed = [];
        RecoveryGroups = [];
    }

    /// <summary>Vernichtbare Einträge samt Metadaten entfernen und die Selbstvernichtung ausschalten.</summary>
    internal void DropDestructibleEntries()
    {
        var doomed = DestructibleIds;
        if (doomed.Count > 0)
        {
            Entries.RemoveAll(e => doomed.Contains(e.Id));
            foreach (var id in doomed) { Meta.Remove(id); }
        }
        Destructible = [];
        Destruction = null;
    }

    /// <summary>Geheimteile über den Notfall-Umschlag (Gruppen-Schlüssel statt Faktoren).</summary>
    internal static EntrySecrets OpenViaGroup(SealedSecrets x, VaultEntry e, HybridPrivateKeys group, byte[] vaultId)
    {
        var s = (byte)e.Protection;
        var mask = e.Protection.Factors();
        using var k = EntrySealing.OpenRecoveryWrap(x.Recovery, e.Id, s, mask, group, vaultId);
        using var padded = Aead.Open(k, x.Blob.Nonce, x.Blob.Ciphertext,
            EntrySealing.Ad(EntrySealing.EntryAd, vaultId, EntrySealing.IdBytes(e.Id), s, mask)) ?? throw Fehler.Corrupt("entry.recovery");
        return EntrySealing.DecodeSecrets(padded);
    }

    /// <summary>Geheimteile versiegelter Einträge über freigegebene Gruppen (ERS je Gruppen-Kennung).</summary>
    internal Dictionary<Guid, EntrySecrets> SecretsViaGroups(IEnumerable<VaultEntry> list, IReadOnlyDictionary<Guid, SecureBuffer> released,
        byte[] vaultId)
    {
        var keysByMask = new Dictionary<FactorSet, HybridPrivateKeys>();
        var output = new Dictionary<Guid, EntrySecrets>();
        try
        {
            foreach (var e in list.Where(e => e.SecretsSealed))
            {
                var mask = e.Protection.Factors();
                if (!Sealed.TryGetValue(e.Id, out var x) || RecoveryGroups.FirstOrDefault(g => g.Mask == mask) is not { } g)
                {
                    throw Fehler.Corrupt("entry.sealed");
                }
                if (!keysByMask.TryGetValue(mask, out var gk))
                {
                    if (!released.TryGetValue(g.Id, out var ers)) { throw Fehler.FactorMissing(mask.Kinds()[0]); }
                    gk = EntrySealing.GroupPrivateKeys(ers, vaultId, g.Pk) ?? throw Fehler.Corrupt("entry.anchor");
                    keysByMask[mask] = gk;
                }
                output[e.Id] = OpenViaGroup(x, e, gk, vaultId);
            }
            return output;
        }
        finally
        {
            foreach (var k in keysByMask.Values) { k.Dispose(); }
        }
    }

    /// <summary>Neues Kit: alle gebrauchten Gruppen an die neuen öffentlichen Schlüssel kapseln (ERS je Gruppe aus der
    /// Freigabe der Anker). Fehlt eine Freigabe → <c>FactorMissing</c>. Ungebrauchte Gruppen fallen weg.</summary>
    internal void RewrapRecoveryGroups(IReadOnlyDictionary<Guid, SecureBuffer> released, RecoveryPublicKeys kit, byte[] vaultId)
    {
        PruneRecoveryGroups();
        for (var i = 0; i < RecoveryGroups.Count; i++)
        {
            var g = RecoveryGroups[i];
            if (!released.TryGetValue(g.Id, out var ers)) { throw Fehler.FactorMissing(g.Mask.Kinds()[0]); }
            using (var check = EntrySealing.GroupPrivateKeys(ers, vaultId, g.Pk))
            {
                if (check is null) { throw Fehler.Corrupt("entry.anchor"); }
            }
            RecoveryGroups[i] = g with { Kit = EntrySealing.WrapToKit(ers, g.Id, g.Mask, kit, vaultId) };
        }
    }

    internal void PruneRecoveryGroups()
    {
        var needed = NeededRecoveryGroups.Select(g => g.Id).ToHashSet();
        RecoveryGroups.RemoveAll(g => !needed.Contains(g.Id));
    }

    /// <summary>Kommt das (normalisierte) Passwort als aktuelles Passwort eines versiegelten Eintrags vor (über reuseTag)?</summary>
    internal bool IsUsedBySealedEntries(SecureBuffer password, string? raw)
    {
        var tags = MasterReuseTags(password, raw);
        if (tags.Count == 0) { return false; }
        return Entries.Any(e => e.SecretsSealed && Meta.GetValueOrDefault(e.Id)?.Tag is { } tag
            && tags.Any(t => Bytes.ConstantTimeEqual(tag, t)));
    }

    // MARK: Speichern

    /// <summary>Vor jedem Speichern (nach <see cref="PrepareForSave"/>): Grundschlüssel sicherstellen, verwaiste Teile und
    /// ungebrauchte Gruppen entfernen, Metadaten offener Einträge nachführen.</summary>
    internal void PrepareEntryData(DateTimeOffset now)
    {
        EnsureEntryKey();
        var ids = Entries.Select(e => e.Id).ToHashSet();
        Sealed = Sealed.Where(p => ids.Contains(p.Key)).ToDictionary(p => p.Key, p => p.Value);
        Destructible = Destructible.Where(p => ids.Contains(p.Key)).ToDictionary(p => p.Key, p => p.Value);
        Meta = Meta.Where(p => ids.Contains(p.Key)).ToDictionary(p => p.Key, p => p.Value);
        if (Destruction?.IsEmpty == true) { Destruction = null; }
        PruneRecoveryGroups();
        using var rk = ReuseKey();
        foreach (var e in Entries.Where(e => !e.SecretsSealed))
        {
            Meta[e.Id] = EntrySealing.Meta(e.Password, Meta.GetValueOrDefault(e.Id), rk, EstimatedPasswordChange(e), now);
        }
    }
}
