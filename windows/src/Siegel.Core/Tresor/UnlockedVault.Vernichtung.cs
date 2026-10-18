using Siegel.Modell;

namespace Siegel.Core;

// Selbstvernichtung im entsperrten Tresor (SPEC §23.3): Einstellungen, Markierung vernichtbarer Einträge,
// Vernichtungs-Passwort, vernichtete Einträge entfernen, Vernichtungs-Sitzung – wie UnlockedVault+Vernichtung.swift.
public sealed partial class UnlockedVault
{
    private bool TryEnter(out Scope scope)
    {
        try
        {
            scope = Enter();
            return true;
        }
        catch (SiegelException)
        {
            scope = default;
            return false;
        }
    }

    // MARK: Lesen

    /// <summary>Vernichtete Einträge (nur in einer echten Sitzung gefüllt): die vernichtbaren, deren V vernichtet ist. Sie
    /// stehen weiter in <see cref="Entries"/>, lassen sich nicht mehr aufdecken und nur noch entfernen.</summary>
    public IReadOnlyList<Guid> DestroyedEntries
    {
        get
        {
            if (IsDuressSession || !TryEnter(out var scope)) { return []; }
            using (scope)
            {
                var c = scope.State.Content;
                return DestructionKeyDestroyed(c) ? [.. c.Entries.Where(e => c.Destructible.ContainsKey(e.Id)).Select(e => e.Id)] : [];
            }
        }
    }

    /// <summary>Einstellungen der Selbstvernichtung aus dem verschlüsselten Inhalt (massgeblich).</summary>
    public DestructionSettings DestructionSettings
    {
        get
        {
            if (!TryEnter(out var scope)) { return DestructionSettings.Off; }
            using (scope)
            {
                return scope.State.Content.Destruction?.Settings ?? DestructionSettings.Off;
            }
        }
    }

    /// <summary>Als vernichtbar markierte Einträge (in einer Vernichtungs-Sitzung leer).</summary>
    public IReadOnlySet<Guid> DestructibleEntries
    {
        get
        {
            if (!TryEnter(out var scope)) { return new HashSet<Guid>(); }
            using (scope)
            {
                return scope.State.Content.DestructibleIds.Except(HiddenEntries).ToHashSet();
            }
        }
    }

    /// <summary>Kennung des eingerichteten V (null = keiner oder schon vernichtet; in einer Vernichtungs-Sitzung der
    /// bisherige, damit nichts auffällt).</summary>
    public Guid? DestructionKeyId
    {
        get
        {
            if (!TryEnter(out var scope)) { return null; }
            using (scope)
            {
                var c = scope.State.Content;
                return c.Destruction?.VKey is { } v && (IsDuressSession || !DestructionKeyDestroyed(c)) ? v.KeyId : null;
            }
        }
    }

    /// <summary>Wie <see cref="VaultStore.GetDestructionStatus"/>, aber passend zur Sitzung: Einstellungen aus dem Inhalt,
    /// in einer Vernichtungs-Sitzung ohne Vermerk der Vernichtung.</summary>
    public DestructionStatus DestructionStatus
    {
        get
        {
            var st = Store.GetDestructionStatus();
            var settings = DestructionSettings;
            DateTimeOffset? deadline = settings.DeadmanDays is { } days && st.LastGenuineUnlock is { } last
                ? Clock.AddDaysSaturating(last, days) : null;
            return new DestructionStatus(settings, st.LastGenuineUnlock, st.FailedAttempts, deadline,
                IsDuressSession ? null : st.DestroyedTrigger, IsDuressSession ? null : st.DestroyedAt,
                st.KeyConfigured || DestructionKeyId is not null);
        }
    }

    // MARK: Einrichten (§23.3)

    /// <summary>
    /// Selbstvernichtung einstellen (nur Stufe 4/5). Braucht Master-Passwort und alle Faktoren der Stufe.
    /// <paramref name="duressPassword"/>: neues Vernichtungs-Passwort (nur mit <c>DuressEnabled</c>; null = bisheriges).
    /// <paramref name="destructible"/>: die ganze neue Auswahl (Schutz 4/5). Markieren/Entmarkieren versiegelt neu und
    /// braucht die Geheimteile → <see cref="ConfigureDestructionAsync"/>; hier <c>FactorMissing(secureEnclave)</c>.
    /// <paramref name="vKey"/>: neues V (null = bisheriges). In einer Vernichtungs-Sitzung → <c>WrongPassword</c> (nach
    /// gleich langer Rechnung). Werden Einträge neu markiert, entfernt der Kern danach alle älteren Sicherungen (Bericht;
    /// null = nichts entfernt). Nach dem Schreiben wirft es nicht mehr (Befund datei-1).
    /// </summary>
    public PurgeReport? ConfigureDestruction(DestructionSettings settings, string? duressPassword, IReadOnlySet<Guid> destructible,
        string masterPassword, FactorSecrets factors, EntryKeyEnrollment? vKey) =>
        ConfigureDestruction(settings, duressPassword, destructible, masterPassword, factors, vKey, new Dictionary<Guid, OpenedEntry>(), null, null);

    /// <summary>Wie <see cref="ConfigureDestruction(DestructionSettings, string?, IReadOnlySet{Guid}, string, FactorSecrets, EntryKeyEnrollment?)"/>;
    /// neu zu versiegelnde Einträge werden vorher über <paramref name="entryFactors"/> geöffnet (neu markierte über ihre
    /// Notfall-Gruppe, entmarkierte einzeln über V). Passwort und Faktoren werden zuerst geprüft. Mit der
    /// Windows-Hello-Art holt es zusätzlich die Signaturen fürs Versiegeln.</summary>
    public async Task<PurgeReport?> ConfigureDestructionAsync(DestructionSettings settings, string? duressPassword, IReadOnlySet<Guid> destructible,
        string masterPassword, FactorSecrets factors, EntryKeyEnrollment? vKey, IEntryFactorProvider? entryFactors,
        CancellationToken cancellationToken = default)
    {
        var request = new DestructionRequest(settings, duressPassword, destructible, masterPassword, vKey);
        Fehler.NotNull(factors);
        var opened = new Dictionary<Guid, OpenedEntry>();
        byte[]? verified = null;
        using (var scope = Enter())
        {
            var st = scope.State;
            if (!IsDuressSession)
            {
                var plan = PlanDestruction(request, st);
                var sealedNeeds = plan.Reseal.Where(id => st.Content.Entries.Any(e => e.Id == id && e.SecretsSealed)).ToHashSet();
                if (sealedNeeds.Count > 0)
                {
                    if (entryFactors is null) { throw Fehler.FactorMissing(FactorKind.SecureEnclave); }
                    await InBackground(() =>
                    {
                        using var pw = PasswordNormalizer.SecureBytes(masterPassword);
                        VerifyAccess(pw, factors, st);
                    }, cancellationToken).ConfigureAwait(false);
                    verified = st.Header.Salt;
                    using var caching = new CachingEntryFactors(entryFactors);
                    opened = await OpenForResealingAsync(sealedNeeds, st, caching, cancellationToken).ConfigureAwait(false);
                    if (IsLocked) { throw Fehler.Locked(); }
                }
            }
        }
        var salt = verified;
        return await WithHelloAsync(h => ConfigureDestruction(settings, duressPassword, destructible, masterPassword, factors, vKey, opened, salt, h),
            entryFactors, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Geheimteile eines Eintrags, geöffnet aus genau diesem Siegel (ändert sich der Eintrag inzwischen, gilt es
    /// nicht mehr).</summary>
    internal sealed record OpenedEntry(EntrySecrets Secrets, SealedSecrets? Sealed, SealedBlob? Destructible);

    /// <summary>Kern: <paramref name="opened"/> = Geheimteile der neu zu versiegelnden; <paramref name="verifiedSalt"/> =
    /// Zugang für genau diesen Kopf schon geprüft. Seit dem Öffnen geändert → <c>Io("entry.stale")</c>.</summary>
    internal PurgeReport? ConfigureDestruction(DestructionSettings settings, string? duressPassword, IReadOnlySet<Guid> destructible,
        string masterPassword, FactorSecrets factors, EntryKeyEnrollment? vKey, IReadOnlyDictionary<Guid, OpenedEntry> opened, byte[]? verifiedSalt,
        HelloSealing? hello)
    {
        CoreEnvironment.RequireBackgroundThread();
        var request = new DestructionRequest(settings, duressPassword, destructible, masterPassword, vKey);
        Fehler.NotNull(factors);
        using var pw = PasswordNormalizer.SecureBytes(masterPassword);
        lock (WriteLock)
        {
            using var scope = Enter();
            var st = scope.State;
            if (IsDuressSession)
            {
                // Gleich lange Rechnung wie eine echte Prüfung; das Vernichtungs-Passwort ist kein Master-Passwort.
                try
                {
                    VerifyAccess(pw, factors, st);
                }
                catch (SiegelException)
                {
                    // gleich behandelt
                }
                throw Fehler.WrongPassword();
            }
            var plan = PlanDestruction(request, st);
            if (verifiedSalt is null || !verifiedSalt.AsSpan().SequenceEqual(st.Header.Salt)) { VerifyAccess(pw, factors, st); }

            using var content = st.Content.Clone();
            DestructionConfig? config = null;
            if (plan.Active)
            {
                DestructionConfig.DuressInfo? duress = null;
                if (settings.DuressEnabled)
                {
                    duress = duressPassword is not null ? MakeDuress(duressPassword, st.Header.VaultId, st.Header.Kdf) : st.Content.Destruction?.Duress;
                }
                config = new DestructionConfig(settings, plan.VKey, duress);
            }
            content.Destruction = config;
            var now = Clock.Now();
            for (var i = 0; i < content.Entries.Count; i++)
            {
                var e = content.Entries[i];
                if (!plan.Reseal.Contains(e.Id)) { continue; }
                if (e.SecretsSealed)
                {
                    if (!opened.TryGetValue(e.Id, out var o)) { throw Fehler.FactorMissing(FactorKind.SecureEnclave); }
                    if (!Equals(o.Sealed, content.Sealed.GetValueOrDefault(e.Id)) || !Equals(o.Destructible, content.Destructible.GetValueOrDefault(e.Id)))
                    {
                        throw Fehler.Io("entry.stale");
                    }
                    content.ReplaceSecrets(i, o.Secrets);
                }
                else
                {
                    content.ReplaceSecrets(i, VaultContent.SecretsOf(e));
                }
                if (destructible.Contains(e.Id))
                {
                    content.SealDestructible(i, st.Header.VaultId, now, hello);
                }
                else
                {
                    content.Seal(i, st.Header.VaultId, st.Header.Pk, now, hello);
                }
            }
            if (content.Destruction?.IsEmpty == true) { content.Destruction = null; }
            if (hello?.HasRequests == true) { throw new HelloMaterialNeededException(); }
            // Inzwischen gesperrt? Dann nichts schreiben (Befund datei-1); Save/RekeyAndSave prüfen es nochmals.
            RequireUnlocked();
            ulong generation;
            if (st.Content.Destruction?.Duress is { } oldDuress && oldDuress.FileId != content.Destruction?.Duress?.FileId)
            {
                // Vernichtungs-Passwort ersetzt oder entfernt: ein Zugangswechsel (§1.2, v4.4) – neuer DEK.
                generation = RekeyAndSave(st, content, pw, factors);
            }
            else
            {
                generation = Save(st, content, null);
            }

            // Ab hier ist die Datei geschrieben: nichts wirft mehr (Befund datei-1).
            if (st.Content.Destruction?.VKey is { } oldV && oldV.KeyId != plan.VKey?.KeyId) { Store.EraseDestructionKey(oldV.KeyId); }
            if (plan.VKey is { } v)
            {
                try
                {
                    var path = Store.HardwareKeyPath(v.KeyId);
                    if (FileIO.Exists(path)) { FileIO.ExcludeFromIndexing(path); }
                }
                catch (SiegelException)
                {
                    // bestes Bemühen
                }
            }
            if (!plan.NewlyMarked) { return null; }
            // Ältere Sicherungen enthielten die neu markierten Einträge noch mit Notfall-Umschlag (§23.1).
            try
            {
                return Store.PurgeBackups(st.Header.Uuid, generation);
            }
            catch (SiegelException)
            {
                return new PurgeReport { Interrupted = true };
            }
        }
    }

    /// <summary>Vernichtete Einträge endgültig entfernen. Danach ist die Selbstvernichtung aus (V verbraucht). Nichts
    /// vernichtet → nichts. In einer Vernichtungs-Sitzung ohne Wirkung.</summary>
    public void RemoveDestroyedEntries()
    {
        if (IsDuressSession) { return; }
        lock (WriteLock)
        {
            using var scope = Enter();
            var s = scope.State;
            if (!DestructionKeyDestroyed(s.Content)) { return; }
            using var content = s.Content.Clone();
            content.DropDestructibleEntries();
            Save(s, content, null);
        }
    }

    // MARK: Interna

    /// <summary>Speichern mit neuem DEK und neuem Salz (gleiche Stufe, Faktoren, Kit und KDF). Nur unter
    /// <see cref="WriteLock"/>, nach geprüftem Zugang. Ein Argon2.</summary>
    internal ulong RekeyAndSave(State s, VaultContent content, SecureBuffer pw, FactorSecrets factors)
    {
        var (header, slots, dek) = Store.Rekey(s.Header.VaultId, s.Header.Kdf, s.Header.FactorFields, s.Header.RecoveryScheme, s.Header.Pk, pw, factors);
        SecureBuffer tagKey, tag;
        try
        {
            (tagKey, tag) = NewTags(dek, pw);
        }
        catch
        {
            dek.Dispose();
            throw;
        }
        return CommitNewAccess(s, header, slots, dek, tagKey, tag, s.MasterReuseTags, content, null, s.DuressBinding, ownsKeys: true);
    }

    /// <summary>Ist das V dieses Inhalts im Zustand als vernichtet vermerkt?</summary>
    internal bool DestructionKeyDestroyed(VaultContent content) =>
        content.Destruction?.VKey is { } v && Store.DestroyedKeyId() == v.KeyId;

    /// <summary>Ist <paramref name="pw"/> das Vernichtungs-Passwort? (ein Argon2 mit dSalt, Vergleich des Prüfwerts)</summary>
    internal bool IsDuressPassword(SecureBuffer pw, DestructionConfig.DuressInfo d, byte[] vaultId, KdfParameters kdf)
    {
        using var dd = DuressCrypto.Derive(pw, d.Salt, kdf, Store.Limits);
        return Bytes.ConstantTimeEqual(DuressCrypto.Check(dd, vaultId), d.Check);
    }

    /// <summary>Neues Vernichtungs-Passwort: dSalt, Argon2 mit den Parametern des Kopfes, Schlüsselpaar und Prüfwert.</summary>
    private DestructionConfig.DuressInfo MakeDuress(string password, byte[] vaultId, KdfParameters kdf)
    {
        using var dpw = PasswordNormalizer.SecureBytes(password);
        var salt = Zufall.Bytes(DuressCrypto.SaltBytes);
        using var d = DuressCrypto.Derive(dpw, salt, kdf, Store.Limits);
        return new DestructionConfig.DuressInfo(Zufall.NewGuid(), salt, DuressCrypto.Check(d, vaultId), DuressCrypto.PublicKeys(d, vaultId));
    }

    /// <summary>Geprüfte Eingaben (ohne Zustand).</summary>
    internal sealed class DestructionRequest
    {
        internal DestructionRequest(DestructionSettings settings, string? duressPassword, IReadOnlySet<Guid> destructible, string masterPassword,
            EntryKeyEnrollment? vKey)
        {
            Fehler.NotNull(settings);
            Fehler.NotNull(destructible);
            Fehler.NotNull(masterPassword);
            settings.Validate();
            if (duressPassword is not null)
            {
                if (!settings.DuressEnabled) { throw Fehler.Io("destruction.duressPassword"); }
                VaultStore.CheckPolicy(duressPassword);
                if (VaultStore.PasswordsMatch(duressPassword, masterPassword)) { throw Fehler.MasterPasswordReused(); }
            }
            if (vKey is not null)
            {
                if (vKey.KeyId == Guid.Empty) { throw Fehler.Crypto("factor.keyID"); }
                VKey = VKeyOf(vKey);
            }
            Settings = settings;
            Destructible = destructible;
            HasNewDuressPassword = duressPassword is not null;
        }

        internal DestructionSettings Settings { get; }
        internal IReadOnlySet<Guid> Destructible { get; }
        internal DestructionConfig.VKeyInfo? VKey { get; }

        /// <summary>Bringt die Anfrage ein neues Vernichtungs-Passwort mit (das Passwort selbst wird nicht gehalten)?</summary>
        internal bool HasNewDuressPassword { get; }
    }

    internal sealed record DestructionPlan(bool Active, DestructionConfig.VKeyInfo? VKey, IReadOnlySet<Guid> Reseal, bool NewlyMarked);

    /// <summary>Regeln vor jeder Rechnung (§23): Stufe, Schutz, V, Vernichtungs-Passwort, nichts Vernichtetes offen.</summary>
    internal DestructionPlan PlanDestruction(DestructionRequest r, State st)
    {
        var content = st.Content;
        if (DestructionKeyDestroyed(content)) { throw Fehler.Io("destruction.destroyed"); }
        var active = r.Settings.AnyTriggerEnabled || r.Destructible.Count > 0;
        if (active && content.Level < SecurityLevel.Maximal) { throw Fehler.NotAllowedAtLevel(); }
        foreach (var id in r.Destructible)
        {
            var i = VisibleIndex(content, id);
            if (i < 0) { throw Fehler.Io("entry.notFound"); }
            var p = content.Entries[i].Protection;
            if (p < EntryProtection.Maximal) { throw Fehler.NotAllowedAtLevel(); }
            EntrySealing.RequireEnrolled(p.Factors() & ~FactorSet.SecureEnclave, content.EntryFactors);
        }
        var current = content.DestructibleIds;
        var old = content.Destruction?.VKey;
        var v = active ? r.VKey ?? old : null;
        if (active && v is null) { throw Fehler.FactorMissing(FactorKind.SecureEnclave); }
        if (v is not null && (v.KeyId == content.EntryFactors.DeviceKeyId || v.KeyId == st.Header.FactorFields.SeKeyId))
        {
            throw Fehler.Crypto("factor.keyID");
        }
        // Ein anderes V geht nur, solange keine vernichtbaren Einträge an das bisherige gebunden bleiben.
        if (v is not null && old is not null && !v.Equals(old) && current.Overlaps(r.Destructible)) { throw Fehler.NotAllowedAtLevel(); }
        if (r.Settings.DuressEnabled && content.Destruction?.Duress is null && !r.HasNewDuressPassword)
        {
            throw Fehler.Io("destruction.duressPassword");
        }
        var toMark = r.Destructible.Except(current).ToHashSet();
        var toUnmark = current.Except(r.Destructible).ToHashSet();
        return new DestructionPlan(active, v, toMark.Union(toUnmark).ToHashSet(), toMark.Count > 0);
    }

    /// <summary>Geheimteile der neu zu versiegelnden Einträge: neu markierte über ihre Notfall-Gruppe (eine Freigabe je
    /// Gruppe), entmarkierte über V (je Eintrag).</summary>
    private async Task<Dictionary<Guid, OpenedEntry>> OpenForResealingAsync(HashSet<Guid> ids, State st, IEntryFactorProvider provider,
        CancellationToken cancellationToken)
    {
        var output = new Dictionary<Guid, OpenedEntry>();
        var list = st.Content.Entries.Where(e => ids.Contains(e.Id) && e.SecretsSealed).ToList();
        var viaGroups = list.Where(e => st.Content.Sealed.ContainsKey(e.Id)).ToList();
        if (viaGroups.Count > 0)
        {
            var masks = viaGroups.Select(e => e.Protection.Factors()).ToHashSet();
            var groups = st.Content.RecoveryGroups.Where(g => masks.Contains(g.Mask)).OrderBy(g => (byte)g.Mask).ToList();
            if (groups.Count != masks.Count) { throw Fehler.Corrupt("entry.sealed"); }
            var released = await ReleaseGroupsAsync(groups, st, provider, cancellationToken).ConfigureAwait(false);
            try
            {
                foreach (var (id, secrets) in st.Content.SecretsViaGroups(viaGroups, released, st.Header.VaultId))
                {
                    output[id] = new OpenedEntry(secrets, st.Content.Sealed[id], null);
                }
            }
            finally
            {
                foreach (var v in released.Values) { v.Dispose(); }
            }
        }
        foreach (var e in list.Where(e => st.Content.Destructible.ContainsKey(e.Id)))
        {
            output[e.Id] = new OpenedEntry(await RevealDestructibleAsync(e, st, provider, cancellationToken).ConfigureAwait(false), null,
                st.Content.Destructible[e.Id]);
        }
        return output;
    }
}

/// <summary>Hält Karte und Sicherheitsschlüssel für die Dauer eines Aufrufs (Markieren/Entmarkieren vieler Einträge);
/// der Gerätefaktor wird für jeden Eintrag neu verlangt. Liefert immer Kopien (der Kern gibt jede Lieferung frei).</summary>
internal sealed class CachingEntryFactors(IEntryFactorProvider inner) : IEntryFactorProvider, IDisposable
{
    private readonly Lock gate = new();
    private FactorSecret? card;
    private readonly Dictionary<string, FactorSecret> keyOutputs = new(StringComparer.Ordinal);

    public Task<FactorSecret> SecureEnclaveSharedSecretAsync(Guid keyId, ReadOnlyMemory<byte> ephemeralPublicKey, CancellationToken cancellationToken) =>
        inner.SecureEnclaveSharedSecretAsync(keyId, ephemeralPublicKey, cancellationToken);

    public Task<FactorSecret> WindowsHelloSecretAsync(Guid keyId, ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken) =>
        inner.WindowsHelloSecretAsync(keyId, challenge, cancellationToken);

    public async Task<FactorSecret> CardSecretAsync(CancellationToken cancellationToken)
    {
        lock (gate)
        {
            if (card is not null) { return CopyOf(card); }
        }
        var q = await inner.CardSecretAsync(cancellationToken).ConfigureAwait(false);
        lock (gate)
        {
            if (card is null) { card = q; } else { q.Dispose(); }
            return CopyOf(card);
        }
    }

    public async Task<FactorSecret> SecurityKeyOutputAsync(ReadOnlyMemory<byte> credentialId, ReadOnlyMemory<byte> salt, CancellationToken cancellationToken)
    {
        var key = Bytes.Hex(credentialId.Span) + ":" + Bytes.Hex(salt.Span);
        lock (gate)
        {
            if (keyOutputs.TryGetValue(key, out var y)) { return CopyOf(y); }
        }
        var output = await inner.SecurityKeyOutputAsync(credentialId, salt, cancellationToken).ConfigureAwait(false);
        lock (gate)
        {
            if (!keyOutputs.TryAdd(key, output)) { output.Dispose(); }
            return CopyOf(keyOutputs[key]);
        }
    }

    private static FactorSecret CopyOf(FactorSecret s)
    {
        using var l = s.Storage.Borrow();
        return FactorSecret.Copy(l.Span);
    }

    public void Dispose()
    {
        lock (gate)
        {
            card?.Dispose();
            card = null;
            foreach (var y in keyOutputs.Values) { y.Dispose(); }
            keyOutputs.Clear();
        }
    }
}
