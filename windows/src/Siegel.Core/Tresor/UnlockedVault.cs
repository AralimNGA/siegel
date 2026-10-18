using Siegel.Modell;
using Siegel.Werkzeuge;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Core;

/// <summary>
/// Ein entsperrter Tresor (SPEC §8, §22, §23.3), C#-Gegenstück zu UnlockedVault.swift (+Notfall, +Stufen, +Schutz,
/// +Vernichtung). Threadsicher: ein kurzer Zustands-Riegel für Lesen/Übernehmen und ein Schreib-Riegel, der Änderungen
/// serialisiert. Mutationen sind transaktional: Kopie ändern → speichern → erst dann übernehmen. <see cref="Lock"/>
/// (bzw. <see cref="Dispose"/>) verwirft DEK und Inhalt; laufende Vorgänge behalten ihre Puffer bis zum Ende, danach
/// werden auch diese genullt (Gegenstück zur Referenzzählung in Swift).
/// </summary>
public sealed partial class UnlockedVault : IDisposable
{
    /// <summary>Vorbereitetes neues Notfallkit; erst <c>CommitRecovery</c> bzw. <c>ChangeSecurityLevel</c> schreibt es.</summary>
    internal sealed class PendingKit(SecureBuffer r, RecoveryScheme scheme, VaultHeader header, SecureBuffer kekPw, SecureBuffer dek,
        SecureBuffer tagKey, SecureBuffer masterTag, byte[] basedOnSalt) : IDisposable
    {
        internal SecureBuffer R { get; } = r;
        internal RecoveryScheme Scheme { get; } = scheme;

        /// <summary>Neuer Kopf: Faktoren wie bei der Vorbereitung, neues Salz, neues Kit.</summary>
        internal VaultHeader Header { get; } = header;
        internal SecureBuffer KekPw { get; } = kekPw;
        internal SecureBuffer Dek { get; } = dek;
        internal SecureBuffer TagKey { get; } = tagKey;
        internal SecureBuffer MasterTag { get; } = masterTag;

        /// <summary>Salz des Kopfes, auf dem die Vorbereitung beruht (Passwortwechsel dazwischen → ungültig).</summary>
        internal byte[] BasedOnSalt { get; } = basedOnSalt;

        /// <summary>Puffer, die dem Kit gehören; <see cref="Dek"/>, <see cref="TagKey"/> und <see cref="MasterTag"/>
        /// gehen beim Schreiben in den Zustand über.</summary>
        internal IEnumerable<IDisposable> Owned => [R, KekPw, Dek, TagKey, MasterTag];

        public void Dispose()
        {
            foreach (var o in Owned) { o.Dispose(); }
        }
    }

    /// <summary>Unveränderlicher Zustand einer Sitzung (neu bei jeder Übernahme).</summary>
    internal sealed record State(VaultHeader Header, VaultSlots Slots, SecureBuffer Dek, VaultContent Content, ulong Generation,
        SecureBuffer TagKey, SecureBuffer MasterTag, IReadOnlyList<byte[]> MasterReuseTags, IReadOnlySet<Guid> Reuse, PendingKit? Pending,
        SecureBuffer? MigrationKek, SecureBuffer? DuressBinding)
    {
        /// <summary>Alles, was dieser Zustand besitzt (Freigabe beim Ersetzen bzw. Sperren).</summary>
        internal IEnumerable<IDisposable> Owned
        {
            get
            {
                IDisposable?[] all = [Dek, Content, TagKey, MasterTag, MigrationKek, DuressBinding];
                foreach (var o in all) { if (o is not null) { yield return o; } }
                if (Pending is not null) { foreach (var o in Pending.Owned) { yield return o; } }
            }
        }
    }

    /// <summary>Nicht geheime Kennwerte, die auch nach dem Sperren lesbar bleiben.</summary>
    private sealed record MetaInfo(ulong Generation, KdfParameters Kdf, string KitId, SecurityLevel Level, VaultHeaderInfo HeaderInfo,
        FactorSet Enrolled)
    {
        internal static MetaInfo Of(State s) =>
            new(s.Generation, s.Header.Kdf, s.Header.Pk.KitId, s.Content.Level, s.Header.Info, s.Content.EntryFactors.Enrolled);
    }

    private readonly Lock stateLock = new();
    private State? state;
    private MetaInfo meta;
    private int inFlight;
    private readonly List<IDisposable> retired = [];

    /// <summary>Serialisiert Änderungen (nie über ein <c>await</c> halten).</summary>
    internal Lock WriteLock { get; } = new();

    internal VaultStore Store { get; }

    /// <summary>In einer Vernichtungs-Sitzung unsichtbar: die (eben vernichteten) vernichtbaren Einträge.</summary>
    internal IReadOnlySet<Guid> HiddenEntries { get; }

    /// <summary>Mit dem Vernichtungs-Passwort geöffnet (§23.2 Nr. 3). Nach aussen wie eine normale Sitzung.</summary>
    public bool IsDuressSession { get; }

    /// <summary>Übernimmt <paramref name="dek"/>, <paramref name="content"/> und <paramref name="migrationKek"/> (bei einem
    /// Fehler bleiben sie beim Aufrufer). <paramref name="password"/> (abgebildet) und <paramref name="rawPassword"/>
    /// (Eingabe, nur für den Tag bis v4.3) werden nicht gehalten.</summary>
    internal UnlockedVault(VaultStore store, VaultHeader header, VaultSlots slots, SecureBuffer dek, VaultContent content, ulong generation,
        SecureBuffer password, string? rawPassword = null, FactorSecrets? factors = null, SecureBuffer? migrationKek = null,
        bool duress = false)
    {
        // Ältere Inhalte (v1, Stufe A) haben noch keinen Grundschlüssel; er wird mit dem nächsten Speichern geschrieben.
        content.EnsureEntryKey();
        var tagKey = MasterTag.Key(dek);
        SecureBuffer? tag = null;
        SecureBuffer? binding = null;
        try
        {
            tag = MasterTag.Tag(tagKey, password);
            var masterReuseTags = content.MasterReuseTags(password, rawPassword);
            binding = DuressCrypto.TryBinding(header, factors ?? new FactorSecrets());
            Store = store;
            IsDuressSession = duress;
            HiddenEntries = duress ? content.DestructibleIds : new HashSet<Guid>();
            var s = new State(header, slots, dek, content, generation, tagKey, tag, masterReuseTags,
                ReuseSet(content, tagKey, tag, masterReuseTags), null, header.FormatVersion == 1 ? migrationKek : null, binding);
            if (header.FormatVersion != 1) { migrationKek?.Dispose(); }
            state = s;
            meta = MetaInfo.Of(s);
        }
        catch
        {
            tagKey.Dispose();
            tag?.Dispose();
            binding?.Dispose();
            throw;
        }
    }

    // MARK: Lesen

    public Guid VaultId => meta.HeaderInfo.VaultId;

    public ulong Generation { get { lock (stateLock) { return meta.Generation; } } }

    public KdfParameters Kdf { get { lock (stateLock) { return meta.Kdf; } } }

    public string KitId { get { lock (stateLock) { return meta.KitId; } } }

    public bool IsLocked { get { lock (stateLock) { return state is null; } } }

    /// <summary>Tresor-Stufe (§13); bleibt nach dem Sperren lesbar.</summary>
    public SecurityLevel Level { get { lock (stateLock) { return meta.Level; } } }

    /// <summary>Regeln der Stufe, die die Oberfläche durchsetzt.</summary>
    public LevelPolicy Policy => Level.Policy();

    /// <summary>Kopf im Speicher (wie <see cref="VaultStore.Inspect()"/>, aber der beim Entsperren authentifizierte).</summary>
    public VaultHeaderInfo HeaderInfo { get { lock (stateLock) { return meta.HeaderInfo; } } }

    /// <summary>Für Einträge eingerichtete Faktoren (§16).</summary>
    public FactorSet EnrolledFactors { get { lock (stateLock) { return meta.Enrolled; } } }

    /// <summary>Art des Eintrags-Gerätefaktors (null = keiner eingerichtet; W4.1).</summary>
    public DeviceKeyKind? EntryDeviceKeyKind
    {
        get
        {
            lock (stateLock)
            {
                if (state?.Content.EntryFactors is not { } f) { return null; }
                return f.SecureEnclave is not null ? DeviceKeyKind.SecureEnclaveP256 : f.WindowsHello is not null ? DeviceKeyKind.WindowsHello : null;
            }
        }
    }

    /// <summary>Credential und Entsperr-Salz des eingerichteten Sicherheitsschlüssels (aus dem Kopf, sonst aus dem Inhalt).</summary>
    public (ReadOnlyMemory<byte> CredentialId, ReadOnlyMemory<byte> Salt)? SecurityKeyCredential
    {
        get
        {
            lock (stateLock)
            {
                if (state is not { } s) { return null; }
                if (s.Header.FactorFields.FidoCredentialId is { } cred && s.Header.FactorFields.FidoSalt is { } salt)
                {
                    return (cred.ToArray(), salt.ToArray());
                }
                return s.Content.EntryFactors.SecurityKey is { } k ? (k.CredentialId.ToArray(), k.Salt.ToArray()) : null;
            }
        }
    }

    public bool RecoveryConfirmed { get { lock (stateLock) { return state?.Content.RecoveryConfirmedAt is not null; } } }

    /// <summary>Ohne gelöschte Einträge (in einer Vernichtungs-Sitzung ohne die vernichteten). Kopien.</summary>
    public IReadOnlyList<VaultEntry> Entries
    {
        get
        {
            lock (stateLock)
            {
                return state is null ? [] : [.. state.Content.Entries.Where(e => e.DeletedAt is null && !HiddenEntries.Contains(e.Id)).Select(e => e.Copy())];
            }
        }
    }

    /// <summary>„Zuletzt gelöscht“ (Kopien).</summary>
    public IReadOnlyList<VaultEntry> DeletedEntries
    {
        get
        {
            lock (stateLock)
            {
                return state is null ? [] : [.. state.Content.Entries.Where(e => e.DeletedAt is not null && !HiddenEntries.Contains(e.Id)).Select(e => e.Copy())];
            }
        }
    }

    /// <summary>Letzte Änderung eines Eintrags (bearbeitet oder gelöscht); null ohne Einträge.</summary>
    public DateTimeOffset? LastModified
    {
        get
        {
            lock (stateLock)
            {
                var list = state?.Content.Entries.Where(e => !HiddenEntries.Contains(e.Id)).ToList();
                if (list is null || list.Count == 0) { return null; }
                return list.Max(e => e.DeletedAt is { } d && d > e.Modified ? d : e.Modified);
            }
        }
    }

    /// <summary>Einträge, deren Passwort oder Verlaufswert dem Master-Passwort entspricht.</summary>
    public IReadOnlySet<Guid> MasterPasswordReuse
    {
        get
        {
            lock (stateLock)
            {
                return state is null ? new HashSet<Guid>() : state.Reuse.Except(HiddenEntries).ToHashSet();
            }
        }
    }

    /// <summary>Index eines Eintrags, den diese Sitzung sehen darf.</summary>
    internal int VisibleIndex(VaultContent content, Guid id) =>
        HiddenEntries.Contains(id) ? -1 : content.Entries.FindIndex(e => e.Id == id);

    // MARK: Einträge

    /// <summary>
    /// Transaktional; setzt <c>Modified</c>, pflegt den Verlauf. Neue Einträge bekommen mindestens den Standard-Schutz
    /// der Stufe (4/5: Schutz 2); Schutz ≥ 2 wird sofort versiegelt (fehlender Faktor → <c>FactorMissing</c>). Bei einem
    /// versiegelten Eintrag ändert <c>Upsert</c> nur offene Felder (sonst <c>Io("entry.sealedSecrets")</c> bzw.
    /// <c>Io("entry.protection")</c>); ein offener Eintrag darf höher geschützt werden, nie tiefer. Mit einem
    /// Windows-Hello-Eintragsschlüssel braucht das Versiegeln eine Signatur → <see cref="UpsertAsync"/>; hier
    /// <c>FactorMissing(secureEnclave)</c>.
    /// </summary>
    public void Upsert(VaultEntry entry) => Upsert(entry, null);

    internal void Upsert(VaultEntry entry, HelloSealing? hello)
    {
        Fehler.NotNull(entry);
        VaultContent.Validate(entry);
        Mutate(null, hello, (content, c) =>
        {
            // Vernichtungs-Sitzung: ein unsichtbarer Eintrag lässt sich weder ändern noch neu anlegen.
            if (HiddenEntries.Contains(entry.Id)) { throw Fehler.Io("entry.stale"); }
            var i = content.Entries.FindIndex(e => e.Id == entry.Id);
            if (i >= 0)
            {
                var old = content.Entries[i];
                if (old.SecretsSealed)
                {
                    if (entry.Protection != old.Protection) { throw Fehler.Io("entry.protection"); }
                    if (!entry.SecretsSealed || !SecretsAreEmpty(entry)) { throw Fehler.Io("entry.sealedSecrets"); }
                    var sealedUpdate = entry.Copy();
                    sealedUpdate.Created = old.Created;
                    sealedUpdate.DeletedAt = old.DeletedAt;
                    sealedUpdate.Modified = c.Now;
                    content.Entries[i] = sealedUpdate;
                    return true;
                }
                // Veraltete Kopie (z. B. von vor einer Wiederherstellung): nie leere Geheimteile übernehmen.
                if (entry.SecretsSealed) { throw Fehler.Io("entry.stale"); }
                if (entry.Protection < old.Protection) { throw Fehler.Io("entry.protection"); }
                var updated = entry.Copy();
                updated.Created = old.Created;
                updated.DeletedAt = old.DeletedAt;
                var history = new List<PasswordHistoryItem>(old.History);
                // Gleichheit wie Swift-String (kanonisch, Befund krypto-4): „Café“ in NFD und NFC ist dasselbe Passwort.
                if (!SwiftStringComparer.Instance.Equals(old.Password, entry.Password) && old.Password.Length > 0)
                {
                    history.Add(new PasswordHistoryItem(old.Password, c.Now));
                }
                // Das aktuelle Passwort ist kein „früheres“.
                history.RemoveAll(h => SwiftStringComparer.Instance.Equals(h.Password, entry.Password));
                updated.History = VaultContent.ApplyHistoryRule(history, c.Now);
                updated.Modified = c.Now;
                content.Entries[i] = updated;
                if (updated.Protection > EntryProtection.Normal) { content.Seal(i, c.Header.VaultId, c.Header.Pk, c.Now, c.Hello); }
            }
            else
            {
                if (entry.SecretsSealed) { throw Fehler.Io("entry.stale"); }
                var created = entry.Copy();
                created.Created = Clock.Canonical(entry.Created);
                created.Modified = c.Now;
                created.DeletedAt = null;
                var minimum = content.Level.Policy().DefaultEntryProtection;
                created.Protection = entry.Protection > minimum ? entry.Protection : minimum;
                created.History = VaultContent.ApplyHistoryRule(
                    entry.History.Where(h => !SwiftStringComparer.Instance.Equals(h.Password, entry.Password)), c.Now);
                content.Entries.Add(created);
                if (created.Protection > EntryProtection.Normal)
                {
                    content.Seal(content.Entries.Count - 1, c.Header.VaultId, c.Header.Pk, c.Now, c.Hello);
                }
            }
            return true;
        });
    }

    internal static bool SecretsAreEmpty(VaultEntry e) =>
        e.Password.Length == 0 && e.Notes.Length == 0 && e.Totp.Length == 0 && e.History.Count == 0;

    /// <summary>Setzt <c>DeletedAt</c> (→ „Zuletzt gelöscht“, 30 Tage).</summary>
    public void Delete(Guid id) =>
        Mutate(null, null, (content, c) =>
        {
            var i = VisibleIndex(content, id);
            if (i < 0) { throw Fehler.Io("entry.notFound"); }
            if (content.Entries[i].DeletedAt is not null) { return false; }
            content.Entries[i].DeletedAt = c.Now;
            return true;
        });

    public void Restore(Guid id) =>
        Mutate(null, null, (content, _) =>
        {
            var i = VisibleIndex(content, id);
            if (i < 0) { throw Fehler.Io("entry.notFound"); }
            if (content.Entries[i].DeletedAt is null) { return false; }
            content.Entries[i].DeletedAt = null;
            return true;
        });

    /// <summary>Endgültig entfernen (nur Einträge in „Zuletzt gelöscht“).</summary>
    public void PurgeDeleted(Guid id) =>
        Mutate(null, null, (content, _) =>
        {
            var i = VisibleIndex(content, id);
            if (i < 0) { throw Fehler.Io("entry.notFound"); }
            if (content.Entries[i].DeletedAt is null) { throw Fehler.Io("entry.notDeleted"); }
            content.Entries.RemoveAt(i);
            return true;
        });

    /// <summary>Verlauf leeren. Bei versiegelten Einträgen ist der Verlauf ein Geheimteil → <c>Io("entry.sealedSecrets")</c>.</summary>
    public void ClearHistory(Guid id) =>
        Mutate(null, null, (content, _) =>
        {
            var i = VisibleIndex(content, id);
            if (i < 0) { throw Fehler.Io("entry.notFound"); }
            if (content.Entries[i].SecretsSealed) { throw Fehler.Io("entry.sealedSecrets"); }
            if (content.Entries[i].History.Count == 0) { return false; }
            content.Entries[i].History = [];
            return true;
        });

    /// <summary>Nur anhängen. Dubletten (Host + Benutzer + Passwort) werden übersprungen; gleicher Host + Benutzer mit
    /// anderem Passwort → neuer Eintrag mit „(Import)“. Bestand wird nie geändert. Vorher angeheftete Sicherung
    /// „vor-import“. Versiegelte Bestandseinträge vergleicht der Kern über ihren reuseTag. Neue Einträge bekommen
    /// mindestens den Standard-Schutz der Stufe und werden dann versiegelt.</summary>
    public ImportReport ImportEntries(IReadOnlyList<VaultEntry> entries) => ImportEntries(entries, null);

    internal ImportReport ImportEntries(IReadOnlyList<VaultEntry> entries, HelloSealing? hello)
    {
        Fehler.NotNull(entries);
        foreach (var e in entries)
        {
            Fehler.NotNull(e);
            VaultContent.Validate(e);
            if (e.SecretsSealed) { throw Fehler.Io("entry.stale"); }
        }
        var report = new ImportReport();
        Mutate(BackupNaming.Reason.ImportCsv, hello, (content, c) =>
        {
            report = new ImportReport();
            var minimum = content.Level.Policy().DefaultEntryProtection;
            foreach (var e in entries)
            {
                EntrySealing.RequireEnrolled((e.Protection > minimum ? e.Protection : minimum).Factors(), content.EntryFactors);
            }
            content.EnsureEntryKey();
            using var reuseKey = content.ReuseKey();
            // Schlüssel und Passwörter vergleicht Swift kanonisch (Dictionary/Set<String>, Befund krypto-4).
            var known = new Dictionary<string, HashSet<string>>(SwiftStringComparer.Instance);
            var knownTags = new Dictionary<string, List<byte[]>>(SwiftStringComparer.Instance);
            var ids = new HashSet<Guid>();
            foreach (var e in content.Entries)
            {
                ids.Add(e.Id);
                if (e.DeletedAt is not null || HiddenEntries.Contains(e.Id)) { continue; }
                var key = DuplicateKey(e);
                if (e.SecretsSealed)
                {
                    if (!knownTags.TryGetValue(key, out var tags)) { knownTags[key] = tags = []; }
                    tags.Add(content.Meta.GetValueOrDefault(e.Id)?.Tag ?? []);
                }
                else
                {
                    if (!known.TryGetValue(key, out var pws)) { known[key] = pws = new HashSet<string>(SwiftStringComparer.Instance); }
                    pws.Add(e.Password);
                }
            }
            for (var index = 0; index < entries.Count; index++)
            {
                var e = entries[index];
                var key = DuplicateKey(e);
                var added = e.Copy();
                if (known.ContainsKey(key) || knownTags.ContainsKey(key))
                {
                    var tag = EntrySealing.ReuseTag(reuseKey, e.Password) ?? [];
                    // Versiegelte Einträge können noch einen Tag nach der Formel bis v4.3 tragen (nur NFC).
                    var legacy = EntrySealing.LegacyReuseTag(reuseKey, e.Password);
                    var tags = knownTags.GetValueOrDefault(key);
                    if ((known.TryGetValue(key, out var pws) && pws.Contains(e.Password))
                        || (tags is not null && tags.Any(t => Bytes.Same(t, tag)))
                        || (legacy is not null && tags is not null && tags.Any(t => Bytes.Same(t, legacy))))
                    {
                        report.SkippedDuplicates++;
                        continue;
                    }
                    added.Title = ImportTitle(e.Title);
                    report.Conflicts++;
                }
                // Ersatz-Kennung über alle Sammelrunden der Windows-Hello-Art gleich (Befund krypto-3): sonst gehört die
                // in der Vorrunde geholte Signatur zu einer verworfenen Kennung, und jede Runde fragt neu.
                if (ids.Contains(added.Id)) { added.Id = hello?.ReplacementId(e.Id, index) ?? Zufall.NewGuid(); }
                ids.Add(added.Id);
                added.DeletedAt = null;
                added.Created = Clock.Canonical(added.Created);
                added.Modified = Clock.Canonical(added.Modified);
                added.Protection = e.Protection > minimum ? e.Protection : minimum;
                added.History = VaultContent.ApplyHistoryRule(
                    added.History.Where(h => !SwiftStringComparer.Instance.Equals(h.Password, added.Password)), c.Now);
                content.Meta[added.Id] = EntrySealing.Meta(added.Password, null, reuseKey, added.Modified, c.Now);
                content.Entries.Add(added);
                if (added.Protection > EntryProtection.Normal)
                {
                    content.Seal(content.Entries.Count - 1, c.Header.VaultId, c.Header.Pk, c.Now, c.Hello);
                }
                if (!known.TryGetValue(key, out var set)) { known[key] = set = new HashSet<string>(SwiftStringComparer.Instance); }
                set.Add(e.Password);
                report.Added++;
            }
            return report.Added > 0;
        });
        return report;
    }

    /// <summary>Host (klein, IDNA) + Benutzer, getrennt durch ein Nullzeichen.</summary>
    internal static string DuplicateKey(VaultEntry e) => HostKey(e.Url) + "\0" + e.Username;

    /// <summary>Wie Swift <c>hostKey</c>: <c>URL(string:)?.host(percentEncoded: false)</c> (ACE-Form, IPv6 ohne
    /// Klammern) klein und ohne abschliessenden Punkt; ohne Host die getrimmte Adresse klein. Über das Foundation-Modell
    /// der Werkzeuge (<see cref="UrlHost"/>, wie der Autofill-Abgleich), das nie wirft (Befund robust-2: <c>Uri.IdnHost</c>
    /// warf bei Hosts, die <c>Uri.TryCreate</c> annimmt und IDNA ablehnt, z. B. U+FFFD, eine <c>UriFormatException</c>,
    /// und ein einziger solcher Eintrag blockierte jeden Import). Nur innerhalb eines Imports verglichen.</summary>
    internal static string HostKey(string url)
    {
        var t = SwiftText.Trimmen(url, SwiftText.IstLeerzeichenOderUmbruch);
        if (t.Length == 0) { return ""; }
        var withScheme = SwiftText.EnthaeltFolge(t, "://") ? t : "https://" + t;
        if (UrlHost.Zerlegen(withScheme, out var teile) && UrlHost.AceForm(teile) is { Length: > 0 } ace)
        {
            var host = SwiftText.Klein(ace);
            if (host.EndsWith('.')) { host = host[..^1]; }
            return host;
        }
        return SwiftText.Klein(t);
    }

    internal static string ImportTitle(string title)
    {
        var suffix = title.Length == 0 ? "(Import)" : " (Import)";
        var b = new System.Text.StringBuilder(title);
        while (System.Text.Encoding.UTF8.GetByteCount(b + suffix) > VaultContent.MaxTitle && b.Length > 0)
        {
            // ganze Zeichen entfernen (kein halbes Surrogat-Paar)
            var cut = b.Length >= 2 && char.IsLowSurrogate(b[^1]) && char.IsHighSurrogate(b[^2]) ? 2 : 1;
            b.Length -= cut;
        }
        return b + suffix;
    }

    // MARK: Master-Passwort

    /// <summary>Argon2-Prüfung des Master-Passworts (nicht auf dem Oberflächen-Thread), ohne Faktoren.</summary>
    public bool Verify(string masterPassword) => Verify(masterPassword, new FactorSecrets());

    /// <summary>Argon2-Prüfung von Master-Passwort und Faktoren der Stufe. Fehlt ein Faktor oder stimmt etwas nicht → false.</summary>
    public bool Verify(string masterPassword, FactorSecrets factors)
    {
        Fehler.NotNull(masterPassword);
        Fehler.NotNull(factors);
        CoreEnvironment.RequireBackgroundThread();
        try
        {
            using var pw = PasswordNormalizer.SecureBytes(masterPassword);
            using var scope = Enter();
            VerifyAccess(pw, factors, scope.State);
            return true;
        }
        catch (SiegelException)
        {
            return false;
        }
    }

    public void ChangeMasterPassword(string current, string newPassword, KdfParameters? kdf = null) =>
        ChangeMasterPassword(current, newPassword, new FactorSecrets(), kdf);

    /// <summary>Neues Passwort (und optional KDF-Profil): neuer DEK, neues Salz, recSlot neu gekapselt (Code bleibt
    /// gültig), angeheftete Sicherung „vor-passwortwechsel“. Ein reiner Profilwechsel ruft das mit gleichem Passwort auf
    /// (dann greift die Wiederverwendungs-Sperre nicht). Schwächeres Profil als die Stufe → <c>NotAllowedAtLevel</c>.</summary>
    public void ChangeMasterPassword(string current, string newPassword, FactorSecrets factors, KdfParameters? kdf = null)
    {
        Fehler.NotNull(current);
        Fehler.NotNull(newPassword);
        Fehler.NotNull(factors);
        CoreEnvironment.RequireBackgroundThread();
        VaultStore.CheckPolicy(newPassword);
        var unchanged = VaultStore.PasswordsMatch(current, newPassword);
        using var newPw = PasswordNormalizer.SecureBytes(newPassword);
        using var currentPw = PasswordNormalizer.SecureBytes(current);
        lock (WriteLock)
        {
            using var scope = Enter();
            var s = scope.State;
            var parameters = kdf ?? s.Header.Kdf;
            Store.Limits.Validate(parameters);
            if (kdf is not null && Store.Limits.IsWeaker(parameters, s.Content.Level)) { throw Fehler.NotAllowedAtLevel(); }
            // Vernichtungs-Passwort (§23.2): gleiche Argon2-Parameter wie der Kopf, also kein Profilwechsel.
            if (s.Content.Destruction?.Duress is not null && parameters != s.Header.Kdf) { throw Fehler.NotAllowedAtLevel(); }
            if (!unchanged && (MasterTag.IsUsedByEntries(newPw, s.Content.Entries) || s.Content.IsUsedBySealedEntries(newPw, newPassword)))
            {
                throw Fehler.MasterPasswordReused();
            }
            VerifyAccess(currentPw, factors, s);
            // Das neue Master-Passwort darf nicht das Vernichtungs-Passwort sein.
            if (s.Content.Destruction?.Duress is { } d && IsDuressPassword(newPw, d, s.Header.VaultId, s.Header.Kdf))
            {
                throw Fehler.MasterPasswordReused();
            }
            var (header, slots, dek) = Store.Rekey(s.Header.VaultId, parameters, s.Header.FactorFields, s.Header.RecoveryScheme, s.Header.Pk,
                newPw, factors);
            SecureBuffer tagKey, tag;
            try
            {
                (tagKey, tag) = NewTags(dek, newPw);
            }
            catch
            {
                dek.Dispose();
                throw;
            }
            var masterReuseTags = s.Content.MasterReuseTags(newPw, newPassword);
            // Gleiche Faktoren wie beim Entsperren (eben geprüft) → F bleibt.
            CommitNewAccess(s, header, slots, dek, tagKey, tag, masterReuseTags, s.Content, BackupNaming.Reason.PasswordChange,
                s.DuressBinding, ownsKeys: true);
        }
    }

    /// <summary>DEK und Inhalt verwerfen; danach unbrauchbar. Laufende Vorgänge halten ihre Puffer bis zum Ende.</summary>
    public void Lock()
    {
        lock (stateLock)
        {
            if (state is not null)
            {
                retired.AddRange(state.Owned);
                state = null;
            }
            if (inFlight == 0) { FlushRetired(); }
        }
    }

    /// <summary>Wie <see cref="Lock"/>.</summary>
    public void Dispose() => Lock();

    public override string ToString() => "UnlockedVault(redacted)";

    // MARK: Interna: Zustand, Sperren, Speichern

    /// <summary>Laufender Vorgang mit seinem Zustand; hält die Puffer am Leben (Freigabe beim letzten Ende).</summary>
    internal readonly struct Scope(UnlockedVault owner, State state) : IDisposable
    {
        internal State State { get; } = state;

        public void Dispose() => owner.Exit();
    }

    internal Scope Enter()
    {
        lock (stateLock)
        {
            if (state is null) { throw Fehler.Locked(); }
            inFlight++;
            return new Scope(this, state);
        }
    }

    private void Exit()
    {
        lock (stateLock)
        {
            inFlight--;
            if (inFlight == 0) { FlushRetired(); }
        }
    }

    private void FlushRetired()
    {
        foreach (var r in retired) { r.Dispose(); }
        retired.Clear();
    }

    /// <summary>Vor jedem Schreiben (unter <see cref="WriteLock"/>): nach dem Sperren schreibt der Tresor nichts mehr
    /// (Befund datei-1).</summary>
    internal void RequireUnlocked()
    {
        if (IsLocked) { throw Fehler.Locked(); }
    }

    /// <summary>Neuen Zustand übernehmen; was der alte besass und der neue nicht mehr, wird freigegeben (sobald kein
    /// Vorgang mehr läuft). Gesperrt → der neue Zustand wird ganz freigegeben.</summary>
    internal void Commit(State next)
    {
        lock (stateLock)
        {
            if (state is null)
            {
                retired.AddRange(next.Owned);
            }
            else
            {
                var keep = new HashSet<IDisposable>(next.Owned, ReferenceEqualityComparer.Instance);
                retired.AddRange(state.Owned.Where(o => !keep.Contains(o)));
                state = next;
                meta = MetaInfo.Of(next);
            }
            if (inFlight == 0) { FlushRetired(); }
        }
    }

    /// <summary>Vorbereitetes Kit merken (nur solange entsperrt; ein früheres wird freigegeben).</summary>
    internal void SetPending(PendingKit pending)
    {
        lock (stateLock)
        {
            if (state is not { } s)
            {
                pending.Dispose();
                throw Fehler.Locked();
            }
            if (s.Pending is not null) { retired.AddRange(s.Pending.Owned); }
            state = s with { Pending = pending };
            if (inFlight == 0) { FlushRetired(); }
        }
    }

    /// <summary>Was eine Änderung sieht: Zeitpunkt, beim Entsperren authentifizierter Kopf, Material der Hello-Art.</summary>
    internal sealed record Change(DateTimeOffset Now, VaultHeader Header, HelloSealing? Hello);

    /// <summary>Kopie ändern → speichern → übernehmen. <paramref name="change"/> liefert false, wenn nichts zu speichern ist.
    /// Fehlen der Hello-Art noch Signaturen, wird nichts geschrieben (<see cref="HelloMaterialNeededException"/>).</summary>
    internal void Mutate(string? reason, HelloSealing? hello, Func<VaultContent, Change, bool> change)
    {
        lock (WriteLock)
        {
            using var scope = Enter();
            var s = scope.State;
            using var content = s.Content.Clone();
            if (!change(content, new Change(Clock.Now(), s.Header, hello))) { return; }
            if (hello?.HasRequests == true) { throw new HelloMaterialNeededException(); }
            Save(s, content, reason);
        }
    }

    /// <summary>Offene Einträge über den Master-Tag (§1.6), versiegelte über ihren reuseTag (§17).</summary>
    internal static HashSet<Guid> ReuseSet(VaultContent content, SecureBuffer tagKey, SecureBuffer masterTag, IReadOnlyList<byte[]> masterReuseTags)
    {
        var output = MasterTag.Reuse(content.Entries, tagKey, masterTag);
        foreach (var e in content.Entries.Where(e => e.SecretsSealed))
        {
            if (content.Meta.GetValueOrDefault(e.Id)?.Tag is { } t && masterReuseTags.Any(m => Bytes.ConstantTimeEqual(t, m))) { output.Add(e.Id); }
        }
        return output;
    }

    /// <summary>Normales Speichern mit gleichem DEK und gleichen Slots (nur unter <see cref="WriteLock"/>). Ist die Datei
    /// noch Format v1, wird sie dabei zu v2 (gleiches Salz, gleicher DEK, Slots mit v2-Labels). Gesperrt →
    /// <c>Io("vault.locked")</c> ohne zu schreiben. Liefert die Generation; nach dem Schreiben wirft es nicht mehr.</summary>
    internal ulong Save(State s, VaultContent content, string? reason)
    {
        var header = s.Header;
        var slots = s.Slots;
        if (s.Header.FormatVersion == 1)
        {
            var kek = s.MigrationKek ?? throw Fehler.Crypto("migration.kek");
            header = VaultHeader.V2(s.Header.VaultId, s.Header.Kdf, s.Header.Salt, HeaderFactorFields.None, RecoveryScheme.SingleCode, s.Header.Pk);
            slots = VaultCrypto.MakeSlots(header, kek, s.Dek);
        }
        RequireUnlocked();
        var (generation, result) = Store.Persist(header, slots, s.Dek, content, s.Generation,
            new VaultStore.DiskExpectation.Generation(s.Header.Uuid, s.Generation), reason, s.DuressBinding);
        var reuse = ReuseSet(result, s.TagKey, s.MasterTag, s.MasterReuseTags);
        Commit(s with { Header = header, Slots = slots, Content = result, Generation = generation, Reuse = reuse, MigrationKek = null });
        return generation;
    }

    /// <summary>Master-Tag-Schlüssel und Master-Tag zu einem neuen DEK (gehören dem Aufrufer).</summary>
    internal static (SecureBuffer TagKey, SecureBuffer MasterTag) NewTags(SecureBuffer dek, SecureBuffer password)
    {
        var tagKey = MasterTag.Key(dek);
        try
        {
            return (tagKey, MasterTag.Tag(tagKey, password));
        }
        catch
        {
            tagKey.Dispose();
            throw;
        }
    }

    /// <summary>Zugangswechsel mit neuem DEK schreiben und übernehmen (Passwort, Kit, Stufe, Vernichtungs-Passwort). Nur
    /// unter <see cref="WriteLock"/>. <paramref name="ownsKeys"/>: DEK und Tags gehören dem Vorgang (bei einem Fehler vor
    /// dem Schreiben frei); sonst stammen sie aus dem vorbereiteten Kit und bleiben bei ihm. <paramref name="binding"/>
    /// (F) wird der neue Zustand; ein neues F wird bei einem Fehler frei. Nach dem Schreiben wirft es nicht mehr.</summary>
    internal ulong CommitNewAccess(State s, VaultHeader header, VaultSlots slots, SecureBuffer dek, SecureBuffer tagKey, SecureBuffer masterTag,
        IReadOnlyList<byte[]> masterReuseTags, VaultContent content, string? reason, SecureBuffer? binding, bool ownsKeys)
    {
        ulong generation;
        VaultContent result;
        try
        {
            RequireUnlocked();
            (generation, result) = Store.Persist(header, slots, dek, content, s.Generation,
                new VaultStore.DiskExpectation.Generation(s.Header.Uuid, s.Generation), reason, binding, newDek: true);
        }
        catch
        {
            if (ownsKeys)
            {
                dek.Dispose();
                tagKey.Dispose();
                masterTag.Dispose();
            }
            if (binding is not null && !ReferenceEquals(binding, s.DuressBinding)) { binding.Dispose(); }
            throw;
        }
        var reuse = ReuseSet(result, tagKey, masterTag, masterReuseTags);
        Commit(s with
        {
            Header = header, Slots = slots, Dek = dek, Content = result, Generation = generation, TagKey = tagKey, MasterTag = masterTag,
            MasterReuseTags = masterReuseTags, Reuse = reuse, Pending = null, MigrationKek = null, DuressBinding = binding,
        });
        return generation;
    }

    /// <summary>Master-Passwort und Faktoren gegen den Kopf im Speicher: Faktoren/Karte (<c>FactorMissing</c>,
    /// <c>WrongCard</c>), Argon2, pwSlot öffnen, DEK vergleichen (<c>WrongPassword</c>).</summary>
    internal void VerifyAccess(SecureBuffer pw, FactorSecrets factors, State s)
    {
        var (kek, p) = FactorKdf.DeriveKek(s.Header, pw, factors, Store.Limits, null);
        using (p)
        using (kek)
        {
            using var dek = Aead.Unwrap(kek, s.Slots.PwSlot, VaultSlots.PwAd(s.Header));
            if (dek is null || !dek.ConstantTimeEquals(s.Dek)) { throw Fehler.WrongPassword(); }
        }
    }

#if DEBUG
    /// <summary>Nur Tests: Kopie des aktuellen DEK.</summary>
    internal SecureBuffer DekForTesting()
    {
        using var scope = Enter();
        using var l = scope.State.Dek.Borrow();
        return SecureBuffer.Copy(l.Span);
    }

    /// <summary>Nur Tests: alle Einträge inkl. gelöschter (Kopien).</summary>
    internal IReadOnlyList<VaultEntry> AllEntriesForTesting
    {
        get { lock (stateLock) { return state is null ? [] : [.. state.Content.Entries.Select(e => e.Copy())]; } }
    }

    internal VaultHeader? HeaderForTesting { get { lock (stateLock) { return state?.Header; } } }

    /// <summary>Nur Tests: Kopie des Inhalts (gehört dem Aufrufer).</summary>
    internal VaultContent? ContentForTesting { get { lock (stateLock) { return state?.Content.Clone(); } } }

    internal DateTimeOffset? RecoveryConfirmedAtForTesting { get { lock (stateLock) { return state?.Content.RecoveryConfirmedAt; } } }
#endif
}

/// <summary>Ziel-Prüfung und Ordner für Klartext-Exporte (SPEC §8 „CSV-Export-Hygiene“). Abgelehnt werden Cloud-Ordner:
/// iCloud Drive (wie Mac, <c>"icloud"</c>) und unter Windows OneDrive (<c>"onedrive"</c>, über die
/// OneDrive-Umgebungsvariablen).</summary>
internal static class ExportLocation
{
    internal static void Check(string directory)
    {
        string full;
        try
        {
            full = Path.GetFullPath(directory);
            var info = new DirectoryInfo(full);
            if (!info.Exists) { throw Fehler.Io("export.directory"); }
            if (info.ResolveLinkTarget(returnFinalTarget: true) is { } target) { full = target.FullName; }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw Fehler.Io("export.directory");
        }
        if (full.Contains("/Library/Mobile Documents/", StringComparison.Ordinal) || full.EndsWith("/Library/Mobile Documents", StringComparison.Ordinal))
        {
            throw Fehler.ExportLocationRejected("icloud");
        }
        foreach (var name in new[] { "OneDrive", "OneDriveConsumer", "OneDriveCommercial" })
        {
            if (Environment.GetEnvironmentVariable(name) is { Length: > 0 } root && IsInside(full, Path.GetFullPath(root)))
            {
                throw Fehler.ExportLocationRejected("onedrive");
            }
        }
    }

    private static bool IsInside(string path, string root)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var r = root.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return path.Equals(r, comparison) || path.StartsWith(r + Path.DirectorySeparatorChar, comparison);
    }

    /// <summary><c>Siegel-Export-&lt;JJJJ-MM-TT&gt;.noindex</c> (0700, vom Indizieren ausgenommen); besteht er, mit Zähler.</summary>
    internal static string MakeFolder(string directory, DateTime localNow)
    {
        var day = localNow.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        for (var n = 1; n <= 100; n++)
        {
            var name = "Siegel-Export-" + day + (n == 1 ? "" : "-" + n.ToString(System.Globalization.CultureInfo.InvariantCulture)) + ".noindex";
            var path = Path.Combine(directory, name);
            if (FileIO.Exists(path)) { continue; }
            FileIO.EnsureDirectory(path);
            return path;
        }
        throw Fehler.Io("export.folder");
    }
}
