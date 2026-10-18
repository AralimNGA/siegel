using System.Security.Cryptography;
using Siegel.Modell;
using Siegel.Werkzeuge;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Core;

// Eintrags-Schutz (SPEC §16), Offline-Sicherheitsbericht (§17), Exporte (§8, §19) und die async-Varianten, die
// versiegelte Einträge mitnehmen müssen – wie UnlockedVault+Schutz.swift. Dazu die async-Varianten für die
// Windows-Hello-Art (W4.1), deren Versiegeln eine Signatur braucht.
public sealed partial class UnlockedVault
{
    // MARK: Aufdecken (§16)

    /// <summary>
    /// Geheimteile eines Eintrags. Schutz 1: direkt, ohne Anbieter. Schutz ≥ 2: Anbieter Pflicht (sonst
    /// <c>FactorMissing</c> mit der ersten verlangten Art); gerufen werden nur die Methoden der Maske, je einmal. Falsche
    /// Karte → <c>WrongCard</c>; anderer falscher Faktor → <c>WrongPassword</c>. Wird während der Freigabe gesperrt →
    /// <c>Io("vault.locked")</c>. Vernichtbare Einträge über V; vernichtet → <c>FactorUnavailable(secureEnclave)</c> ohne
    /// Anbieter-Aufruf. In einer Vernichtungs-Sitzung gibt es sie nicht (<c>Io("entry.notFound")</c>).
    /// </summary>
    public async Task<EntrySecrets> RevealSecretsAsync(Guid id, IEntryFactorProvider? factors, CancellationToken cancellationToken = default)
    {
        using var scope = Enter();
        var s = scope.State;
        var i = VisibleIndex(s.Content, id);
        if (i < 0) { throw Fehler.Io("entry.notFound"); }
        var e = s.Content.Entries[i];
        if (!e.SecretsSealed) { return VaultContent.SecretsOf(e); }
        if (s.Content.Destructible.ContainsKey(id)) { return await RevealDestructibleAsync(e, s, factors, cancellationToken).ConfigureAwait(false); }
        var mask = e.Protection.Factors();
        if (!s.Content.Sealed.TryGetValue(id, out var sealedSecrets)) { throw Fehler.Corrupt("entry.sealed"); }
        EntrySealing.RequireEnrolled(mask, s.Content.EntryFactors);
        var provider = factors ?? throw Fehler.FactorMissing(mask.Kinds().FirstOrDefault(FactorKind.SecureEnclave));
        var keys = s.Content.SealingKeys(s.Header.VaultId);
        var released = await EntrySealing.ReleaseAsync(sealedSecrets.Blob.Factors, id, mask, keys.Factors, keys.VaultId,
            new LockCheckedEntryFactors(provider, this), EntrySealing.SePart.ForEntries(keys.Factors), cancellationToken).ConfigureAwait(false);
        try
        {
            if (IsLocked) { throw Fehler.Locked(); }
            using var padded = EntrySealing.Open(sealedSecrets.Blob, id, (byte)e.Protection, mask, EntrySealing.EntryAd, keys.Base, keys.VaultId,
                released) ?? throw Fehler.WrongPassword();
            return EntrySealing.DecodeSecrets(padded);
        }
        finally
        {
            foreach (var r in released) { r.Dispose(); }
        }
    }

    /// <summary>Vernichtbaren Eintrag über V (+ Karte, + Sicherheitsschlüssel) öffnen.</summary>
    internal async Task<EntrySecrets> RevealDestructibleAsync(VaultEntry e, State s, IEntryFactorProvider? provider,
        CancellationToken cancellationToken)
    {
        if (!s.Content.Destructible.TryGetValue(e.Id, out var blob) || s.Content.Destruction?.VKey is not { } v)
        {
            throw Fehler.Corrupt("entry.sealed");
        }
        if (DestructionKeyDestroyed(s.Content)) { throw Fehler.FactorUnavailable(FactorKind.SecureEnclave); }
        var mask = e.Protection.Factors();
        var part = EntrySealing.SePart.ForDestruction(v);
        EntrySealing.RequireEnrolled(part.Required(mask), s.Content.EntryFactors);
        if (provider is null) { throw Fehler.FactorMissing(FactorKind.SecureEnclave); }
        var keys = s.Content.SealingKeys(s.Header.VaultId);
        var released = await EntrySealing.ReleaseAsync(blob.Factors, e.Id, mask, keys.Factors, keys.VaultId,
            new LockCheckedEntryFactors(provider, this), part, cancellationToken).ConfigureAwait(false);
        try
        {
            if (IsLocked) { throw Fehler.Locked(); }
            using var padded = EntrySealing.Open(blob, e.Id, (byte)e.Protection, mask, EntrySealing.DestructibleAd, keys.Base, keys.VaultId,
                released, EntrySealing.DestructibleKeyInfo) ?? throw Fehler.WrongPassword();
            return EntrySealing.DecodeSecrets(padded);
        }
        finally
        {
            foreach (var r in released) { r.Dispose(); }
        }
    }

    /// <summary>Schutz setzen und Geheimteile schreiben (§16, §22) – der einzige Weg, die Geheimteile eines versiegelten
    /// Eintrags zu ändern. <paramref name="secrets"/> ersetzen die bisherigen ganz; der Verlauf wird nach §3 gekürzt.
    /// Schutz ≥ 2 verlangt die eingerichteten Faktoren und versiegelt sofort neu. Vernichtbare Einträge bleiben
    /// vernichtbar (Schutz &lt; 4 → <c>NotAllowedAtLevel</c>); vernichtete → <c>Io("entry.destroyed")</c>. Mit der
    /// Windows-Hello-Art → <see cref="SetProtectionAsync"/>.</summary>
    public void SetProtection(EntryProtection protection, Guid id, EntrySecrets secrets) => SetProtection(protection, id, secrets, null);

    internal void SetProtection(EntryProtection protection, Guid id, EntrySecrets secrets, HelloSealing? hello)
    {
        Fehler.NotNull(secrets);
        if (!protection.IsValid()) { throw Fehler.Io("entry.protection"); }
        VaultContent.Validate(new VaultEntry { Password = secrets.Password, Notes = secrets.Notes, Totp = secrets.Totp, History = [.. secrets.History] });
        Mutate(null, hello, (content, c) =>
        {
            var i = VisibleIndex(content, id);
            if (i < 0) { throw Fehler.Io("entry.notFound"); }
            var destructible = content.Destructible.ContainsKey(id);
            if (destructible)
            {
                if (DestructionKeyDestroyed(content)) { throw Fehler.Io("entry.destroyed"); }
                if (protection < EntryProtection.Maximal) { throw Fehler.NotAllowedAtLevel(); }
                EntrySealing.RequireEnrolled(protection.Factors() & ~FactorSet.SecureEnclave, content.EntryFactors);
            }
            else
            {
                EntrySealing.RequireEnrolled(protection.Factors(), content.EntryFactors);
            }
            var e = content.Entries[i];
            e.Password = secrets.Password;
            e.Notes = secrets.Notes;
            e.Totp = secrets.Totp;
            e.History = VaultContent.ApplyHistoryRule(
                secrets.History.Where(h => !SwiftStringComparer.Instance.Equals(h.Password, secrets.Password)), c.Now);
            e.SecretsSealed = false;
            e.Protection = protection;
            e.Modified = c.Now;
            content.Sealed.Remove(id);
            content.Destructible.Remove(id);
            if (destructible)
            {
                content.SealDestructible(i, c.Header.VaultId, c.Now, c.Hello);
            }
            else if (protection > EntryProtection.Normal)
            {
                content.Seal(i, c.Header.VaultId, c.Header.Pk, c.Now, c.Hello);
            }
            return true;
        });
    }

    // MARK: Windows-Hello-Art: Versiegeln mit Signatur (W4.1)

    /// <summary>Wie <see cref="Upsert(VaultEntry)"/>; braucht das Versiegeln die Windows-Hello-Art, holt es die Signaturen
    /// über <paramref name="entryFactors"/> (eine je Eintrag bzw. neue Gruppe) und speichert dann. Für die Mac-Art
    /// ohne Anbieter-Aufruf.</summary>
    public Task UpsertAsync(VaultEntry entry, IEntryFactorProvider? entryFactors, CancellationToken cancellationToken = default) =>
        WithHelloAsync(h =>
        {
            Upsert(entry, h);
            return 0;
        }, entryFactors, cancellationToken);

    /// <summary>Wie <see cref="SetProtection(EntryProtection, Guid, EntrySecrets)"/>, mit Signaturen der Windows-Hello-Art.</summary>
    public Task SetProtectionAsync(EntryProtection protection, Guid id, EntrySecrets secrets, IEntryFactorProvider? entryFactors,
        CancellationToken cancellationToken = default) =>
        WithHelloAsync(h =>
        {
            SetProtection(protection, id, secrets, h);
            return 0;
        }, entryFactors, cancellationToken);

    /// <summary>Wie <see cref="ImportEntries(IReadOnlyList{VaultEntry})"/>, mit Signaturen der Windows-Hello-Art.</summary>
    public Task<ImportReport> ImportEntriesAsync(IReadOnlyList<VaultEntry> entries, IEntryFactorProvider? entryFactors,
        CancellationToken cancellationToken = default) =>
        WithHelloAsync(h => ImportEntries(entries, h), entryFactors, cancellationToken);

    /// <summary>Synchroner Kern im Thread-Pool (Argon2 nie auf dem Oberflächen-Thread). Eine Absage über das Token wird
    /// <c>FactorCancelled</c>: nach aussen nur SiegelException.</summary>
    internal static async Task<T> InBackground<T>(Func<T> body, CancellationToken cancellationToken)
    {
        try
        {
            return await Task.Run(body, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw Fehler.FactorCancelled();
        }
    }

    internal static Task InBackground(Action body, CancellationToken cancellationToken) =>
        InBackground(() =>
        {
            body();
            return 0;
        }, cancellationToken);

    /// <summary>Führt eine Änderung aus; fehlen der Hello-Art Signaturen (nichts geschrieben), holt es sie und wiederholt
    /// (höchstens vier Runden). Läuft im Thread-Pool.</summary>
    internal async Task<T> WithHelloAsync<T>(Func<HelloSealing, T> body, IEntryFactorProvider? provider, CancellationToken cancellationToken)
    {
        using var hello = new HelloSealing();
        for (var round = 0; round < 4; round++)
        {
            try
            {
                return await InBackground(() => body(hello), cancellationToken).ConfigureAwait(false);
            }
            catch (HelloMaterialNeededException)
            {
                if (provider is null) { throw Fehler.FactorMissing(FactorKind.SecureEnclave); }
                if (IsLocked) { throw Fehler.Locked(); }
                await hello.FetchAsync(new LockCheckedEntryFactors(provider, this), cancellationToken).ConfigureAwait(false);
            }
        }
        throw Fehler.FactorMissing(FactorKind.SecureEnclave);
    }

    // MARK: Offline-Sicherheitsbericht (§17)

    internal static readonly TimeSpan OldPasswordAge = TimeSpan.FromDays(365);

    /// <summary>Schwach (zxcvbn-Stufe unter „fair“), wiederverwendet (gleicher reuseTag, Gruppen ab 2), alt (letzte
    /// Passwortänderung vor über 365 Tagen), gleich wie das Master-Passwort. Ohne Netzwerk, auch für versiegelte
    /// Einträge (Metadaten). Gezählt werden nicht gelöschte Einträge mit Passwort.</summary>
    public SecurityReport SecurityReport()
    {
        Scope scope;
        try
        {
            scope = Enter();
        }
        catch (SiegelException)
        {
            return new SecurityReport([], [], [], [], 0);
        }
        using (scope)
        {
            var s = scope.State;
            var now = Clock.Now();
            SecureBuffer? reuseKey = null;
            try
            {
                reuseKey = s.Content.ReuseKey();
            }
            catch (SiegelException)
            {
                reuseKey = null;
            }
            using (reuseKey)
            {
                var weak = new List<Guid>();
                var old = new List<Guid>();
                var byTag = new Dictionary<string, List<Guid>>(StringComparer.Ordinal);
                var tagOrder = new List<string>();
                var total = 0;
                foreach (var e in s.Content.Entries.Where(e => e.DeletedAt is null && !HiddenEntries.Contains(e.Id)))
                {
                    EntryMeta? m;
                    if (e.SecretsSealed) { m = s.Content.Meta.GetValueOrDefault(e.Id); }
                    else if (reuseKey is not null)
                    {
                        m = EntrySealing.Meta(e.Password, s.Content.Meta.GetValueOrDefault(e.Id), reuseKey, VaultContent.EstimatedPasswordChange(e), now);
                    }
                    else { m = null; }
                    if (m?.Tag is not { } tag) { continue; }
                    total++;
                    if (m.Strength is { } st && st < (int)StrengthLevel.Fair) { weak.Add(e.Id); }
                    if (m.Changed is { } changed && now - changed > OldPasswordAge) { old.Add(e.Id); }
                    var key = Bytes.Hex(tag);
                    if (!byTag.TryGetValue(key, out var ids))
                    {
                        byTag[key] = ids = [];
                        tagOrder.Add(key);
                    }
                    ids.Add(e.Id);
                }
                var reused = tagOrder.Select(t => (IReadOnlyList<Guid>)byTag[t]).Where(g => g.Count > 1).ToList();
                var same = s.Content.Entries.Where(e => e.DeletedAt is null && s.Reuse.Contains(e.Id) && !HiddenEntries.Contains(e.Id))
                    .Select(e => e.Id).ToList();
                return new SecurityReport(weak, reused, old, same, total);
            }
        }
    }

    // MARK: Freigaben für Zugangswechsel und Exporte

    /// <summary>Anker der Gruppen über den Anbieter freigeben (eine Freigabe pro Gruppe, in Maskenreihenfolge). Nach einem
    /// Sperren unterwegs fragt er keinen Faktor mehr ab (Befund ablaeufe-4). Die ERS gehören dem Aufrufer.</summary>
    internal async Task<Dictionary<Guid, SecureBuffer>> ReleaseGroupsAsync(IReadOnlyList<RecoveryGroup> groups, State s,
        IEntryFactorProvider provider, CancellationToken cancellationToken)
    {
        if (IsLocked) { throw Fehler.Locked(); }
        var keys = s.Content.SealingKeys(s.Header.VaultId);
        var checkedProvider = new LockCheckedEntryFactors(provider, this);
        var output = new Dictionary<Guid, SecureBuffer>();
        try
        {
            foreach (var g in groups)
            {
                output[g.Id] = await EntrySealing.ReleaseAnchorAsync(g, keys, checkedProvider, cancellationToken).ConfigureAwait(false);
            }
            return output;
        }
        catch
        {
            foreach (var v in output.Values) { v.Dispose(); }
            throw;
        }
    }

    /// <summary>Wie <see cref="CommitRecovery(PendingRecovery, IReadOnlyList{string})"/>; bei neuem Kit und versiegelten
    /// Einträgen je Notfall-Gruppe eine Freigabe über <paramref name="entryFactors"/>. Ohne Anbieter → <c>FactorMissing</c>.</summary>
    public async Task CommitRecoveryAsync(PendingRecovery pending, IReadOnlyList<string> confirmation, IEntryFactorProvider? entryFactors,
        CancellationToken cancellationToken = default)
    {
        CheckConfirmation(pending, confirmation);
        var released = new Dictionary<Guid, SecureBuffer>();
        try
        {
            using (var r = SecretOf(pending))
            using (var scope = Enter())
            {
                var s = scope.State;
                if (s.Pending is { } p && p.R.ConstantTimeEquals(r) && !p.Header.Pk.Equals(s.Header.Pk))
                {
                    var needed = s.Content.NeededRecoveryGroups;
                    if (needed.Count > 0)
                    {
                        var provider = entryFactors ?? throw Fehler.FactorMissing(needed[0].Mask.Kinds()[0]);
                        released = await ReleaseGroupsAsync(needed, s, provider, cancellationToken).ConfigureAwait(false);
                    }
                }
            }
            var groups = released;
            await InBackground(() => CommitRecovery(pending, confirmation, groups), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            foreach (var v in released.Values) { v.Dispose(); }
        }
    }

    /// <summary>Wie <see cref="ChangeSecurityLevel(SecurityLevel, string, FactorSecrets, NewFactorMaterial, PendingRecovery?, IReadOnlyList{string})"/>.
    /// Bringt der Wechsel ein neues Kit und gibt es versiegelte Einträge, prüft er zuerst Passwort und Faktoren (Argon2)
    /// und holt dann je Notfall-Gruppe eine Freigabe über <paramref name="entryFactors"/>.</summary>
    public async Task ChangeSecurityLevelAsync(SecurityLevel level, string masterPassword, FactorSecrets currentFactors,
        NewFactorMaterial newFactors, PendingRecovery? recovery, IReadOnlyList<string> recoveryConfirmation, IEntryFactorProvider? entryFactors,
        CancellationToken cancellationToken = default)
    {
        Fehler.NotNull(masterPassword);
        Fehler.NotNull(currentFactors);
        Fehler.NotNull(newFactors);
        Fehler.NotNull(recoveryConfirmation);
        var released = new Dictionary<Guid, SecureBuffer>();
        byte[]? verified = null;
        try
        {
            using (var scope = Enter())
            {
                var s = scope.State;
                var needed = s.Content.NeededRecoveryGroups;
                if (recovery is not null && needed.Count > 0)
                {
                    ValidateMaterial(newFactors);
                    CheckConfirmation(recovery, recoveryConfirmation);
                    var provider = entryFactors ?? throw Fehler.FactorMissing(needed[0].Mask.Kinds()[0]);
                    // Erst Passwort und Faktoren (kein Touch ID für ein falsches Passwort), dann die Freigaben.
                    await InBackground(() =>
                    {
                        using var pw = PasswordNormalizer.SecureBytes(masterPassword);
                        VerifyAccess(pw, currentFactors, s);
                    }, cancellationToken).ConfigureAwait(false);
                    verified = s.Header.Salt;
                    released = await ReleaseGroupsAsync(needed, s, provider, cancellationToken).ConfigureAwait(false);
                }
            }
            var groups = released;
            var salt = verified;
            await InBackground(() => ChangeSecurityLevel(level, masterPassword, currentFactors, newFactors, recovery, recoveryConfirmation, groups, salt),
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            foreach (var v in released.Values) { v.Dispose(); }
        }
    }

    // MARK: Exporte (§8 CSV-Hygiene, §16, §19)

    /// <summary>Nicht gelöscht und Schutz &lt; 4; dazu die Notfall-Gruppen der versiegelten darunter.</summary>
    internal sealed record ExportPlan(IReadOnlyList<VaultEntry> Entries, IReadOnlyList<RecoveryGroup> Needed);

    internal static ExportPlan ExportPlanFor(State s, bool allowed)
    {
        if (!allowed) { throw Fehler.NotAllowedAtLevel(); }
        var list = s.Content.Entries.Where(e => e.DeletedAt is null && e.Protection.ExportAllowed()).ToList();
        var masks = list.Where(e => e.SecretsSealed).Select(e => e.Protection.Factors()).ToHashSet();
        var needed = s.Content.RecoveryGroups.Where(g => masks.Contains(g.Mask)).ToList();
        if (needed.Count != masks.Count) { throw Fehler.Corrupt("entry.sealed"); }
        return new ExportPlan(list, needed);
    }

    /// <summary>Einträge mit Geheimteilen (versiegelte über die freigegebenen Gruppen).</summary>
    internal static List<(VaultEntry Entry, EntrySecrets Secrets)> ExportItems(State s, ExportPlan plan, IReadOnlyDictionary<Guid, SecureBuffer> released)
    {
        var opened = s.Content.SecretsViaGroups(plan.Entries, released, s.Header.VaultId);
        return [.. plan.Entries.Select(e =>
        {
            if (!e.SecretsSealed) { return (e.Copy(), VaultContent.SecretsOf(e)); }
            if (!opened.TryGetValue(e.Id, out var x)) { throw Fehler.Corrupt("entry.sealed"); }
            return (VaultContent.Unsealed(e, x), x);
        })];
    }

    public string ExportCsv(string toParent, string masterPassword) => ExportCsv(toParent, masterPassword, new FactorSecrets());

    /// <summary>Prüft Master-Passwort und Faktoren, lehnt Cloud-Ordner ab und schreibt <c>Siegel-Export-&lt;Datum&gt;.noindex/</c>
    /// mit <c>Siegel-Export.csv</c>. Stufen 4/5 → <c>NotAllowedAtLevel</c> (vor Argon2). Schutz 4/5 fehlt immer;
    /// versiegelte Schutz-2/3-Einträge → async-Variante, hier <c>FactorMissing</c> (vor Argon2).</summary>
    public string ExportCsv(string toParent, string masterPassword, FactorSecrets factors)
    {
        Fehler.NotNull(toParent);
        Fehler.NotNull(masterPassword);
        Fehler.NotNull(factors);
        CoreEnvironment.RequireBackgroundThread();
        using var scope = Enter();
        var s = scope.State;
        var plan = ExportPlanFor(s, s.Content.Level.Policy().AllowCsvExport);
        if (plan.Needed.Count > 0) { throw Fehler.FactorMissing(plan.Needed[0].Mask.Kinds()[0]); }
        using (var pw = PasswordNormalizer.SecureBytes(masterPassword)) { VerifyAccess(pw, factors, s); }
        ExportLocation.Check(toParent);
        return WriteCsv(ExportItems(s, plan, new Dictionary<Guid, SecureBuffer>()), toParent);
    }

    /// <summary>Wie <see cref="ExportCsv(string, string, FactorSecrets)"/>; versiegelte Schutz-2/3-Einträge über eine
    /// Freigabe ihrer Notfall-Gruppe (nach der Passwortprüfung).</summary>
    public async Task<string> ExportCsvAsync(string toParent, string masterPassword, FactorSecrets factors, IEntryFactorProvider? entryFactors,
        CancellationToken cancellationToken = default)
    {
        Fehler.NotNull(toParent);
        Fehler.NotNull(masterPassword);
        Fehler.NotNull(factors);
        return await ExportAsync(s => s.Content.Level.Policy().AllowCsvExport, null, masterPassword, factors, entryFactors, toParent,
            (items, _) => WriteCsv(items, toParent), cancellationToken).ConfigureAwait(false);
    }

    private static string WriteCsv(List<(VaultEntry Entry, EntrySecrets Secrets)> items, string directory)
    {
        byte[] data;
#if DEBUG
        if (TestHooks.CsvExporter is { } hook)
        {
            data = hook(items);
            return WriteExport(data, directory, "Siegel-Export.csv");
        }
#endif
        data = CsvExport.Export(items);
        return WriteExport(data, directory, "Siegel-Export.csv");
    }

    /// <summary>KeePass-Export KDBX 4.1 (§19): nur Stufen 1–3 (sonst <c>NotAllowedAtLevel</c>, vor Argon2), eigenes
    /// Export-Passwort nach MasterPasswordPolicy (<c>PasswordTooWeak</c>), nicht gleich dem Master-Passwort
    /// (<c>MasterPasswordReused</c>), Master-Passwort + Faktoren geprüft, Datei-Hygiene wie CSV.</summary>
    public string ExportKeePass(string toParent, string masterPassword, FactorSecrets factors, string exportPassword)
    {
        Fehler.NotNull(toParent);
        Fehler.NotNull(masterPassword);
        Fehler.NotNull(factors);
        Fehler.NotNull(exportPassword);
        CoreEnvironment.RequireBackgroundThread();
        using var scope = Enter();
        var s = scope.State;
        var plan = ExportPlanFor(s, s.Content.Level.Policy().AllowKeePassExport);
        CheckExportPassword(exportPassword, masterPassword);
        if (plan.Needed.Count > 0) { throw Fehler.FactorMissing(plan.Needed[0].Mask.Kinds()[0]); }
        using (var pw = PasswordNormalizer.SecureBytes(masterPassword)) { VerifyAccess(pw, factors, s); }
        ExportLocation.Check(toParent);
        return WriteKeePass(ExportItems(s, plan, new Dictionary<Guid, SecureBuffer>()), toParent, exportPassword);
    }

    /// <summary>Wie <see cref="ExportKeePass(string, string, FactorSecrets, string)"/>, mit Freigabe der versiegelten
    /// Schutz-2/3-Einträge.</summary>
    public async Task<string> ExportKeePassAsync(string toParent, string masterPassword, FactorSecrets factors, string exportPassword,
        IEntryFactorProvider? entryFactors, CancellationToken cancellationToken = default)
    {
        Fehler.NotNull(toParent);
        Fehler.NotNull(masterPassword);
        Fehler.NotNull(factors);
        Fehler.NotNull(exportPassword);
        return await ExportAsync(s => s.Content.Level.Policy().AllowKeePassExport, () => CheckExportPassword(exportPassword, masterPassword),
            masterPassword, factors, entryFactors, toParent, (items, _) => WriteKeePass(items, toParent, exportPassword),
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<string> ExportAsync(Func<State, bool> allowed, Action? precheck, string masterPassword, FactorSecrets factors,
        IEntryFactorProvider? entryFactors, string toParent, Func<List<(VaultEntry Entry, EntrySecrets Secrets)>, State, string> write,
        CancellationToken cancellationToken)
    {
        using var scope = Enter();
        var s = scope.State;
        var plan = ExportPlanFor(s, allowed(s));
        precheck?.Invoke();
        if (plan.Needed.Count > 0 && entryFactors is null) { throw Fehler.FactorMissing(plan.Needed[0].Mask.Kinds()[0]); }
        await InBackground(() =>
        {
            using var pw = PasswordNormalizer.SecureBytes(masterPassword);
            VerifyAccess(pw, factors, s);
        }, cancellationToken).ConfigureAwait(false);
        ExportLocation.Check(toParent);
        var released = new Dictionary<Guid, SecureBuffer>();
        try
        {
            if (entryFactors is not null && plan.Needed.Count > 0)
            {
                released = await ReleaseGroupsAsync(plan.Needed, s, entryFactors, cancellationToken).ConfigureAwait(false);
            }
            if (IsLocked) { throw Fehler.Locked(); }
            return write(ExportItems(s, plan, released), s);
        }
        finally
        {
            foreach (var v in released.Values) { v.Dispose(); }
        }
    }

    internal static void CheckExportPassword(string exportPassword, string masterPassword)
    {
        VaultStore.CheckPolicy(exportPassword);
        if (VaultStore.PasswordsMatch(exportPassword, masterPassword)) { throw Fehler.MasterPasswordReused(); }
    }

    private static string WriteKeePass(List<(VaultEntry Entry, EntrySecrets Secrets)> items, string directory, string password)
    {
        byte[] data;
#if DEBUG
        if (TestHooks.KeePassExporter is { } hook)
        {
            data = hook(items, password);
            return WriteExport(data, directory, "Siegel-Export.kdbx");
        }
#endif
        try
        {
            data = KeePassExport.Kdbx(items, password);
        }
        catch (SiegelException)
        {
            throw;
        }
#pragma warning disable CA1031 // Fremde Fehler der Werkzeuge werden auf einen festen Code abgebildet (SPEC §5).
        catch (Exception)
#pragma warning restore CA1031
        {
            throw Fehler.Io("export.kdbx");
        }
        return WriteExport(data, directory, "Siegel-Export.kdbx");
    }

    /// <summary>Neuer <c>.noindex</c>-Ordner (0700) mit einer Datei (0600), beide vom Indizieren ausgenommen; scheitert
    /// etwas, bleibt nichts liegen. Die Daten werden danach genullt (bestes Bemühen).</summary>
    internal static string WriteExport(byte[] data, string directory, string fileName)
    {
        try
        {
            var folder = ExportLocation.MakeFolder(directory, DateTime.Now);
            var file = Path.Combine(folder, fileName);
            try
            {
                FileIO.WriteExclusive(file, data);
                FileIO.ExcludeFromIndexing(folder);
                FileIO.ExcludeFromIndexing(file);
            }
            catch (Exception e) when (e is SiegelException or FileIO.ExistsException)
            {
                FileIO.RemoveTemp(file);
                try
                {
                    Directory.Delete(folder);
                }
                catch (Exception d) when (d is IOException or UnauthorizedAccessException)
                {
                    // bleibt leer liegen
                }
                throw e as SiegelException ?? Fehler.Io("export.write");
            }
            return file;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(data);
        }
    }
}

/// <summary>Prüft vor jeder Freigabe, ob der Tresor inzwischen gesperrt ist (Befund ablaeufe-4): danach öffnet keine
/// weitere Abfrage mehr einen Dialog → <c>Io("vault.locked")</c>, ohne den Anbieter zu rufen.</summary>
internal sealed class LockCheckedEntryFactors(IEntryFactorProvider inner, UnlockedVault vault) : IEntryFactorProvider
{
    private void RequireOpen()
    {
        if (vault.IsLocked) { throw Fehler.Locked(); }
    }

    public Task<FactorSecret> SecureEnclaveSharedSecretAsync(Guid keyId, ReadOnlyMemory<byte> ephemeralPublicKey, CancellationToken cancellationToken)
    {
        RequireOpen();
        return inner.SecureEnclaveSharedSecretAsync(keyId, ephemeralPublicKey, cancellationToken);
    }

    public Task<FactorSecret> CardSecretAsync(CancellationToken cancellationToken)
    {
        RequireOpen();
        return inner.CardSecretAsync(cancellationToken);
    }

    public Task<FactorSecret> SecurityKeyOutputAsync(ReadOnlyMemory<byte> credentialId, ReadOnlyMemory<byte> salt, CancellationToken cancellationToken)
    {
        RequireOpen();
        return inner.SecurityKeyOutputAsync(credentialId, salt, cancellationToken);
    }

    public Task<FactorSecret> WindowsHelloSecretAsync(Guid keyId, ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken)
    {
        RequireOpen();
        return inner.WindowsHelloSecretAsync(keyId, challenge, cancellationToken);
    }
}
