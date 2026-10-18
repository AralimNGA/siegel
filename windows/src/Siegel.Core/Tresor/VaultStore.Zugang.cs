using Siegel.Modell;
using Siegel.Werkzeuge;

namespace Siegel.Core;

// Anlegen, Kopf-Auskunft, Entsperren (mit Faktoren), Wiederherstellen/Einspielen von Sicherungen (SPEC §4, §13, §22),
// wie VaultStore+Zugang.swift.
public sealed partial class VaultStore
{
    // MARK: Anlegen

    /// <summary>Neuer Tresor in Stufe 1 (Format v2, keine Faktoren, ein Notfallcode). Höhere Stufen danach über
    /// <see cref="UnlockedVault.ChangeSecurityLevel"/>.</summary>
    public (UnlockedVault Vault, PendingRecovery Recovery) Create(string masterPassword, KdfParameters? kdf = null)
    {
        Fehler.NotNull(masterPassword);
        CoreEnvironment.RequireBackgroundThread();
        var parameters = kdf ?? KdfParameters.Standard;
        CheckPolicy(masterPassword);
        Limits.Validate(parameters);
        if (VaultExists) { throw Fehler.VaultAlreadyExists(); }
        using var pw = PasswordNormalizer.SecureBytes(masterPassword);
        var vaultId = Bytes.OfGuid(Zufall.NewGuid());
        using var r = SecureBuffer.Random(RecoveryKem.RBytes);
        var pk = RecoveryKem.DerivePublicKeys(r, vaultId);
        var (header, slots, dek) = Rekey(vaultId, parameters, HeaderFactorFields.None, RecoveryScheme.SingleCode, pk, pw, new FactorSecrets());
        VaultContent? saved = null;
        try
        {
            using var empty = VaultContent.Empty(Clock.Now());
            var (generation, content) = Persist(header, slots, dek, empty, 0, new DiskExpectation.Absent(), null, newDek: true);
            saved = content;
            var vault = new UnlockedVault(this, header, slots, dek, content, generation, pw);
            var code = new RecoveryCode(RecoveryCodeCodec.Format(r), pk.KitId);
            return (vault, new PendingRecovery(code, RandomConfirmationGroups()));
        }
        catch
        {
            dek.Dispose();
            saved?.Dispose();
            throw;
        }
    }

    /// <summary>MasterPasswordPolicy (§1.6) auf das abgebildete Passwort; sonst <c>PasswordTooWeak</c>.</summary>
    internal static void CheckPolicy(string password)
    {
        var (bits, ok) = MasterPasswordPolicy.Check(PasswordNormalizer.Normalize(password));
        if (!ok) { throw Fehler.PasswordTooWeak(bits); }
    }

    // MARK: Kopf-Auskunft (§13.3)

    /// <summary>Liest nur KOPF + Prüfsumme (kein Argon2). Fehlende Datei → <c>VaultMissing</c>; Bitfäule →
    /// <c>CorruptFile</c>; neuere Version → <c>UnsupportedVersion</c>.</summary>
    public static VaultHeaderInfo Inspect(string path)
    {
        Fehler.NotNull(path);
        return VaultFile.Inspect(FileIO.Read(path, FileFormat.MaxFileBytes));
    }

    public VaultHeaderInfo Inspect() => Inspect(VaultPath);

    /// <summary>Nur der Kopf, <b>ohne</b> Prüfsumme – ausdrücklich ungeprüft, nur für die Wahl Code oder Teile im
    /// Notfallweg (v4.4, Befund datei-4).</summary>
    public static VaultHeaderInfo InspectHeaderUnverified(string path)
    {
        Fehler.NotNull(path);
        return VaultFile.ParseHeaderOnly(FileIO.ReadPrefix(path, VaultHeader.MaxSize)).Info;
    }

    public VaultHeaderInfo InspectHeaderUnverified() => InspectHeaderUnverified(VaultPath);

    // MARK: Entsperren

    /// <summary>Ohne Faktoren (Stufe 1 bzw. Format v1). Verlangt die Datei Faktoren → <c>FactorMissing</c>.</summary>
    public UnlockOutcome Unlock(string masterPassword) => Unlock(masterPassword, new FactorSecrets());

    /// <summary>
    /// Entsperren mit den rohen Faktor-Werten, die <see cref="Inspect()"/> verlangt (§13.1). Fehlt einer →
    /// <c>FactorMissing</c> (vor Argon2); falsche Karte → <c>WrongCard</c>; falsches Passwort oder Faktor →
    /// <c>WrongPassword</c>. Selbstvernichtung (§23): zuerst der Totmann-Schalter; mit Vernichtungs-Passwort laufen immer
    /// beide Argon2 gleichzeitig; passt das Vernichtungs-Passwort, wird zuerst V vernichtet (Vernichtungs-Sitzung, nach
    /// aussen wie normal). Nur <c>WrongPassword</c> zählt als Fehlversuch. Das erste echte Entsperren nach einer
    /// Vernichtungs-Sitzung erneuert DEK und Salz (v4.4). Die Faktoren gehören weiter dem Aufrufer.
    /// </summary>
    public UnlockOutcome Unlock(string masterPassword, FactorSecrets factors)
    {
        Fehler.NotNull(masterPassword);
        Fehler.NotNull(factors);
        CoreEnvironment.RequireBackgroundThread();
        using var pw = PasswordNormalizer.SecureBytes(masterPassword);
        TryCheckDeadman();
        var probe = ReadDuressProbe();
        using var cache = new KekCache();
        using var duressCache = new SecretCache();
        UnlockAttempt attempt;
        try
        {
            try
            {
                attempt = OpenForUnlock(pw, factors, cache, probe, duressCache);
            }
            catch (SiegelException e) when (IsRetryable(e))
            {
                // Beschädigt: kurz warten und genau einmal neu lesen (gleiches Salz → Argon2 wiederverwenden).
                if (CorruptRetryDelay > TimeSpan.Zero) { Thread.Sleep(CorruptRetryDelay); }
                attempt = OpenForUnlock(pw, factors, cache, probe, duressCache);
            }
        }
        catch (SiegelException e) when (e.Code == SiegelErrorCode.WrongPassword)
        {
            RecordFailedAttempt();
            throw Fehler.WrongPassword();
        }
        if (attempt.Genuine is { } opened)
        {
            var header = opened.File.Header;
            // Nach einer Vernichtungs-Sitzung: DEK erneuern (nicht bei Rollback-Verdacht; scheitert das Schreiben, öffnet
            // der Tresor wie bisher und das nächste echte Entsperren versucht es neu).
            if (header.FormatVersion >= 2 && RekeyPending() && RollbackSeen(opened.File) is null)
            {
                try
                {
                    var fresh = RekeyAfterDuress(opened, pw, factors, masterPassword);
                    opened.Dispose();
                    return new UnlockOutcome(fresh, null, fresh.Generation);
                }
                catch (SiegelException)
                {
                    // wie bisher öffnen
                }
            }
            UnlockedVault vault;
            try
            {
                vault = new UnlockedVault(this, header, opened.File.Slots, opened.Dek, opened.Content, opened.File.Generation, pw,
                    masterPassword, factors, opened.MigrationKek);
            }
            catch
            {
                opened.Dispose();
                throw;
            }
            // Inhalt und DEK gehören jetzt dem Tresor; er ist noch nicht herausgegeben, also unverändert.
            using (var binding = DuressCrypto.TryBinding(header, factors))
            {
                RecordGenuineUnlock(opened.Content, header, opened.Dek, binding);
            }
            return Outcome(vault, opened.File);
        }
        var (file, dek) = attempt.Duress!.Value;
#if DEBUG
        TestHooks.AfterDuressArgon?.Invoke();
#endif
        RecordDuressUnlock(Clock.Now());
        // Veralteter Umschlag oder falscher Faktor: vernichtet ist trotzdem.
        if (dek is null) { throw Fehler.WrongPassword(); }
        VaultContent content;
        try
        {
            (content, _) = VaultCrypto.DecryptPayload(file, dek);
        }
        catch (SiegelException)
        {
            dek.Dispose();
            throw Fehler.WrongPassword();
        }
        UnlockedVault duressVault;
        try
        {
            duressVault = new UnlockedVault(this, file.Header, file.Slots, dek, content, file.Generation, pw, masterPassword, factors,
                duress: true);
        }
        catch
        {
            dek.Dispose();
            content.Dispose();
            throw;
        }
        return Outcome(duressVault, file);
    }

    /// <summary>Rollback-Stolperdraht (auch in einer Vernichtungs-Sitzung gleich).</summary>
    private UnlockOutcome Outcome(UnlockedVault vault, VaultFile file)
    {
        if (RollbackSeen(file) is { } seen) { return new UnlockOutcome(vault, seen, file.Generation); }
        RollbackGuard.Record(file.Header.Uuid, file.Generation);
        return new UnlockOutcome(vault, null, file.Generation);
    }

    /// <summary>Höhere schon gesehene Generation (Rollback-Verdacht), sonst null.</summary>
    private ulong? RollbackSeen(VaultFile file) =>
        RollbackGuard.LastSeenGeneration(file.Header.Uuid) is { } seen && seen > file.Generation ? seen : null;

    /// <summary>Erstes echtes Entsperren nach einer Vernichtungs-Sitzung (v4.4): neuer DEK und neues Salz (gleiche Stufe,
    /// Faktoren, Kit), sofort geschrieben. Ein Argon2 mehr.</summary>
    private UnlockedVault RekeyAfterDuress(OpenedVault opened, SecureBuffer password, FactorSecrets factors, string rawPassword)
    {
        var source = opened.File.Header;
        var (header, slots, dek) = Rekey(source.VaultId, source.Kdf, source.FactorFields, source.RecoveryScheme, source.Pk, password, factors);
        VaultContent? saved = null;
        try
        {
            using var binding = DuressCrypto.Binding(header, factors);
            var (generation, content) = Persist(header, slots, dek, opened.Content, opened.File.Generation,
                new DiskExpectation.Generation(source.Uuid, opened.File.Generation), null, binding, newDek: true);
            saved = content;
            var vault = new UnlockedVault(this, header, slots, dek, content, generation, password, rawPassword, factors);
            RecordGenuineUnlock(content, header, dek, binding);
            return vault;
        }
        catch
        {
            dek.Dispose();
            saved?.Dispose();
            throw;
        }
    }

    internal static bool IsRetryable(SiegelException e) =>
        e.Code is SiegelErrorCode.CorruptFile or SiegelErrorCode.KdfParametersOutOfRange or SiegelErrorCode.UnsupportedVersion;

    /// <summary>Ergebnis eines Öffnungsversuchs: echt (geöffnet) oder Vernichtungs-Passwort erkannt (DEK aus dem Umschlag,
    /// null = Umschlag passt nicht mehr).</summary>
    private sealed record UnlockAttempt(OpenedVault? Genuine, (VaultFile File, SecureBuffer? Dek)? Duress);

    private UnlockAttempt OpenForUnlock(SecureBuffer password, FactorSecrets factors, KekCache cache, DuressProbe? probe,
        SecretCache duressCache)
    {
        var bytes = FileIO.Read(VaultPath, FileFormat.MaxFileBytes);
        var file = VaultFile.Parse(bytes);
        if (probe is null)
        {
            return new UnlockAttempt(VaultCrypto.OpenWithPassword(file, password, factors, Limits, cache), null);
        }
        // Gleiche Reihenfolge wie der Passwortweg: Faktoren/Karte vor jeder Rechnung, dann beide Argon2 zugleich.
        FactorKdf.Precheck(file.Header, factors);
        var (p, d) = BothArgon(file.Header, password, cache, probe.Salt, duressCache);
        SecureBuffer? master;
        using (var kek = FactorKdf.Kek(p, file.Header, factors))
        {
            master = Aead.Unwrap(kek, file.Slots.PwSlot, VaultSlots.PwAd(file.Header));
        }
        // Der Umschlag ist an die Faktoren gebunden (F, v4.4); erkannt wird nur über d. Wie Swift in beiden Fällen gerechnet.
        (bool Recognized, SecureBuffer? Dek)? duress = null;
        if (probe.File is { } df)
        {
            using var binding = DuressCrypto.TryBinding(file.Header, factors);
            duress = DuressCrypto.Open(df, d, binding, file.Header.VaultId);
        }
        if (master is not null)
        {
            duress?.Dek?.Dispose();
            try
            {
                var (content, _) = VaultCrypto.DecryptPayload(file, master);
                var opened = new OpenedVault(file, master, content);
                if (file.Header.FormatVersion == 1) { opened.MigrationKek = FactorKdf.Kek(p, [], file.Header.Salt, 0); }
                return new UnlockAttempt(opened, null);
            }
            catch
            {
                master.Dispose();
                throw;
            }
        }
        if (duress is { Recognized: true } x) { return new UnlockAttempt(null, (file, x.Dek)); }
        throw Fehler.WrongPassword();
    }

    // MARK: Sicherungen einsetzen

    public UnlockedVault RestoreBackup(BackupInfo backup, string masterPassword) => RestoreBackup(backup, masterPassword, new FactorSecrets());

    /// <summary>Sicherung als Tresor einsetzen: mit den Faktoren, die <b>ihr</b> Kopf verlangt; DEK und Salz werden erneuert.</summary>
    public UnlockedVault RestoreBackup(BackupInfo backup, string masterPassword, FactorSecrets factors)
    {
        Fehler.NotNull(backup);
        CoreEnvironment.RequireBackgroundThread();
        return OpenAndInstall(backup.Path, masterPassword, factors);
    }

    public UnlockedVault ImportBackup(string path, string masterPassword) => ImportBackup(path, masterPassword, new FactorSecrets());

    public UnlockedVault ImportBackup(string path, string masterPassword, FactorSecrets factors)
    {
        Fehler.NotNull(path);
        CoreEnvironment.RequireBackgroundThread();
        return OpenAndInstall(path, masterPassword, factors);
    }

    /// <summary>Sicherungswege zählen falsche Passwörter wie das Entsperren (§23.2 Nr. 2); ein Erfolg gilt als echtes
    /// Entsperren.</summary>
    private UnlockedVault OpenAndInstall(string path, string masterPassword, FactorSecrets factors)
    {
        Fehler.NotNull(masterPassword);
        Fehler.NotNull(factors);
        using var pw = PasswordNormalizer.SecureBytes(masterPassword);
        TryCheckDeadman();
        byte[] bytes;
        try
        {
            bytes = FileIO.Read(path, FileFormat.MaxFileBytes);
        }
        catch (SiegelException e) when (e.Code == SiegelErrorCode.VaultMissing)
        {
            throw Fehler.Io("backup.missing");
        }
        var file = VaultFile.Parse(bytes);
        OpenedVault opened;
        try
        {
            opened = VaultCrypto.OpenWithPassword(file, pw, factors, Limits);
        }
        catch (SiegelException e) when (e.Code == SiegelErrorCode.WrongPassword)
        {
            RecordFailedAttempt();
            throw Fehler.WrongPassword();
        }
        return Install(opened, pw, factors, rawPassword: masterPassword);
    }

    public (UnlockedVault Vault, BackupInfo Backup) RestoreNewestReadableBackup(string masterPassword) =>
        RestoreNewestReadableBackup(masterPassword, new FactorSecrets());

    /// <summary>Neueste lesbare Sicherung öffnen (absteigend; gleiches Salz + Parameter → Argon2 wiederverwenden). Fehlt
    /// der neuesten Sicherung ein Faktor (<c>FactorMissing</c>) bzw. passt die Karte nicht (<c>WrongCard</c>), endet die
    /// Suche dort. Falsches Passwort → ältere probieren; ohne Treffer <c>WrongPassword</c>, sonst
    /// <c>CorruptFile("backup.noneReadable")</c>.</summary>
    public (UnlockedVault Vault, BackupInfo Backup) RestoreNewestReadableBackup(string masterPassword, FactorSecrets factors)
    {
        Fehler.NotNull(masterPassword);
        Fehler.NotNull(factors);
        CoreEnvironment.RequireBackgroundThread();
        using var pw = PasswordNormalizer.SecureBytes(masterPassword);
        TryCheckDeadman();
        var currentId = CurrentHeader()?.Uuid;
        var candidates = Backups();
        if (currentId is { } id && candidates.Any(b => b.VaultId == id)) { candidates = [.. candidates.Where(b => b.VaultId == id)]; }
        using var cache = new KekCache();
        var sawWrongPassword = false;
        foreach (var backup in candidates)
        {
            VaultFile file;
            try
            {
                file = VaultFile.Parse(FileIO.Read(backup.Path, FileFormat.MaxFileBytes));
            }
            catch (SiegelException)
            {
                continue;
            }
            OpenedVault opened;
            try
            {
                opened = VaultCrypto.OpenWithPassword(file, pw, factors, Limits, cache);
            }
            catch (SiegelException e) when (e.Code == SiegelErrorCode.WrongPassword)
            {
                sawWrongPassword = true;
                continue;
            }
            catch (SiegelException e) when (e.Code is SiegelErrorCode.FactorMissing or SiegelErrorCode.WrongCard or SiegelErrorCode.KdfFailed)
            {
                throw;
            }
            catch (SiegelException)
            {
                continue;
            }
            return (Install(opened, pw, factors, rawPassword: masterPassword), backup);
        }
        if (sawWrongPassword)
        {
            RecordFailedAttempt();
            throw Fehler.WrongPassword();
        }
        throw Fehler.Corrupt("backup.noneReadable");
    }

    // MARK: Interna: neuer Zugang

    /// <summary>Neuer Kopf v2 (neues Salz), Argon2, Faktoren, neuer DEK und beide Slots (alle drei gehören dem Aufrufer).</summary>
    internal (VaultHeader Header, VaultSlots Slots, SecureBuffer Dek) Rekey(byte[] vaultId, KdfParameters kdf, HeaderFactorFields fields,
        RecoveryScheme scheme, RecoveryPublicKeys pk, SecureBuffer password, FactorSecrets factors) =>
        VaultCrypto.Rekey(vaultId, kdf, fields, scheme, pk, password, factors, Limits);

    /// <summary>
    /// Geöffneten Tresor als aktuellen einsetzen (Wiederherstellung/Einspielen): DEK-Rotation, neues Salz, bisherige
    /// Datei als „vor-wiederherstellung“ bzw. beschädigt sichern. Faktoren und Stufe der Sicherung bleiben;
    /// <paramref name="recoveryReset"/> (Notfallweg) setzt Stufe 1. Ist nicht belegt, dass das Kit dasselbe wie in der
    /// bisherigen Datei ist, gilt es als unbestätigt. Übernimmt <paramref name="opened"/> (gibt es frei).
    /// </summary>
    internal UnlockedVault Install(OpenedVault opened, SecureBuffer password, FactorSecrets factors, KdfParameters? kdf = null,
        bool confirmRecovery = false, bool recoveryReset = false, string reason = BackupNaming.Reason.Restore, string? rawPassword = null)
    {
        using (opened)
        {
            var disk = ObserveDisk();
            if (disk?.NewerVersion is { } v) { throw Fehler.UnsupportedVersion(v); }
            var source = opened.File.Header;
            var baseGeneration = opened.File.Generation;
            if (disk?.File is { } f && f.Header.Uuid == source.Uuid) { baseGeneration = Math.Max(baseGeneration, f.Generation); }
            using var content = opened.Content.Clone();
            var sameKit = disk?.File is { } df && df.Header.Uuid == source.Uuid && df.Header.Pk.KitId == source.Pk.KitId;
            if (confirmRecovery)
            {
                // Notfallweg: Der eingegebene Code hat genau dieses Kit geöffnet – damit ist es bestätigt.
                content.RecoveryConfirmedAt ??= Clock.Now();
            }
            else if (!sameKit)
            {
                content.RecoveryConfirmedAt = null;
            }
            if (recoveryReset) { content.ResetAfterRecovery(); }
            var used = recoveryReset ? new FactorSecrets() : factors;
            var (header, slots, dek) = Rekey(source.VaultId, kdf ?? source.Kdf, recoveryReset ? HeaderFactorFields.None : source.FactorFields,
                source.RecoveryScheme, source.Pk, password, used);
            VaultContent? saved = null;
            try
            {
                using var binding = DuressCrypto.Binding(header, used);
                var (generation, result) = Persist(header, slots, dek, content, baseGeneration, new DiskExpectation.Observed(disk?.Digest), reason,
                    binding, newDek: true);
                saved = result;
                var vault = new UnlockedVault(this, header, slots, dek, result, generation, password, rawPassword, used);
                // Mit dem Master-Passwort der Sicherung geöffnet (bzw. Notfallweg): gilt als echtes Entsperren (§23).
                RecordGenuineUnlock(result, header, dek, binding);
                return vault;
            }
            catch
            {
                dek.Dispose();
                saved?.Dispose();
                throw;
            }
        }
    }
}
