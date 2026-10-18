using System.Security.Cryptography;
using Siegel.Modell;

namespace Siegel.Core;

// Notfallweg (SPEC §1.3, §1.5, §4, §15): Code bzw. zwei Teile prüfen (mit Fehlerkorrektur), wiederherstellen, auch aus
// Sicherungen, wenn die Tresordatei beschädigt ist. Jede Wiederherstellung setzt Stufe 1 (§16.1). Wie
// VaultStore+Notfall.swift.
public sealed partial class VaultStore
{
    // MARK: Eingabe-Hilfen für die Oberfläche

    /// <summary>Volle Form eines Notfallcodes (55 Zeichen aus dem Alphabet, höchstens 4 „?“)?</summary>
    public static bool RecoveryCodeInputIsComplete(string input) => RecoveryMatching.CodeInputIsComplete(input);

    /// <summary>Wie <see cref="RecoveryCodeInputIsComplete"/>, für einen Teil (56 Zeichen).</summary>
    public static bool RecoveryShareInputIsComplete(string input) => RecoveryMatching.ShareInputIsComplete(input);

    /// <summary>Nummer des Teils (1…3), wenn die Eingabe ein exakt gültiger Teil ist; sonst null.</summary>
    public static int? RecoveryShareIndex(string input) => Shamir.IndexOf(input);

    // MARK: Notfallcode prüfen

    /// <summary>Prüft einen Code gegen den Kopf (inkl. Korrektur). Für einen Treffer liest er nur den Kopf; ohne Treffer
    /// prüft er die Datei-Prüfsumme, bevor er <c>WrongRecoveryCode</c> bzw. <c>RecoveryCodeChecksum</c> meldet.</summary>
    public RecoveryCodeMatch CheckRecoveryCode(string input)
    {
        Fehler.NotNull(input);
        CoreEnvironment.RequireBackgroundThread();
        var symbols = RecoveryCodeCodec.ParseSymbols(input, allowUnknown: true);
        try
        {
            var header = ReadCurrentHeader();
            return WithChecksumOnMiss(null, () => RecoveryMatching.MatchRecoveryCode(symbols, header));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(symbols);
        }
    }

    /// <summary>Zwei Teile (Shamir 2 aus 3) gegen den Kopf, mit Korrektur pro Teil. Genau 2 Eingaben; Ergebnis in der
    /// Reihenfolge der Eingaben.</summary>
    public IReadOnlyList<RecoveryCodeMatch> CheckRecoveryShares(IReadOnlyList<string> inputs)
    {
        CoreEnvironment.RequireBackgroundThread();
        var symbols = RecoveryMatching.ParseShareInputs(inputs);
        try
        {
            var header = ReadCurrentHeader();
            return WithChecksumOnMiss(null, () => RecoveryMatching.MatchRecoveryShares(symbols, header));
        }
        finally
        {
            foreach (var s in symbols) { CryptographicOperations.ZeroMemory(s); }
        }
    }

    private VaultHeader ReadCurrentHeader() => VaultFile.ParseHeaderOnly(FileIO.ReadPrefix(VaultPath, VaultHeader.MaxSize));

    /// <summary>Kein Treffer (falsches Kit oder Prüfsumme): erst Bitfäule der ganzen Datei ausschliessen.</summary>
    private T WithChecksumOnMiss<T>(string? path, Func<T> body)
    {
        try
        {
            return body();
        }
        catch (SiegelException e) when (e.Code is SiegelErrorCode.WrongRecoveryCode or SiegelErrorCode.RecoveryCodeChecksum)
        {
            VaultFile.VerifyChecksum(FileIO.Read(path ?? VaultPath, FileFormat.MaxFileBytes));
            throw;
        }
    }

    // MARK: Notfallweg für eine bestimmte Datei (v4.4, Befund datei-3)

    /// <summary>Wie <see cref="CheckRecoveryCode(string)"/>, gegen den Kopf einer bestimmten Datei. Fehlt sie →
    /// <c>Io("backup.missing")</c>.</summary>
    public RecoveryCodeMatch CheckRecoveryCode(string input, string againstFile)
    {
        Fehler.NotNull(input);
        Fehler.NotNull(againstFile);
        CoreEnvironment.RequireBackgroundThread();
        var symbols = RecoveryCodeCodec.ParseSymbols(input, allowUnknown: true);
        try
        {
            var header = ReadBackupHeader(againstFile);
            return MappingMissing(() => WithChecksumOnMiss(againstFile, () => RecoveryMatching.MatchRecoveryCode(symbols, header)));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(symbols);
        }
    }

    /// <summary>Wie <see cref="CheckRecoveryShares(IReadOnlyList{string})"/>, gegen den Kopf einer bestimmten Datei.</summary>
    public IReadOnlyList<RecoveryCodeMatch> CheckRecoveryShares(IReadOnlyList<string> inputs, string againstFile)
    {
        Fehler.NotNull(againstFile);
        CoreEnvironment.RequireBackgroundThread();
        var symbols = RecoveryMatching.ParseShareInputs(inputs);
        try
        {
            var header = ReadBackupHeader(againstFile);
            return MappingMissing(() => WithChecksumOnMiss(againstFile, () => RecoveryMatching.MatchRecoveryShares(symbols, header)));
        }
        finally
        {
            foreach (var s in symbols) { CryptographicOperations.ZeroMemory(s); }
        }
    }

    /// <summary>Notfallweg für genau diese Datei (gemessen an ihrem eigenen Kopf, egal zu welchem Tresor sie gehört): neues
    /// Master-Passwort, neuer DEK, neues Salz, Stufe 1. Eine bisherige Tresordatei bleibt als „vor-notfall“.</summary>
    public UnlockedVault RecoverBackup(string from, string code, string newMasterPassword, KdfParameters? kdf = null)
    {
        Fehler.NotNull(from);
        Fehler.NotNull(code);
        CoreEnvironment.RequireBackgroundThread();
        var parameters = kdf ?? KdfParameters.Standard;
        CheckNewPassword(newMasterPassword, parameters);
        using var r = RecoveryCodeCodec.Decode(code);
        return RecoverBackup(from, r, newMasterPassword, parameters);
    }

    /// <summary>Wie <see cref="RecoverBackup(string, string, string, KdfParameters?)"/>, mit zwei der drei Teile.</summary>
    public UnlockedVault RecoverBackup(string from, IReadOnlyList<string> shares, string newMasterPassword, KdfParameters? kdf = null)
    {
        Fehler.NotNull(from);
        CoreEnvironment.RequireBackgroundThread();
        var parameters = kdf ?? KdfParameters.Standard;
        CheckNewPassword(newMasterPassword, parameters);
        using var r = RecoveryMatching.CombineShares(shares);
        return RecoverBackup(from, r, newMasterPassword, parameters);
    }

    private UnlockedVault RecoverBackup(string path, SecureBuffer r, string newMasterPassword, KdfParameters kdf)
    {
        var bytes = MappingMissing(() => FileIO.Read(path, FileFormat.MaxFileBytes));
        var file = VaultFile.Parse(bytes);
        if (!RecoveryKem.Matches(r, file.Header.VaultId, file.Header.Pk))
        {
            var codeKit = RecoveryKem.DerivePublicKeys(r, file.Header.VaultId).KitId;
            throw Fehler.WrongRecoveryCode(codeKit, file.Header.Pk.KitId);
        }
        var opened = Unsealed(VaultCrypto.OpenWithRecovery(file, r), r);
        using var pw = PasswordNormalizer.SecureBytes(newMasterPassword);
        if (MasterTag.IsUsedByEntries(pw, opened.Content.Entries))
        {
            opened.Dispose();
            throw Fehler.MasterPasswordReused();
        }
        return Install(opened, pw, new FactorSecrets(), kdf, confirmRecovery: true, recoveryReset: true, reason: BackupNaming.Reason.Recovery);
    }

    /// <summary>Kopf einer gewählten Datei (ohne Prüfsumme; die Prüfung folgt bei einem Fehlschlag bzw. beim Öffnen).</summary>
    private static VaultHeader ReadBackupHeader(string path) =>
        MappingMissing(() => VaultFile.ParseHeaderOnly(FileIO.ReadPrefix(path, VaultHeader.MaxSize)));

    /// <summary>Eine fehlende Sicherungsdatei ist kein fehlender Tresor.</summary>
    private static T MappingMissing<T>(Func<T> body)
    {
        try
        {
            return body();
        }
        catch (SiegelException e) when (e.Code == SiegelErrorCode.VaultMissing)
        {
            throw Fehler.Io("backup.missing");
        }
    }

    // MARK: Wiederherstellen

    /// <summary>Wiederherstellung über den Notfallcode: neuer DEK, neues Master-Passwort, Stufe 1 (keine Faktoren),
    /// angeheftete Sicherung „vor-notfall“. Versiegelte Einträge werden über ihre Notfall-Umschläge entsiegelt.</summary>
    public UnlockedVault Recover(string code, string newMasterPassword, KdfParameters? kdf = null)
    {
        Fehler.NotNull(code);
        CoreEnvironment.RequireBackgroundThread();
        var parameters = kdf ?? KdfParameters.Standard;
        CheckNewPassword(newMasterPassword, parameters);
        using var r = RecoveryCodeCodec.Decode(code);
        return Recover(r, newMasterPassword, parameters);
    }

    /// <summary>Wiederherstellung mit zwei der drei Teile (Stufen 4/5).</summary>
    public UnlockedVault Recover(IReadOnlyList<string> shares, string newMasterPassword, KdfParameters? kdf = null)
    {
        CoreEnvironment.RequireBackgroundThread();
        var parameters = kdf ?? KdfParameters.Standard;
        CheckNewPassword(newMasterPassword, parameters);
        using var r = RecoveryMatching.CombineShares(shares);
        return Recover(r, newMasterPassword, parameters);
    }

    private void CheckNewPassword(string password, KdfParameters kdf)
    {
        Fehler.NotNull(password);
        CheckPolicy(password);
        Limits.Validate(kdf);
    }

    private UnlockedVault Recover(SecureBuffer r, string newMasterPassword, KdfParameters kdf)
    {
        var bytes = FileIO.Read(VaultPath, FileFormat.MaxFileBytes);
        var file = VaultFile.Parse(bytes);
        using var opened = Unsealed(VaultCrypto.OpenWithRecovery(file, r), r);
        using var pw = PasswordNormalizer.SecureBytes(newMasterPassword);
        if (MasterTag.IsUsedByEntries(pw, opened.Content.Entries)) { throw Fehler.MasterPasswordReused(); }
        using var content = opened.Content.Clone();
        content.RecoveryConfirmedAt ??= Clock.Now();
        content.ResetAfterRecovery();
        var (header, slots, dek) = Rekey(file.Header.VaultId, kdf, HeaderFactorFields.None, file.Header.RecoveryScheme, file.Header.Pk, pw,
            new FactorSecrets());
        VaultContent? saved = null;
        try
        {
            var (generation, result) = Persist(header, slots, dek, content, file.Generation,
                new DiskExpectation.Generation(file.Header.Uuid, file.Generation), BackupNaming.Reason.Recovery, newDek: true);
            saved = result;
            return new UnlockedVault(this, header, slots, dek, result, generation, pw);
        }
        catch
        {
            dek.Dispose();
            saved?.Dispose();
            throw;
        }
    }

    /// <summary>Alles entsiegeln, bevor die Wiederherstellung Stufe und Schutz zurücksetzt (§16.1). Übernimmt
    /// <paramref name="opened"/>.</summary>
    internal static OpenedVault Unsealed(OpenedVault opened, SecureBuffer r)
    {
        try
        {
            opened.Content.UnsealAll(r, opened.File.Header);
            return opened;
        }
        catch
        {
            opened.Dispose();
            throw;
        }
    }

    // MARK: Notfallweg, wenn die Tresordatei beschädigt ist

    /// <summary>Sicherungen, die der Notfallweg verwenden darf (neueste zuerst): nur dieselbe vaultID <b>und</b> dasselbe
    /// Kit wie die aktuelle Datei; ist sie beschädigt, gilt ihr Kopf nur, wenn ihn eine Sicherung bestätigt, sonst
    /// stufenweise gleiche vaultID, und erst wenn auch die unlesbar ist, alle.</summary>
    private List<BackupInfo> RecoveryBackupCandidates()
    {
        var all = Backups().Where(b => b.VaultId is not null).ToList();
        VaultHeader? current = null;
        var intact = false;
        try
        {
            current = VaultFile.Parse(FileIO.Read(VaultPath, FileFormat.MaxFileBytes)).Header;
            intact = true;
        }
        catch (SiegelException)
        {
            current = CurrentHeader();
        }
        if (current is null) { return all; }
        var sameKit = all.Where(b => b.VaultId == current.Uuid && ReadHeader(b.Path) is { } h && h.Pk.KitId == current.Pk.KitId).ToList();
        if (intact || sameKit.Count > 0) { return sameKit; }
        var sameVault = all.Where(b => b.VaultId == current.Uuid).ToList();
        return sameVault.Count == 0 ? all : sameVault;
    }

    internal static VaultHeader? ReadHeader(string path)
    {
        try
        {
            return VaultFile.ParseHeaderOnly(FileIO.ReadPrefix(path, VaultHeader.MaxSize));
        }
        catch (SiegelException)
        {
            return null;
        }
    }

    /// <summary>Gleiche Auswahl wie der Wiederherstellungsweg; pro (vaultID, Kit) nur einmal. Kein Treffer → derselbe
    /// Fehler wie gegen die Datei (bzw. <c>CorruptFile("backup.noneReadable")</c>).</summary>
    private T MatchAgainstBackups<T>(Func<VaultHeader, T> match)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        SiegelException? lastError = null;
        foreach (var backup in RecoveryBackupCandidates())
        {
            if (ReadHeader(backup.Path) is not { } header) { continue; }
            if (!seen.Add(Bytes.GuidText(header.Uuid) + header.Pk.KitId)) { continue; }
            try
            {
                return match(header);
            }
            catch (SiegelException e)
            {
                lastError = e;
            }
        }
        throw lastError ?? Fehler.Corrupt("backup.noneReadable");
    }

    /// <summary>Prüft einen Code gegen die Sicherungen (inkl. Korrektur), für den Notfallweg bei beschädigter Datei.</summary>
    public RecoveryCodeMatch CheckRecoveryCodeAgainstBackups(string input)
    {
        Fehler.NotNull(input);
        CoreEnvironment.RequireBackgroundThread();
        var symbols = RecoveryCodeCodec.ParseSymbols(input, allowUnknown: true);
        try
        {
            return MatchAgainstBackups(h => RecoveryMatching.MatchRecoveryCode(symbols, h));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(symbols);
        }
    }

    /// <summary>Wie <see cref="CheckRecoveryCodeAgainstBackups"/>, für zwei Teile.</summary>
    public IReadOnlyList<RecoveryCodeMatch> CheckRecoverySharesAgainstBackups(IReadOnlyList<string> inputs)
    {
        CoreEnvironment.RequireBackgroundThread();
        var symbols = RecoveryMatching.ParseShareInputs(inputs);
        try
        {
            return MatchAgainstBackups(h => RecoveryMatching.MatchRecoveryShares(symbols, h));
        }
        finally
        {
            foreach (var s in symbols) { CryptographicOperations.ZeroMemory(s); }
        }
    }

    /// <summary>Notfallweg bei beschädigter Tresordatei: öffnet die neueste lesbare Sicherung, die dieser Code öffnet
    /// (gemessen an ihrem eigenen Kopf), und setzt sie mit neuem Master-Passwort, DEK, Salz und Stufe 1 ein. Die
    /// beschädigte Datei wird als „beschaedigt-…“ abgelegt.</summary>
    public (UnlockedVault Vault, BackupInfo Backup) RecoverFromNewestReadableBackup(string code, string newMasterPassword,
        KdfParameters? kdf = null)
    {
        Fehler.NotNull(code);
        CoreEnvironment.RequireBackgroundThread();
        var parameters = kdf ?? KdfParameters.Standard;
        CheckNewPassword(newMasterPassword, parameters);
        using var r = RecoveryCodeCodec.Decode(code);
        return RecoverFromBackups(r, newMasterPassword, parameters);
    }

    /// <summary>Wie <see cref="RecoverFromNewestReadableBackup(string, string, KdfParameters?)"/>, mit zwei Teilen.</summary>
    public (UnlockedVault Vault, BackupInfo Backup) RecoverFromNewestReadableBackup(IReadOnlyList<string> shares, string newMasterPassword,
        KdfParameters? kdf = null)
    {
        CoreEnvironment.RequireBackgroundThread();
        var parameters = kdf ?? KdfParameters.Standard;
        CheckNewPassword(newMasterPassword, parameters);
        using var r = RecoveryMatching.CombineShares(shares);
        return RecoverFromBackups(r, newMasterPassword, parameters);
    }

    private (UnlockedVault Vault, BackupInfo Backup) RecoverFromBackups(SecureBuffer r, string newMasterPassword, KdfParameters kdf)
    {
        using var pw = PasswordNormalizer.SecureBytes(newMasterPassword);
        foreach (var backup in RecoveryBackupCandidates())
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
            if (!RecoveryKem.Matches(r, file.Header.VaultId, file.Header.Pk)) { continue; }
            OpenedVault opened;
            try
            {
                opened = Unsealed(VaultCrypto.OpenWithRecovery(file, r), r);
            }
            catch (SiegelException e) when (e.Code == SiegelErrorCode.CorruptFile)
            {
                continue;
            }
            if (MasterTag.IsUsedByEntries(pw, opened.Content.Entries))
            {
                opened.Dispose();
                throw Fehler.MasterPasswordReused();
            }
            var vault = Install(opened, pw, new FactorSecrets(), kdf, confirmRecovery: true, recoveryReset: true,
                reason: BackupNaming.Reason.Recovery);
            return (vault, backup);
        }
        throw Fehler.Corrupt("backup.noneReadable");
    }
}
