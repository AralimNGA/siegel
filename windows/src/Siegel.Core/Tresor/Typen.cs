using System.Globalization;
using System.Text;
using Siegel.Modell;
using Siegel.Werkzeuge.Unicode;

// Öffentliche Typen der Tresor-Schicht (SPEC §8, §22, §23.3), C#-Gegenstücke zu UnlockOutcome, RollbackGuard,
// BackupInfo, PurgeReport, SecondaryBackupResult (Model.swift, RollbackGuard.swift, VaultStore.swift) und den Typen der
// Selbstvernichtung (Selbstvernichtung.swift).
namespace Siegel.Core;

/// <summary>Ergebnis des Entsperrens. Eine Vernichtungs-Sitzung sieht nach aussen genauso aus (§23.3).</summary>
public sealed class UnlockOutcome
{
    internal UnlockOutcome(UnlockedVault vault, ulong? seenGeneration, ulong fileGeneration)
    {
        Vault = vault;
        SeenGeneration = seenGeneration;
        FileGeneration = fileGeneration;
    }

    public UnlockedVault Vault { get; }

    /// <summary>Die Datei ist älter als zuletzt gesehen (Rollback-Stolperdraht, §4): die Oberfläche fragt
    /// „Trotzdem öffnen?“.</summary>
    public bool IsRollbackSuspected => SeenGeneration is not null;

    /// <summary>Zuletzt gesehene Generation (nur bei Rollback-Verdacht).</summary>
    public ulong? SeenGeneration { get; }

    public ulong FileGeneration { get; }

    public override string ToString() => IsRollbackSuspected ? "UnlockOutcome(rollbackSuspected)" : "UnlockOutcome(unlocked)";
}

/// <summary>Rollback-Stolperdraht (SPEC §4): merkt pro vaultID die zuletzt gesehene Generation. Implementierungen
/// speichern nur steigende Werte.</summary>
public interface IRollbackGuard
{
    ulong? LastSeenGeneration(Guid vaultId);

    void Record(Guid vaultId, ulong generation);
}

/// <summary>Nur im Speicher (Tests).</summary>
public sealed class InMemoryRollbackGuard : IRollbackGuard
{
    private readonly Lock gate = new();
    private readonly Dictionary<Guid, ulong> seen = [];

    public ulong? LastSeenGeneration(Guid vaultId)
    {
        lock (gate)
        {
            return seen.TryGetValue(vaultId, out var g) ? g : null;
        }
    }

    public void Record(Guid vaultId, ulong generation)
    {
        lock (gate)
        {
            seen[vaultId] = Math.Max(seen.GetValueOrDefault(vaultId), generation);
        }
    }
}

/// <summary>
/// Dauerhafter Stolperdraht in einer kleinen Textdatei ausserhalb des Tresorordners (Gegenstück zu
/// <c>UserDefaultsRollbackGuard</c>; die Windows-App legt ihn in einen eigenen Unterordner, z. B.
/// <c>LocalState\Waechter\generationen.txt</c>, nicht direkt in <c>LocalState</c>). Je Zeile
/// <c>&lt;UUID&gt; &lt;Generation&gt;</c>, atomar ersetzt. Unlesbare Zeilen werden übergangen. Der Elternordner wird
/// nur angelegt, wenn er fehlt; Rechte oder ACL eines bestehenden Ordners ändert der Wächter nie (Befund robust-4).
/// </summary>
public sealed class FileRollbackGuard(string path) : IRollbackGuard
{
    private readonly Lock gate = new();

    public ulong? LastSeenGeneration(Guid vaultId)
    {
        lock (gate)
        {
            return Load().TryGetValue(vaultId, out var g) ? g : null;
        }
    }

    public void Record(Guid vaultId, ulong generation)
    {
        lock (gate)
        {
            var all = Load();
            if (all.TryGetValue(vaultId, out var current) && current >= generation) { return; }
            all[vaultId] = generation;
            var text = new StringBuilder();
            foreach (var (id, g) in all.OrderBy(p => p.Key))
            {
                text.Append(Bytes.GuidText(id)).Append(' ').Append(g.ToString(CultureInfo.InvariantCulture)).Append('\n');
            }
            var dir = Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".";
            try
            {
                FileIO.EnsureDirectory(dir, restrictExisting: false);
                var tmp = Path.Combine(dir, "." + Path.GetFileName(path) + "." + BackupNaming.RandomHex4() + ".tmp");
                FileIO.WriteExclusive(tmp, Encoding.UTF8.GetBytes(text.ToString()));
                try
                {
                    FileIO.Rename(tmp, path);
                }
                catch (SiegelException)
                {
                    FileIO.RemoveTemp(tmp);
                }
            }
            catch (Exception e) when (e is SiegelException or FileIO.ExistsException)
            {
                // bestes Bemühen wie UserDefaults
            }
        }
    }

    private Dictionary<Guid, ulong> Load()
    {
        var output = new Dictionary<Guid, ulong>();
        byte[] bytes;
        try
        {
            bytes = FileIO.Read(path, 1 << 20);
        }
        catch (SiegelException)
        {
            return output;
        }
        foreach (var line in Encoding.UTF8.GetString(bytes).Split('\n'))
        {
            var parts = line.Split(' ');
            if (parts.Length == 2 && Guid.TryParseExact(parts[0], "D", out var id)
                && ulong.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var g))
            {
                output[id] = Math.Max(output.GetValueOrDefault(id), g);
            }
        }
        return output;
    }
}

/// <summary>Eine Sicherung (lokal oder am zweiten Ort).</summary>
public sealed record BackupInfo(string Path, DateTimeOffset Date, ulong Generation, Guid? VaultId, string? Reason, bool IsExternal)
{
    /// <summary>Kennung wie Swift <c>id: URL</c>.</summary>
    public string Id => Path;
}

/// <summary>Ergebnis von <c>PurgeBackups</c> (SPEC v3.1): Was liess sich nicht entfernen? Die Oberfläche meldet nur
/// dann „Alte Sicherungen entfernt“, wenn <see cref="IsComplete"/> gilt.</summary>
public sealed record PurgeReport
{
    /// <summary>Entfernte Sicherungsdateien (lokal und am zweiten Ort).</summary>
    public int Removed { get; set; }

    /// <summary>Dateien, die sich nicht entfernen liessen (bleiben mit dem alten Zugang lesbar).</summary>
    public int Failed { get; set; }

    /// <summary>Der zweite Sicherungsort ist gesetzt, liess sich aber nicht lesen.</summary>
    public bool SecondaryUnreachable { get; set; }

    /// <summary>Das Entfernen brach ab (nach gültigem Speichern; v4.4, Befund datei-1).</summary>
    public bool Interrupted { get; set; }

    public bool IsComplete => Failed == 0 && !SecondaryUnreachable && !Interrupted;
}

public enum SecondaryBackupKind
{
    /// <summary>Kopie geschrieben (Zeitpunkt in <see cref="SecondaryBackupResult.Date"/>).</summary>
    Written,

    /// <summary>Nicht fällig (höchstens 1× pro Stunde).</summary>
    NotDue,

    /// <summary>Kein Ort gesetzt oder Ordner nicht lesbar.</summary>
    Unreachable,

    /// <summary>Schreiben gescheitert.</summary>
    Failed,
}

/// <summary>Ergebnis des letzten Versuchs am zweiten Sicherungsort (SPEC v3.1).</summary>
public sealed record SecondaryBackupResult(SecondaryBackupKind Kind, DateTimeOffset? Date = null)
{
    public static SecondaryBackupResult NotDue { get; } = new(SecondaryBackupKind.NotDue);
    public static SecondaryBackupResult Unreachable { get; } = new(SecondaryBackupKind.Unreachable);
    public static SecondaryBackupResult Failed { get; } = new(SecondaryBackupKind.Failed);

    public static SecondaryBackupResult Written(DateTimeOffset date) => new(SecondaryBackupKind.Written, date);
}

/// <summary>Zustand der Selbstvernichtung, auch gesperrt lesbar (aus <c>Hardware/zustand.json</c>, nicht geheim, §23.3).
/// <c>destroyed</c> ist als zwei Felder umgesetzt. <see cref="DestroyedTrigger"/>/<see cref="DestroyedAt"/> gehören nur in
/// die Meldung nach einem echten Entsperren (dort <see cref="UnlockedVault.DestructionStatus"/>, das in einer
/// Vernichtungs-Sitzung nichts verrät).</summary>
public sealed record DestructionStatus(DestructionSettings Settings, DateTimeOffset? LastGenuineUnlock, int FailedAttempts,
    DateTimeOffset? Deadline, DestructionTrigger? DestroyedTrigger, DateTimeOffset? DestroyedAt, bool KeyConfigured = false)
{
    /// <summary>Nichts eingerichtet, nichts vernichtet.</summary>
    public static DestructionStatus Off { get; } = new(DestructionSettings.Off, null, 0, null, null, null);

    /// <summary>Verbleibende Fehlversuche (null, wenn der Zähler aus ist).</summary>
    public int? RemainingAttempts => Settings.MaxFailedAttempts is { } n ? Math.Max(0, n - FailedAttempts) : null;

    /// <summary>true ab der Hälfte der erlaubten Fehlversuche (§23.2).</summary>
    public bool ShouldWarnAboutAttempts => Settings.MaxFailedAttempts is { } n && FailedAttempts * 2 >= n;

    /// <summary>true, wenn höchstens noch 25 % der Totmann-Frist bleiben (§23.2).</summary>
    public bool DeadlineIsNear(DateTimeOffset now)
    {
        if (Deadline is not { } deadline || LastGenuineUnlock is not { } last) { return false; }
        var total = (deadline - last).TotalSeconds;
        if (total <= 0) { return false; }
        return (deadline - now).TotalSeconds <= total / 4;
    }
}

/// <summary>Vernichtet den Vernichtungsschlüssel V (§23.1). Unter Windows setzt die App die Umsetzung über
/// <c>KeyCredentialManager.DeleteAsync</c> (SPEC-WINDOWS W4.1); ohne das nimmt der Kern
/// <see cref="FileDestructionKeyEraser"/>. Der Kern ruft nur <see cref="Destroy"/> und braucht dafür keinen Schlüssel.</summary>
public interface IDestructionKeyEraser
{
    void Destroy(Guid keyId, string directory);
}

/// <summary>Variante mit Rückruf.</summary>
public sealed class ClosureDestructionKeyEraser(Action<Guid, string> body) : IDestructionKeyEraser
{
    public void Destroy(Guid keyId, string directory) => body(keyId, directory);
}

/// <summary>Rückfall des Kerns: <c>&lt;directory&gt;/&lt;keyID&gt;.siegelhw</c> mit Zufallsbytes überschreiben,
/// synchronisieren, löschen, Ordner synchronisieren. Gross-/Kleinschreibung egal. Fehler → <c>Io("hw.destroy")</c>.</summary>
public sealed class FileDestructionKeyEraser : IDestructionKeyEraser
{
    public void Destroy(Guid keyId, string directory)
    {
        var wanted = Bytes.GuidText(keyId) + "." + VaultStore.HardwareKeyExtension;
        var failed = false;
        foreach (var f in FileIO.ListFiles(directory))
        {
            if (string.Equals(Path.GetFileName(f), wanted, StringComparison.OrdinalIgnoreCase) && !FileIO.OverwriteAndRemove(f)) { failed = true; }
        }
        FileIO.TrySyncDirectory(directory);
        if (failed) { throw Fehler.Io("hw.destroy"); }
    }
}

/// <summary>Hilfen zu den Geheimteilen eines Eintrags (§22).</summary>
public static class EntrySecretsExtensions
{
    /// <summary>Neues Passwort; das bisherige wandert in den Verlauf (wie <c>Upsert</c> bei offenen Einträgen). Zum
    /// Bearbeiten versiegelter Einträge vor <c>SetProtection</c>.</summary>
    public static EntrySecrets ReplacingPassword(this EntrySecrets secrets, string newPassword)
    {
        Fehler.NotNull(secrets);
        Fehler.NotNull(newPassword);
        var output = new EntrySecrets
        {
            Password = secrets.Password,
            Notes = secrets.Notes,
            Totp = secrets.Totp,
            History = [.. secrets.History],
        };
        // Gleichheit wie Swift-String (kanonisch, Befund krypto-4)
        if (SwiftStringComparer.Instance.Equals(newPassword, secrets.Password)) { return output; }
        if (secrets.Password.Length > 0) { output.History.Add(new PasswordHistoryItem(secrets.Password, Clock.Now())); }
        output.History.RemoveAll(h => SwiftStringComparer.Instance.Equals(h.Password, newPassword));
        output.Password = newPassword;
        return output;
    }
}
