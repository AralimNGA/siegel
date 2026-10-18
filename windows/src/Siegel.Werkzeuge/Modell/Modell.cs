using System.Text.Json.Serialization;

// Gemeinsame Datentypen (eingefroren wie Model.swift auf dem Mac): Kern und Werkzeuge bauen parallel dagegen.
// JSON-Namen exakt wie das Mac-Inhaltsformat (../../SPEC.md §3, §13–§18). Geheimnis-Typen schwärzen ToString().
namespace Siegel.Modell;

public sealed record PasswordHistoryItem(
    [property: JsonPropertyName("password")] string Password,
    [property: JsonPropertyName("changed")] DateTimeOffset Changed)
{
    public override string ToString() => "PasswordHistoryItem(redacted)";
}

public enum EntryProtection { Normal = 1, Fingerabdruck = 2, Hoch = 3, Maximal = 4, Festung = 5 }

public sealed class VaultEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Title { get; set; } = "";
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string Url { get; set; } = "";
    public string Notes { get; set; } = "";
    public DateTimeOffset Created { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset Modified { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? DeletedAt { get; set; }
    public List<PasswordHistoryItem> History { get; set; } = [];
    public string Totp { get; set; } = "";
    public EntryProtection Protection { get; set; } = EntryProtection.Normal;
    /// <summary>Nur der Kern setzt das: Geheimteile versiegelt (dann leer).</summary>
    public bool SecretsSealed { get; internal set; }

    public VaultEntry Copy()
    {
        var c = (VaultEntry)MemberwiseClone();
        c.History = [.. History];
        return c;
    }

    public override string ToString() => $"VaultEntry({Id}, redacted)";
}

public sealed class EntrySecrets
{
    public string Password { get; set; } = "";
    public string Notes { get; set; } = "";
    public string Totp { get; set; } = "";
    public List<PasswordHistoryItem> History { get; set; } = [];
    public override string ToString() => "EntrySecrets(redacted)";
}

public sealed class ImportReport
{
    public int Added { get; set; }
    public int SkippedDuplicates { get; set; }
    public int Conflicts { get; set; }
    public int WithOtpSecret { get; set; }
    public int MovedToNotes { get; set; }
    public int PasswordsWithControlCharacters { get; set; }
    public int ApostrophePrefixed { get; set; }
}

public enum CsvFormat { ApplePasswords, Chrome, Firefox, Bitwarden }

public sealed record CsvImportResult(CsvFormat Format, IReadOnlyList<VaultEntry> Entries, ImportReport Report);

/// <summary>Feste Fehlercodes wie SiegelError auf dem Mac; Detail ist immer ein fester Code, nie Inhalt.</summary>
public enum SiegelErrorCode
{
    WrongPassword, WrongRecoveryCode, InvalidRecoveryCodeFormat, RecoveryCodeChecksum, RecoveryConfirmationMismatch,
    PasswordTooWeak, MasterPasswordReused, CorruptFile, UnsupportedVersion, KdfParametersOutOfRange, KdfFailed,
    VaultAlreadyExists, VaultMissing, VaultChangedOnDisk, NotEnoughDiskSpace, CsvInvalid, ExportLocationRejected,
    Io, Crypto, FactorMissing, FactorUnavailable, FactorCancelled, WrongCard, NotAllowedAtLevel, TotpInvalid,
    // v4.4 (../../SPEC.md §12), bei der Integration von Etappe 1 angehängt (bestehende Werte bleiben gleich):
    /// <summary>Faktor geht gerade nicht, ist aber nicht verloren (erneut versuchen, kein Notfallweg). Detail ist der
    /// feste Code wie auf dem Mac: <c>se.lockout</c>, <c>se.notReachable</c> (unter Windows: Windows Hello gesperrt bzw.
    /// nicht erreichbar), <c>fido.busy</c>.</summary>
    FactorTemporarilyUnavailable,
    /// <summary>Der Sicherheitsschlüssel kennt die Registrierung nicht (anderer oder zurückgesetzter Schlüssel).</summary>
    WrongSecurityKey,
}

public sealed class SiegelException(SiegelErrorCode code, string detail = "", int line = 0) : Exception(code + (detail.Length > 0 ? ":" + detail : ""))
{
    public SiegelErrorCode Code { get; } = code;
    /// <summary>Fester Code (z. B. "file.checksum"), nie Inhalt.</summary>
    public string Detail { get; } = detail;
    /// <summary>Zeile bei CSV-Fehlern, sonst 0.</summary>
    public int Line { get; } = line;
    /// <summary>Kit-Kennungen bei WrongRecoveryCode bzw. Bits bei PasswordTooWeak (nicht geheim).</summary>
    public string? CodeKit { get; init; }
    public string? VaultKit { get; init; }
    public double? Bits { get; init; }
}
