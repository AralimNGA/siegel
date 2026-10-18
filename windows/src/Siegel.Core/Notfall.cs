// Öffentliche Typen des Notfallwegs (SPEC §8, §22), Gegenstück zu RecoveryCode/PendingRecovery/RecoveryCodeMatch aus
// Model.swift. Alle geschwärzt (SPEC §5).
namespace Siegel.Core;

/// <summary>Der Notfallcode. Wird nie gespeichert, nur angezeigt/gedruckt.</summary>
public sealed class RecoveryCode
{
    internal RecoveryCode(string formatted, string kitId)
    {
        Formatted = formatted;
        KitId = kitId;
    }

    /// <summary>„XXXXX-XXXXX-…“ (11 Gruppen à 5 Zeichen, Crockford-Base32); bei Shamir leer.</summary>
    public string Formatted { get; }

    /// <summary>Kit-Kennung „XXXX-XXXX“ (nicht geheim).</summary>
    public string KitId { get; }

    public IReadOnlyList<string> Groups => Formatted.Length == 0 ? [] : Formatted.Split('-');

    public override string ToString() => $"RecoveryCode(kit: {KitId}, redacted)";
}

/// <summary>Ein vorbereitetes Notfallkit. Bei <c>Create</c> schon gültig (aber unbestätigt), bei <c>PrepareRecovery</c>
/// noch nicht geschrieben.</summary>
public sealed class PendingRecovery
{
    internal PendingRecovery(RecoveryCode code, IReadOnlyList<int> confirmationGroups, RecoveryScheme scheme = RecoveryScheme.SingleCode,
        IReadOnlyList<RecoveryShare>? shares = null, IReadOnlyList<int>? shareConfirmationGroups = null)
    {
        Code = code;
        ConfirmationGroups = confirmationGroups;
        Scheme = scheme;
        Shares = shares ?? [];
        ShareConfirmationGroups = shareConfirmationGroups ?? [];
    }

    public RecoveryCode Code { get; }

    /// <summary>Zwei verschiedene Gruppenindizes 0…10 zur Bestätigung (bei <see cref="RecoveryScheme.SingleCode"/>).</summary>
    public IReadOnlyList<int> ConfirmationGroups { get; }

    public RecoveryScheme Scheme { get; }

    /// <summary>Drei Teile bei <see cref="RecoveryScheme.Shamir2Of3"/>, sonst leer.</summary>
    public IReadOnlyList<RecoveryShare> Shares { get; }

    /// <summary>Bei Shamir: je Teil ein Gruppenindex zur Bestätigung (gleiche Reihenfolge wie <see cref="Shares"/>).</summary>
    public IReadOnlyList<int> ShareConfirmationGroups { get; }

    public override string ToString() => $"PendingRecovery(kit: {Code.KitId}, redacted)";
}

/// <summary>Ergebnis der Code-Prüfung: exakt oder korrigiert (mit den geänderten Positionen im Code ohne Bindestriche).</summary>
public sealed class RecoveryCodeMatch : IEquatable<RecoveryCodeMatch>
{
    private RecoveryCodeMatch(string? formatted, IReadOnlyList<int> changedPositions)
    {
        Formatted = formatted;
        ChangedPositions = changedPositions;
    }

    public static RecoveryCodeMatch Exact { get; } = new(null, []);

    public static RecoveryCodeMatch Corrected(string formatted, IReadOnlyList<int> changedPositions) =>
        new(formatted, [.. changedPositions]);

    public bool IsExact => Formatted is null;

    /// <summary>Korrigierter Code (geheim), null bei <see cref="Exact"/>.</summary>
    public string? Formatted { get; }

    /// <summary>Positionen (0…54 bzw. 0…55 bei Teilen), aufsteigend.</summary>
    public IReadOnlyList<int> ChangedPositions { get; }

    public bool Equals(RecoveryCodeMatch? other) =>
        other is not null && Formatted == other.Formatted && ChangedPositions.SequenceEqual(other.ChangedPositions);

    public override bool Equals(object? obj) => Equals(obj as RecoveryCodeMatch);

    public override int GetHashCode() => HashCode.Combine(Formatted is null, ChangedPositions.Count);

    public override string ToString() =>
        IsExact ? "RecoveryCodeMatch(exact)" : $"RecoveryCodeMatch(corrected, {ChangedPositions.Count} Stellen, redacted)";
}
