using Siegel.Modell;

// Gemeinsame Typen der Härtestufe (SPEC §13–§22), C#-Gegenstück zu Sources/SiegelCore/Faktoren.swift. Faktor-Werte
// zwischen den Modulen sind immer roh (Gerätefaktor, q, hmac-secret-Ausgabe je 32 Byte); die HKDFs aus §13.1 rechnet
// nur der Kern. Unter Windows ist der Gerätefaktor (Maskenbit 0) Windows Hello statt Secure Enclave (SPEC-WINDOWS W4.1);
// Name und Bit bleiben gleich, damit Dateien austauschbar sind.
namespace Siegel.Core;

/// <summary>Faktorart; der Zahlenwert ist das Bit in der Faktormaske des Kopfes.</summary>
public enum FactorKind : byte
{
    SecureEnclave = 1,
    Card = 2,
    SecurityKey = 4,
}

public static class FactorKindExtensions
{
    /// <summary>Alle Arten in der Reihenfolge der Schlüsselableitung (§13.1).</summary>
    public static IReadOnlyList<FactorKind> AllKinds { get; } = [FactorKind.SecureEnclave, FactorKind.Card, FactorKind.SecurityKey];

    public static string Title(this FactorKind kind) => kind switch
    {
        FactorKind.SecureEnclave => "Fingerabdruck",
        FactorKind.Card => "QR-Schlüsselkarte",
        _ => "Sicherheitsschlüssel",
    };

    /// <summary>Fester Code wie der Swift-Fallname (Detail von <c>FactorMissing</c>).</summary>
    public static string Code(this FactorKind kind) => kind switch
    {
        FactorKind.SecureEnclave => "secureEnclave",
        FactorKind.Card => "card",
        _ => "securityKey",
    };
}

/// <summary>Faktormaske: Bit 0 = Gerätefaktor, Bit 1 = Karte, Bit 2 = Sicherheitsschlüssel.</summary>
[Flags]
public enum FactorSet : byte
{
    None = 0,
    SecureEnclave = 1,
    Card = 2,
    SecurityKey = 4,
    All = 7,
}

public static class FactorSetExtensions
{
    public static bool Contains(this FactorSet set, FactorKind kind) => ((byte)set & (byte)kind) != 0;

    public static bool IsSupersetOf(this FactorSet set, FactorSet other) => (set & other) == other;

    /// <summary>In der Reihenfolge der Schlüsselableitung (§13.1): Gerätefaktor, Karte, Sicherheitsschlüssel.</summary>
    public static IReadOnlyList<FactorKind> Kinds(this FactorSet set) =>
        [.. FactorKindExtensions.AllKinds.Where(k => set.Contains(k))];
}

public enum RecoveryScheme : byte
{
    SingleCode = 1,
    Shamir2Of3 = 2,
}

/// <summary>Regeln einer Stufe, die die Oberfläche durchsetzt (die Faktoren selbst erzwingt die Kryptografie).</summary>
public sealed record LevelPolicy(
    bool TouchIdBeforeReveal,
    bool LockOnDeactivate,
    int? ClipboardSecondsMax,
    int? AutoLockMinutesMax,
    bool AllowCsvExport,
    bool AllowKeePassExport,
    bool AutofillAllowed,
    EntryProtection DefaultEntryProtection);

/// <summary>Tresor-Stufe (§13): was zum Öffnen nötig ist, plus Regeln.</summary>
public enum SecurityLevel
{
    Standard = 1,
    Erhoeht = 2,
    Hoch = 3,
    Maximal = 4,
    Festung = 5,
}

public static class SecurityLevelExtensions
{
    private static readonly LevelPolicy Normal = new(false, false, null, null, true, true, true, EntryProtection.Normal);
    private static readonly LevelPolicy High = new(true, true, 15, 2, true, true, true, EntryProtection.Normal);
    private static readonly LevelPolicy Max = new(true, true, 15, 2, false, false, false, EntryProtection.Fingerabdruck);

    public static bool IsValid(this SecurityLevel level) => level is >= SecurityLevel.Standard and <= SecurityLevel.Festung;

    public static string Title(this SecurityLevel level) => level switch
    {
        SecurityLevel.Standard => "Standard",
        SecurityLevel.Erhoeht => "Erhöht",
        SecurityLevel.Hoch => "Hoch",
        SecurityLevel.Maximal => "Maximal",
        _ => "Festung",
    };

    /// <summary>Zum Öffnen nötige Faktoren (zusätzlich zum Master-Passwort).</summary>
    public static FactorSet Factors(this SecurityLevel level) => level switch
    {
        SecurityLevel.Standard => FactorSet.None,
        SecurityLevel.Erhoeht or SecurityLevel.Hoch => FactorSet.SecureEnclave,
        SecurityLevel.Maximal => FactorSet.SecureEnclave | FactorSet.Card,
        _ => FactorSet.All,
    };

    public static KdfParameters Kdf(this SecurityLevel level) =>
        level <= SecurityLevel.Erhoeht ? KdfParameters.Standard : KdfParameters.Strong;

    public static RecoveryScheme RecoveryScheme(this SecurityLevel level) =>
        level >= SecurityLevel.Maximal ? Core.RecoveryScheme.Shamir2Of3 : Core.RecoveryScheme.SingleCode;

    public static LevelPolicy Policy(this SecurityLevel level) => level switch
    {
        SecurityLevel.Standard or SecurityLevel.Erhoeht => Normal,
        SecurityLevel.Hoch => High,
        _ => Max,
    };
}

/// <summary>Schutz pro Eintrag (§16); der Typ selbst liegt eingefroren in Siegel.Modell.</summary>
public static class EntryProtectionExtensions
{
    public static bool IsValid(this EntryProtection p) => p is >= EntryProtection.Normal and <= EntryProtection.Festung;

    public static string Title(this EntryProtection p) => p switch
    {
        EntryProtection.Normal => "Normal",
        EntryProtection.Fingerabdruck => "Fingerabdruck",
        EntryProtection.Hoch => "Hoch",
        EntryProtection.Maximal => "Maximal",
        _ => "Festung",
    };

    /// <summary>Pro Aufdecken nötige Faktoren.</summary>
    public static FactorSet Factors(this EntryProtection p) => p switch
    {
        EntryProtection.Normal => FactorSet.None,
        EntryProtection.Fingerabdruck or EntryProtection.Hoch => FactorSet.SecureEnclave,
        EntryProtection.Maximal => FactorSet.SecureEnclave | FactorSet.Card,
        _ => FactorSet.All,
    };

    /// <summary>Höchstdauer in der Zwischenablage (null = Einstellung des Nutzers).</summary>
    public static int? ClipboardSecondsMax(this EntryProtection p) => p >= EntryProtection.Hoch ? 15 : null;

    public static bool AutofillAllowed(this EntryProtection p) => p < EntryProtection.Hoch;

    public static bool ExportAllowed(this EntryProtection p) => p < EntryProtection.Maximal;
}

/// <summary>32 geheime Bytes eines Faktors in <c>sodium_malloc</c>-Speicher, beim Freigeben genullt.</summary>
public sealed class FactorSecret : IDisposable
{
    internal const int Size = 32;

    internal FactorSecret(SecureBuffer storage)
    {
        if (storage.Length != Size) { throw Fehler.Crypto("factor.length"); }
        Storage = storage;
    }

    internal SecureBuffer Storage { get; }

    /// <summary>Genau 32 Byte, sonst <c>Crypto("factor.length")</c>. Die Quelle sollte der Aufrufer danach nullen.</summary>
    public static FactorSecret Copy(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != Size) { throw Fehler.Crypto("factor.length"); }
        return new FactorSecret(SecureBuffer.Copy(bytes));
    }

    /// <summary>Lesender Zugriff auf die 32 Byte (nur innerhalb des Rückrufs gültig).</summary>
    public void Read(ReadOnlySpanAction body)
    {
        Fehler.NotNull(body);
        using var l = Storage.Borrow();
        body(l.Span);
    }

    /// <summary>Vergleich in konstanter Zeit.</summary>
    public bool ConstantTimeEquals(FactorSecret other)
    {
        Fehler.NotNull(other);
        return Storage.ConstantTimeEquals(other.Storage);
    }

    public void Dispose() => Storage.Dispose();

    public override string ToString() => "FactorSecret(redacted)";
}

/// <summary>Rückruf mit einem nur lesbaren Span (Span kann kein Typargument von Action sein).</summary>
public delegate void ReadOnlySpanAction(ReadOnlySpan<byte> bytes);

/// <summary>Faktor-Geheimnisse zum Öffnen. Gehört dem Aufrufer (Freigabe mit <see cref="FactorSecret.Dispose"/>).</summary>
public sealed class FactorSecrets
{
    public FactorSecret? SecureEnclave { get; set; }
    public FactorSecret? Card { get; set; }
    public FactorSecret? SecurityKey { get; set; }

    public FactorSet Available =>
        (SecureEnclave is null ? FactorSet.None : FactorSet.SecureEnclave)
        | (Card is null ? FactorSet.None : FactorSet.Card)
        | (SecurityKey is null ? FactorSet.None : FactorSet.SecurityKey);

    public FactorSecret? Secret(FactorKind kind) => kind switch
    {
        FactorKind.SecureEnclave => SecureEnclave,
        FactorKind.Card => Card,
        _ => SecurityKey,
    };

    public override string ToString() => "FactorSecrets(redacted)";
}

public sealed record SEEnrollment(Guid KeyId, FactorSecret Secret)
{
    public override string ToString() => $"SEEnrollment({KeyId}, redacted)";
}

/// <summary>Art eines Gerätefaktor-Schlüssels für Einträge bzw. für den Vernichtungsschlüssel V.</summary>
public enum DeviceKeyKind
{
    /// <summary>Mac: Secure-Enclave-Schlüssel P-256; öffentlicher Teil im Inhalt, Versiegeln ohne Finger (§16.1).</summary>
    SecureEnclaveP256 = 1,

    /// <summary>Windows Hello (Art „windowsHello“ v1, SPEC-WINDOWS W4.1): kein öffentlicher Teil, jedes Versiegeln und
    /// Aufdecken braucht eine Signatur über eine eintragsspezifische Herausforderung.</summary>
    WindowsHello = 2,
}

/// <summary>Öffentlicher Eintrags-Gerätefaktor-Schlüssel (Mac: P-256 x963, 65 Byte) bzw. Kennung eines
/// Windows-Hello-Schlüssels (<see cref="WindowsHello"/>, ohne öffentlichen Teil). Dient auch als Vernichtungsschlüssel V.</summary>
public sealed record EntryKeyEnrollment(Guid KeyId, ReadOnlyMemory<byte> PublicKey)
{
    public DeviceKeyKind Kind { get; init; } = DeviceKeyKind.SecureEnclaveP256;

    /// <summary>Windows-Hello-Schlüssel <c>Siegel-&lt;vaultID&gt;-&lt;keyID&gt;</c> (W4.1).</summary>
    public static EntryKeyEnrollment WindowsHello(Guid keyId) => new(keyId, ReadOnlyMemory<byte>.Empty) { Kind = DeviceKeyKind.WindowsHello };

    public bool Equals(EntryKeyEnrollment? other) =>
        other is not null && KeyId == other.KeyId && Kind == other.Kind && PublicKey.Span.SequenceEqual(other.PublicKey.Span);

    public override int GetHashCode() => HashCode.Combine(KeyId, Kind);
}

public sealed record CardEnrollment(FactorSecret Q)
{
    public override string ToString() => "CardEnrollment(redacted)";
}

public sealed record SecurityKeyEnrollment(ReadOnlyMemory<byte> CredentialId, ReadOnlyMemory<byte> Salt, FactorSecret Output,
    ReadOnlyMemory<byte> EntrySalt, FactorSecret EntryOutput)
{
    public override string ToString() => "SecurityKeyEnrollment(redacted)";
}

public sealed record NewFactorMaterial(SEEnrollment? SecureEnclave = null, EntryKeyEnrollment? EntryKey = null,
    CardEnrollment? Card = null, SecurityKeyEnrollment? SecurityKey = null)
{
    public override string ToString() => "NewFactorMaterial(redacted)";
}

/// <summary>
/// Liefert beim Aufdecken eines geschützten Eintrags die Faktoren (Oberfläche + Plattformschicht). Der Kern ruft nur die
/// Methoden, die der Schutz verlangt; jeder Aufruf ist eine eigene Freigabe. <b>Besitz:</b> Jede gelieferte
/// <see cref="FactorSecret"/> gehört danach dem Kern, der sie nach Gebrauch freigibt – ein Anbieter, der Werte
/// zwischenspeichert, liefert darum jedes Mal eine Kopie. Fehler: <see cref="Modell.SiegelException"/> geht unverändert
/// weiter, <see cref="OperationCanceledException"/> wird <c>FactorCancelled</c>, alles andere <c>FactorUnavailable(Art)</c>.
/// </summary>
public interface IEntryFactorProvider
{
    /// <summary>Mac-Art: ECDH des Eintrags-SE-Schlüssels (bzw. von V) mit dem ephemeren öffentlichen Schlüssel (x963);
    /// roh = x-Koordinate (32 Byte).</summary>
    Task<FactorSecret> SecureEnclaveSharedSecretAsync(Guid keyId, ReadOnlyMemory<byte> ephemeralPublicKey, CancellationToken cancellationToken);

    /// <summary>Karte scannen (q roh).</summary>
    Task<FactorSecret> CardSecretAsync(CancellationToken cancellationToken);

    /// <summary>Sicherheitsschlüssel berühren (hmac-secret-Ausgabe roh).</summary>
    Task<FactorSecret> SecurityKeyOutputAsync(ReadOnlyMemory<byte> credentialId, ReadOnlyMemory<byte> salt, CancellationToken cancellationToken);

    /// <summary>Windows-Art (W4.1, Version 1): Signatur des Windows-Hello-Schlüssels <paramref name="keyId"/>
    /// (RSA-PKCS#1-v1.5-SHA-256, <c>KeyCredential.RequestSignAsync</c>) über die 32-Byte-<paramref name="challenge"/>;
    /// roh = SHA-256("Siegel v2 windows hello entry" ‖ Signatur). Der Kern ruft das beim Aufdecken <b>und</b> beim
    /// Versiegeln. Ohne Windows Hello (Mac-Anbieter) → <c>FactorUnavailable(secureEnclave)</c>: „anderes Gerät“.</summary>
    Task<FactorSecret> WindowsHelloSecretAsync(Guid keyId, ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken) =>
        Task.FromException<FactorSecret>(Fehler.FactorUnavailable(FactorKind.SecureEnclave));
}

/// <summary>Kopf-Auskunft ohne Geheimnis (§13.3).</summary>
public sealed class VaultHeaderInfo : IEquatable<VaultHeaderInfo>
{
    internal VaultHeaderInfo(ushort formatVersion, Guid vaultId, FactorSet factors, RecoveryScheme recoveryScheme,
        Guid? seKeyId, byte[]? cardTag, byte[]? fidoCredentialId, byte[]? fidoSalt, KdfParameters kdf, string kitId)
    {
        FormatVersion = formatVersion;
        VaultId = vaultId;
        Factors = factors;
        RecoveryScheme = recoveryScheme;
        SeKeyId = seKeyId;
        // Ausdrücklich: null wird sonst über byte[] → ReadOnlyMemory zu „leer, aber vorhanden“.
        CardTag = Optional(cardTag);
        FidoCredentialId = Optional(fidoCredentialId);
        FidoSalt = Optional(fidoSalt);
        Kdf = kdf;
        KitId = kitId;
    }

    public ushort FormatVersion { get; }
    public Guid VaultId { get; }
    public FactorSet Factors { get; }
    public RecoveryScheme RecoveryScheme { get; }
    public Guid? SeKeyId { get; }
    public ReadOnlyMemory<byte>? CardTag { get; }
    public ReadOnlyMemory<byte>? FidoCredentialId { get; }
    public ReadOnlyMemory<byte>? FidoSalt { get; }
    public KdfParameters Kdf { get; }
    public string KitId { get; }

    public bool Equals(VaultHeaderInfo? other) =>
        other is not null && FormatVersion == other.FormatVersion && VaultId == other.VaultId && Factors == other.Factors
        && RecoveryScheme == other.RecoveryScheme && SeKeyId == other.SeKeyId && Same(CardTag, other.CardTag)
        && Same(FidoCredentialId, other.FidoCredentialId) && Same(FidoSalt, other.FidoSalt) && Kdf == other.Kdf
        && KitId == other.KitId;

    public override bool Equals(object? obj) => Equals(obj as VaultHeaderInfo);

    public override int GetHashCode() => HashCode.Combine(FormatVersion, VaultId, Factors, KitId);

    private static ReadOnlyMemory<byte>? Optional(byte[]? b)
    {
        if (b is null) { return null; }
        return new ReadOnlyMemory<byte>(b);
    }

    private static bool Same(ReadOnlyMemory<byte>? a, ReadOnlyMemory<byte>? b) =>
        a.HasValue == b.HasValue && (!a.HasValue || a.GetValueOrDefault().Span.SequenceEqual(b.GetValueOrDefault().Span));
}

public sealed record SecurityReport(IReadOnlyList<Guid> Weak, IReadOnlyList<IReadOnlyList<Guid>> Reused,
    IReadOnlyList<Guid> Old, IReadOnlyList<Guid> SameAsMaster, int Total);

/// <summary>Ein Teil des geteilten Notfallcodes (§15). Geschwärzt.</summary>
public sealed class RecoveryShare
{
    internal RecoveryShare(int index, string formatted, string kitId)
    {
        Index = index;
        Formatted = formatted;
        KitId = kitId;
    }

    /// <summary>1…3</summary>
    public int Index { get; }
    public string Formatted { get; }
    public string KitId { get; }
    public IReadOnlyList<string> Groups => Formatted.Split('-');

    public override string ToString() => $"RecoveryShare({Index}, kit: {KitId}, redacted)";
}
