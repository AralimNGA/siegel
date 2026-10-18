using Siegel.Modell;

// Klartext-Inhalt (SPEC §3, v4), nur im Speicher – C#-Gegenstück zu VaultContent.swift, VaultContent+Schutz.swift
// (Datenteil, Konsistenzregeln) und DestructionState.swift (DestructionConfig). Die Kryptografie des Eintrags-Schutzes
// (§16.1: versiegeln, aufdecken, Gruppen) folgt in Stufe B; hier stehen die Datentypen, die das JSON trägt, und die
// Regeln, die beim Lesen (CorruptFile) und Schreiben (Crypto) gelten.
namespace Siegel.Core;

/// <summary>Zwei Chiffrate einer hybriden Kapselung (ML-KEM-1024 1568 B + X25519 32 B). Wertgleichheit.</summary>
internal sealed record HybridCapsule(byte[] CtM, byte[] CtX)
{
    internal bool IsWellFormed => CtM.Length == RecoveryKem.CtMBytes && CtX.Length == RecoveryKem.CtXBytes;

    public bool Equals(HybridCapsule? other) => other is not null && Bytes.Same(CtM, other.CtM) && Bytes.Same(CtX, other.CtX);

    public override int GetHashCode() => HashCode.Combine(CtM.Length, CtX.Length);
}

/// <summary>Hybride Kapselung plus damit verpackter 32-Byte-Schlüssel (nonce ‖ ct ‖ tag = 72 B).</summary>
internal sealed record HybridWrap(HybridCapsule Capsule, byte[] Wrapped)
{
    internal bool IsWellFormed => Capsule.IsWellFormed && Wrapped.Length == Aead.WrappedBytes;

    public bool Equals(HybridWrap? other) => other is not null && Capsule.Equals(other.Capsule) && Bytes.Same(Wrapped, other.Wrapped);

    public override int GetHashCode() => HashCode.Combine(Capsule, Wrapped.Length);
}

/// <summary>Windows-Hello-Teil eines Siegels (Art „windowsHello“, Version 1, SPEC-WINDOWS W4.1): Zufalls-Salz der
/// eintragsspezifischen Herausforderung. Steht im Blob als <c>"hello": {"salt", "version"}</c> statt <c>"se"</c>.</summary>
internal sealed record HelloPart(byte[] Salt, int Version = HelloPart.CurrentVersion)
{
    internal const int CurrentVersion = 1;
    internal const int SaltBytes = 32;

    internal bool IsWellFormed => Salt.Length == SaltBytes && Version == CurrentVersion;

    public bool Equals(HelloPart? other) => other is not null && Version == other.Version && Bytes.Same(Salt, other.Salt);

    public override int GetHashCode() => HashCode.Combine(Version, Salt.Length);
}

/// <summary>Faktor-Teile einer Versiegelung: genau die der Maske. Der Gerätefaktor (Bit 0) ist entweder die Mac-Art
/// (<see cref="SeEphemeral"/>, P-256) oder die Windows-Hello-Art (<see cref="Hello"/>), nie beide.</summary>
internal sealed record SealedFactors(byte[]? SeEphemeral = null, HybridCapsule? Card = null, HybridCapsule? Fido = null,
    HelloPart? Hello = null)
{
    internal FactorSet Mask =>
        (SeEphemeral is null && Hello is null ? FactorSet.None : FactorSet.SecureEnclave)
        | (Card is null ? FactorSet.None : FactorSet.Card)
        | (Fido is null ? FactorSet.None : FactorSet.SecurityKey);

    internal bool IsWellFormed =>
        (SeEphemeral is null || Hello is null)
        && (SeEphemeral is null || (SeEphemeral.Length == 65 && SeEphemeral[0] == 0x04))
        && (Hello is null || Hello.IsWellFormed)
        && (Card is null || Card.IsWellFormed) && (Fido is null || Fido.IsWellFormed);

    public bool Equals(SealedFactors? other) =>
        other is not null && Bytes.Same(SeEphemeral, other.SeEphemeral) && Equals(Card, other.Card) && Equals(Fido, other.Fido)
        && Equals(Hello, other.Hello);

    public override int GetHashCode() => HashCode.Combine(SeEphemeral?.Length, Card, Fido, Hello);
}

/// <summary>Mit K verschlüsselter Klartext samt den Faktor-Teilen, aus denen K entsteht.</summary>
internal sealed record SealedBlob(SealedFactors Factors, byte[] Nonce, byte[] Ciphertext)
{
    internal bool IsWellFormed => Factors.IsWellFormed && Nonce.Length == Aead.NonceBytes && Ciphertext.Length >= Aead.TagBytes;

    public bool Equals(SealedBlob? other) =>
        other is not null && Factors.Equals(other.Factors) && Bytes.Same(Nonce, other.Nonce) && Bytes.Same(Ciphertext, other.Ciphertext);

    public override int GetHashCode() => HashCode.Combine(Factors, Ciphertext.Length);
}

/// <summary>Versiegelte Geheimteile eines Eintrags (§16.1).</summary>
internal sealed record SealedSecrets(SealedBlob Blob, HybridWrap Recovery);

/// <summary>Notfall-Gruppe pro Faktormaske (KERN-NOTIZEN: Abweichung 2).</summary>
internal sealed record RecoveryGroup(Guid Id, FactorSet Mask, RecoveryPublicKeys Pk, HybridWrap Kit, SealedBlob Anchor);

/// <summary>Metadaten für den Offline-Sicherheitsbericht (§17), auch für versiegelte Einträge lesbar. Wertgleichheit.</summary>
internal sealed record EntryMeta(byte[]? Tag, int? Strength, DateTimeOffset? Changed)
{
    public bool Equals(EntryMeta? other) =>
        other is not null && Bytes.Same(Tag, other.Tag) && Strength == other.Strength && Changed == other.Changed;

    public override int GetHashCode() => HashCode.Combine(Tag?.Length, Strength, Changed);
}

/// <summary>Stabiler Eintrags-Grundschlüssel (32 B) im verschlüsselten Inhalt (KERN-NOTIZEN: Abweichung 1).</summary>
internal sealed class EntryBaseKey : IDisposable
{
    internal EntryBaseKey(SecureBuffer key)
    {
        if (key.Length != 32) { throw Fehler.Crypto("entry.baseKey"); }
        Key = key;
    }

    internal SecureBuffer Key { get; }

    internal static EntryBaseKey Generate() => new(SecureBuffer.Random(32));

    internal EntryBaseKey Clone()
    {
        using var l = Key.Borrow();
        return new EntryBaseKey(SecureBuffer.Copy(l.Span));
    }

    public void Dispose() => Key.Dispose();

    public override string ToString() => "EntryBaseKey(redacted)";
}

/// <summary>Öffentliche Teile der für Einträge eingerichteten Faktoren (§16, §16.1), im verschlüsselten Inhalt. Der
/// Eintrags-Gerätefaktor ist entweder ein Mac-Secure-Enclave-Schlüssel (<see cref="SecureEnclave"/>, P-256) oder ein
/// Windows-Hello-Schlüssel (<see cref="WindowsHello"/>, SPEC-WINDOWS W4.1), nie beide.</summary>
internal sealed record EntryFactorKeys(EntryFactorKeys.SecureEnclaveKey? SecureEnclave = null, EntryFactorKeys.CardKey? Card = null,
    EntryFactorKeys.SecurityKeyInfo? SecurityKey = null, EntryFactorKeys.HelloKey? WindowsHello = null)
{
    /// <summary>Eintrags-Gerätefaktor-Schlüssel (Mac: P-256, x963, 65 Byte).</summary>
    internal sealed record SecureEnclaveKey(Guid KeyId, byte[] PublicKey)
    {
        public bool Equals(SecureEnclaveKey? other) => other is not null && KeyId == other.KeyId && Bytes.Same(PublicKey, other.PublicKey);

        public override int GetHashCode() => KeyId.GetHashCode();
    }

    /// <summary>Windows-Hello-Schlüssel für Einträge (Art „windowsHello“, nur Kennung und Version; kein öffentlicher
    /// Teil, denn Schreiben braucht hier die Signatur).</summary>
    internal sealed record HelloKey(Guid KeyId, int Version = HelloPart.CurrentVersion);

    /// <summary>Karte: Kennung (wie im Kopf) und Hybrid-pk aus q („Siegel v2 card entry …“).</summary>
    internal sealed record CardKey(byte[] Tag, RecoveryPublicKeys Pk)
    {
        public bool Equals(CardKey? other) => other is not null && Bytes.Same(Tag, other.Tag) && Pk.Equals(other.Pk);

        public override int GetHashCode() => Pk.GetHashCode();
    }

    /// <summary>Sicherheitsschlüssel: Credential, Entsperr-Salz (+ Prüfwert), Eintrags-Salz und Hybrid-pk aus y2.</summary>
    internal sealed record SecurityKeyInfo(byte[] CredentialId, byte[] Salt, byte[] Check, byte[] EntrySalt, RecoveryPublicKeys Pk)
    {
        public bool Equals(SecurityKeyInfo? other) =>
            other is not null && Bytes.Same(CredentialId, other.CredentialId) && Bytes.Same(Salt, other.Salt)
            && Bytes.Same(Check, other.Check) && Bytes.Same(EntrySalt, other.EntrySalt) && Pk.Equals(other.Pk);

        public override int GetHashCode() => Pk.GetHashCode();
    }

    internal static EntryFactorKeys None { get; } = new();

    internal FactorSet Enrolled =>
        (SecureEnclave is null && WindowsHello is null ? FactorSet.None : FactorSet.SecureEnclave)
        | (Card is null ? FactorSet.None : FactorSet.Card)
        | (SecurityKey is null ? FactorSet.None : FactorSet.SecurityKey);

    /// <summary>Kennung des Eintrags-Gerätefaktors (beide Arten), für die paarweise Verschiedenheit (§23).</summary>
    internal Guid? DeviceKeyId => SecureEnclave?.KeyId ?? WindowsHello?.KeyId;

    /// <summary>Längenprüfung (beim Lesen <c>corruptFile("payload.factors")</c>).</summary>
    internal void Validate()
    {
        if (SecureEnclave is not null && WindowsHello is not null) { throw Fehler.Corrupt("payload.factors"); }
        if (SecureEnclave is { } se && (se.PublicKey.Length != 65 || se.PublicKey[0] != 0x04))
        {
            throw Fehler.Corrupt("payload.factors");
        }
        if (WindowsHello is { } h && h.Version != HelloPart.CurrentVersion) { throw Fehler.Corrupt("payload.factors"); }
        if (Card is { } c && (c.Tag.Length != VaultHeader.CardTagBytes || !c.Pk.HasValidLengths))
        {
            throw Fehler.Corrupt("payload.factors");
        }
        if (SecurityKey is { } k
            && (k.CredentialId.Length is < VaultHeader.MinFidoCredential or > VaultHeader.MaxFidoCredential
                || k.Salt.Length != VaultHeader.FidoSaltBytes || k.EntrySalt.Length != VaultHeader.FidoSaltBytes
                || k.Check.Length != FactorKdf.FidoCheckBytes || !k.Pk.HasValidLengths))
        {
            throw Fehler.Corrupt("payload.factors");
        }
    }
}

/// <summary>Was die Vernichtung ausgelöst hat (§23).</summary>
public enum DestructionTrigger
{
    Deadman,
    FailedAttempts,
    DuressPassword,
}

/// <summary>Einstellungen der Selbstvernichtung (§23.3). Massgeblich ist der verschlüsselte Inhalt.</summary>
public sealed record DestructionSettings(int? DeadmanDays = null, int? MaxFailedAttempts = null, bool DuressEnabled = false)
{
    public static DestructionSettings Off { get; } = new();

    public const int MinDeadmanDays = 7;
    public const int MaxDeadmanDays = 365;
    public const int MinFailedAttempts = 10;
    public const int MaxFailedAttemptsLimit = 100;

    /// <summary>Mindestens ein Auslöser ist eingeschaltet.</summary>
    public bool AnyTriggerEnabled => DeadmanDays is not null || MaxFailedAttempts is not null || DuressEnabled;

    /// <summary>Bereiche prüfen (§23.2): <c>Io("destruction.deadmanDays")</c> bzw. <c>Io("destruction.maxFailedAttempts")</c>.</summary>
    internal void Validate()
    {
        if (DeadmanDays is { } d && d is < MinDeadmanDays or > MaxDeadmanDays) { throw Fehler.Io("destruction.deadmanDays"); }
        if (MaxFailedAttempts is { } n && n is < MinFailedAttempts or > MaxFailedAttemptsLimit)
        {
            throw Fehler.Io("destruction.maxFailedAttempts");
        }
    }
}

/// <summary>Selbstvernichtung im Inhalt (§23): Einstellungen, öffentlicher Teil von V, Vernichtungs-Passwort (öffentlich).</summary>
internal sealed record DestructionConfig(DestructionSettings Settings, DestructionConfig.VKeyInfo? VKey = null,
    DestructionConfig.DuressInfo? Duress = null)
{
    internal const int DuressSaltBytes = 16;
    internal const int DuressCheckBytes = 16;

    /// <summary>Vernichtungsschlüssel V: Kennung (Dateiname im Hardware-Ordner) und öffentlicher Schlüssel (x963) – oder
    /// unter Windows ein Windows-Hello-Schlüssel (<see cref="IsWindowsHello"/>, kein öffentlicher Teil, W4.1).</summary>
    internal sealed record VKeyInfo(Guid KeyId, byte[] PublicKey, int HelloVersion = 0)
    {
        internal bool IsWindowsHello => HelloVersion != 0;

        internal bool IsWellFormed =>
            IsWindowsHello ? HelloVersion == HelloPart.CurrentVersion && PublicKey.Length == 0
                : PublicKey.Length == 65 && PublicKey[0] == 0x04;

        public bool Equals(VKeyInfo? other) =>
            other is not null && KeyId == other.KeyId && HelloVersion == other.HelloVersion && Bytes.Same(PublicKey, other.PublicKey);

        public override int GetHashCode() => KeyId.GetHashCode();
    }

    /// <summary>Vernichtungs-Passwort: Ablage-Kennung, dSalt, Prüfwert und öffentlicher Hybrid-Schlüssel aus d.</summary>
    internal sealed record DuressInfo(Guid FileId, byte[] Salt, byte[] Check, RecoveryPublicKeys Pk)
    {
        public bool Equals(DuressInfo? other) =>
            other is not null && FileId == other.FileId && Bytes.Same(Salt, other.Salt) && Bytes.Same(Check, other.Check)
            && Pk.Equals(other.Pk);

        public override int GetHashCode() => FileId.GetHashCode();
    }

    /// <summary>Nichts eingerichtet (dann steht <c>destruction</c> gar nicht im Inhalt).</summary>
    internal bool IsEmpty => !Settings.AnyTriggerEnabled && VKey is null && Duress is null;
}

/// <summary>
/// Klartext-Inhalt v2: <c>{ "v": 2, "savedAt", "recoveryConfirmedAt", "level", "factors", "entries", "entryKey",
/// "recoveryGroups", ["destruction"] }</c>. Inhalte mit <c>"v": 1</c> (Format v1) werden weiter gelesen: Stufe 1, keine
/// Faktoren, Einträge ohne TOTP/Schutz. Besitzt den Grundschlüssel (<see cref="Dispose"/>); <see cref="Clone"/> kopiert
/// ihn, damit transaktionale Kopien unabhängig freigegeben werden können.
/// </summary>
internal sealed partial class VaultContent : IDisposable
{
    internal const int Version = 2;
    internal const int HistoryMax = 10;
    internal const int HistoryHardMax = 30;
    internal static readonly TimeSpan HistoryProtectedAge = TimeSpan.FromDays(30);
    internal static readonly TimeSpan DeletedRetention = TimeSpan.FromDays(30);

    // Feldgrenzen in UTF-8-Byte
    internal const int MaxTitle = 2 << 10;
    internal const int MaxUsername = 2 << 10;
    internal const int MaxUrl = 2 << 10;
    internal const int MaxPassword = 4 << 10;
    internal const int MaxNotes = 256 << 10;
    internal const int MaxTotp = 4 << 10;

    /// <summary>Masken, die als Eintrags-Schutz vorkommen (Schutz 2/3, 4, 5).</summary>
    internal static readonly FactorSet[] ValidMasks = [FactorSet.SecureEnclave, FactorSet.SecureEnclave | FactorSet.Card, FactorSet.All];

    internal const int ReuseTagBytes = 16;

    internal VaultContent(DateTimeOffset savedAt, DateTimeOffset? recoveryConfirmedAt, SecurityLevel level,
        EntryFactorKeys entryFactors, List<VaultEntry> entries)
    {
        SavedAt = savedAt;
        RecoveryConfirmedAt = recoveryConfirmedAt;
        Level = level;
        EntryFactors = entryFactors;
        Entries = entries;
    }

    internal DateTimeOffset SavedAt { get; set; }
    internal DateTimeOffset? RecoveryConfirmedAt { get; set; }

    /// <summary>Tresor-Stufe (Regeln der Oberfläche; die Faktoren zum Öffnen stehen im Kopf und müssen dazu passen).</summary>
    internal SecurityLevel Level { get; set; }

    internal EntryFactorKeys EntryFactors { get; set; }
    internal List<VaultEntry> Entries { get; set; }

    /// <summary>Eintrags-Grundschlüssel (§16.1, §17); null nur in älteren Inhalten.</summary>
    internal EntryBaseKey? EntryKey { get; set; }

    /// <summary>Versiegelte Geheimteile pro Eintrag (Schutz ≥ 2); im JSON beim Eintrag (<c>sealed</c>).</summary>
    internal Dictionary<Guid, SealedSecrets> Sealed { get; set; } = [];

    /// <summary>Metadaten für den Sicherheitsbericht (§17); im JSON beim Eintrag (<c>meta</c>).</summary>
    internal Dictionary<Guid, EntryMeta> Meta { get; set; } = [];

    /// <summary>Notfall-Gruppen (eine pro Faktormaske versiegelter Einträge).</summary>
    internal List<RecoveryGroup> RecoveryGroups { get; set; } = [];

    /// <summary>Vernichtbare Einträge (§23.1): an V versiegelt, ohne Notfall-Umschlag (<c>"recovery": null</c>).</summary>
    internal Dictionary<Guid, SealedBlob> Destructible { get; set; } = [];

    /// <summary>Selbstvernichtung (§23); null = aus.</summary>
    internal DestructionConfig? Destruction { get; set; }

    internal static VaultContent Empty(DateTimeOffset now) =>
        new(now, null, SecurityLevel.Standard, EntryFactorKeys.None, []);

    /// <summary>Tiefe Kopie (Einträge, Tabellen, Grundschlüssel); Werte-Records werden geteilt (unveränderlich).</summary>
    internal VaultContent Clone() =>
        new(SavedAt, RecoveryConfirmedAt, Level, EntryFactors, [.. Entries.Select(e => e.Copy())])
        {
            EntryKey = EntryKey?.Clone(),
            Sealed = new Dictionary<Guid, SealedSecrets>(Sealed),
            Meta = new Dictionary<Guid, EntryMeta>(Meta),
            RecoveryGroups = [.. RecoveryGroups],
            Destructible = new Dictionary<Guid, SealedBlob>(Destructible),
            Destruction = Destruction,
        };

    public void Dispose()
    {
        EntryKey?.Dispose();
        EntryKey = null;
    }

    /// <summary>Prüft die Feldgrenzen eines Eintrags (inkl. Verlauf).</summary>
    internal static void Validate(VaultEntry e)
    {
        static int N(string s) => System.Text.Encoding.UTF8.GetByteCount(s);
        if (N(e.Title) > MaxTitle) { throw Fehler.Io("entry.titleTooLong"); }
        if (N(e.Username) > MaxUsername) { throw Fehler.Io("entry.usernameTooLong"); }
        if (N(e.Url) > MaxUrl) { throw Fehler.Io("entry.urlTooLong"); }
        if (N(e.Password) > MaxPassword) { throw Fehler.Io("entry.passwordTooLong"); }
        if (N(e.Notes) > MaxNotes) { throw Fehler.Io("entry.notesTooLong"); }
        if (N(e.Totp) > MaxTotp) { throw Fehler.Io("entry.totpTooLong"); }
        if (e.History.Any(h => N(h.Password) > MaxPassword)) { throw Fehler.Io("entry.passwordTooLong"); }
    }

    /// <summary>Verlauf: höchstens 10, Einträge jünger als 30 Tage werden nie verdrängt (harte Obergrenze 30).</summary>
    internal static List<PasswordHistoryItem> ApplyHistoryRule(IEnumerable<PasswordHistoryItem> history, DateTimeOffset now)
    {
        var sorted = history.OrderByDescending(h => h.Changed).ToList();
        var young = sorted.Count(h => now - h.Changed < HistoryProtectedAge);
        var keep = Math.Min(HistoryHardMax, Math.Max(HistoryMax, young));
        return [.. sorted.Take(keep)];
    }

    /// <summary>Vor jedem Speichern: abgelaufene gelöschte Einträge endgültig entfernen, Zeitpunkte kanonisieren.</summary>
    internal void PrepareForSave(DateTimeOffset now)
    {
        Entries.RemoveAll(e => e.DeletedAt is { } d && now - d >= DeletedRetention);
        SavedAt = now;
        RecoveryConfirmedAt = RecoveryConfirmedAt is { } r ? Clock.Canonical(r) : null;
        foreach (var e in Entries)
        {
            e.Created = Clock.Canonical(e.Created);
            e.Modified = Clock.Canonical(e.Modified);
            e.DeletedAt = e.DeletedAt is { } d ? Clock.Canonical(d) : null;
            e.History = [.. e.History.Select(h => h with { Changed = Clock.Canonical(h.Changed) })];
        }
    }

    /// <summary>Nach einer Wiederherstellung über den Notfallcode (§16.1): Stufe 1, keine Faktoren, alle Einträge Schutz 1.
    /// Vorher muss alles entsiegelt sein, sonst <c>Crypto("recovery.sealed")</c> – nie still Geheimteile verwerfen.</summary>
    internal void ResetAfterRecovery()
    {
        if (Sealed.Count > 0 || Entries.Any(e => e.SecretsSealed) || Destructible.Count > 0)
        {
            throw Fehler.Crypto("recovery.sealed");
        }
        Level = SecurityLevel.Standard;
        EntryFactors = EntryFactorKeys.None;
        RecoveryGroups = [];
        Destruction = null;
        foreach (var e in Entries) { e.Protection = EntryProtection.Normal; }
    }

    // MARK: Konsistenz

    /// <summary>Regeln des Eintrags-Schutzes. Beim Lesen → CorruptFile, beim Schreiben → Crypto (Programmfehler).
    /// Schutz 1 ⇔ offen; Schutz ≥ 2 ⇔ versiegelt mit genau den Faktor-Teilen der Maske, leeren Klartextfeldern,
    /// Metadaten, eingerichteten Faktoren und einer Gruppe für die Maske.</summary>
    internal void CheckSealing(Func<string, Exception> fail)
    {
        var masks = new HashSet<FactorSet>();
        var groupIds = new HashSet<Guid>();
        foreach (var g in RecoveryGroups)
        {
            if (!ValidMasks.Contains(g.Mask) || !masks.Add(g.Mask) || !groupIds.Add(g.Id) || !g.Pk.HasValidLengths
                || !g.Kit.IsWellFormed || !g.Anchor.IsWellFormed || g.Anchor.Factors.Mask != g.Mask
                || !DeviceArtMatches(g.Anchor.Factors, destructible: false)
                || !EntryFactors.Enrolled.IsSupersetOf(g.Mask) || EntryKey is null)
            {
                throw fail("payload.recoveryGroup");
            }
        }
        foreach (var m in Meta.Values)
        {
            if (m.Tag is { } t && t.Length != ReuseTagBytes) { throw fail("payload.meta"); }
            if (m.Strength is { } s && s is < 0 or > 4) { throw fail("payload.meta"); }
        }
        CheckDestruction(fail);
        var ids = new HashSet<Guid>();
        var sealedIds = new HashSet<Guid>();
        var destructibleIds = new HashSet<Guid>();
        foreach (var e in Entries)
        {
            if ((Sealed.Count > 0 || Destructible.Count > 0) && !ids.Add(e.Id)) { throw fail("payload.duplicateID"); }
            if (e.Protection == EntryProtection.Normal)
            {
                if (Sealed.ContainsKey(e.Id) || Destructible.ContainsKey(e.Id) || e.SecretsSealed) { throw fail("entry.sealedState"); }
                continue;
            }
            var mask = e.Protection.Factors();
            if (!e.SecretsSealed || e.Password.Length > 0 || e.Notes.Length > 0 || e.Totp.Length > 0 || e.History.Count > 0
                || !Meta.ContainsKey(e.Id) || EntryKey is null)
            {
                throw fail("entry.sealedState");
            }
            if (Destructible.TryGetValue(e.Id, out var b))
            {
                // Vernichtbar (§23.1): nur Schutz 4/5, nur Stufe 4/5, an V versiegelt, kein Notfall-Umschlag.
                if (Sealed.ContainsKey(e.Id) || e.Protection < EntryProtection.Maximal || Level < SecurityLevel.Maximal
                    || !b.IsWellFormed || b.Factors.Mask != mask || Destruction?.VKey is null
                    || !DeviceArtMatches(b.Factors, destructible: true)
                    || !EntryFactors.Enrolled.IsSupersetOf(mask & ~FactorSet.SecureEnclave))
                {
                    throw fail("entry.sealedState");
                }
                destructibleIds.Add(e.Id);
                continue;
            }
            if (!Sealed.TryGetValue(e.Id, out var x) || !x.Blob.IsWellFormed || !x.Recovery.IsWellFormed
                || x.Blob.Factors.Mask != mask || !DeviceArtMatches(x.Blob.Factors, destructible: false)
                || !EntryFactors.Enrolled.IsSupersetOf(mask) || !masks.Contains(mask))
            {
                throw fail("entry.sealedState");
            }
            sealedIds.Add(e.Id);
        }
        if (sealedIds.Count != Sealed.Count || destructibleIds.Count != Destructible.Count) { throw fail("entry.sealedState"); }
    }

    /// <summary>Die Art des Gerätefaktors eines Siegels passt zum eingerichteten Schlüssel: Mac-P-256 ⇔ <c>"se"</c>,
    /// Windows Hello ⇔ <c>"hello"</c> (vernichtbar: nach der Art von V). Ohne Gerätefaktor in der Maske immer.</summary>
    private bool DeviceArtMatches(SealedFactors f, bool destructible)
    {
        if (!f.Mask.Contains(FactorKind.SecureEnclave)) { return true; }
        var hello = destructible ? Destruction?.VKey?.IsWindowsHello == true : EntryFactors.WindowsHello is not null;
        return hello ? f.Hello is not null : f.SeEphemeral is not null;
    }

    /// <summary>Weder V noch die Ablage des Vernichtungs-Passworts heissen wie der Entsperr-Schlüssel des Kopfes
    /// (Tiefenverteidigung, v4.4).</summary>
    internal bool DestructionKeysAvoid(VaultHeader header)
    {
        if (Destruction is not { } d || header.FactorFields.SeKeyId is not { } se) { return true; }
        return d.VKey?.KeyId != se && d.Duress?.FileId != se;
    }

    /// <summary>Regeln der Selbstvernichtung im Inhalt (§23): Bereiche, duressEnabled ⇔ duress, eingeschaltet nur in
    /// Stufe 4/5 und nur mit V; V, Ablage-Kennung und Eintrags-Gerätefaktor-Schlüssel paarweise verschieden.</summary>
    internal void CheckDestruction(Func<string, Exception> fail)
    {
        if (Destruction is not { } d) { return; }
        try
        {
            d.Settings.Validate();
        }
        catch (SiegelException)
        {
            throw fail("payload.destruction");
        }
        if (d.Settings.DuressEnabled != (d.Duress is not null) || d.IsEmpty) { throw fail("payload.destruction"); }
        if (d.VKey is { } v && (!v.IsWellFormed || v.KeyId == EntryFactors.DeviceKeyId))
        {
            throw fail("payload.destruction");
        }
        if (d.Duress is { } x
            && (x.Salt.Length != DestructionConfig.DuressSaltBytes || x.Check.Length != DestructionConfig.DuressCheckBytes
                || !x.Pk.HasValidLengths || x.FileId == d.VKey?.KeyId || x.FileId == EntryFactors.DeviceKeyId))
        {
            throw fail("payload.destruction");
        }
        if ((d.Settings.AnyTriggerEnabled || Destructible.Count > 0) && (Level < SecurityLevel.Maximal || d.VKey is null))
        {
            throw fail("payload.destruction");
        }
    }
}
