#if DEBUG
using System.Security.Cryptography;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Hilfen der Tresor-Tests (Gegenstück zu KernTestSupport.swift, KernStufenSupport.swift, KernSchutzSupport.swift,
/// KernVernichtungSupport.swift). Alle Tests arbeiten in eigenen Temp-Ordnern mit In-Memory-RollbackGuard.</summary>
internal static partial class KT
{
    internal const string Pw3 = "t=5:U.+F3mYWO6#O8@s~@~4_q:";
    internal const string Pw4 = "u_b,DV_>9Ml^Zx./m936@ziw:b";

    /// <summary>Offensichtlich schwach (für Policy-Tests).</summary>
    internal const string Weak = "abc";

    internal static UnlockedVault? Unlocked(UnlockOutcome o) => o.IsRollbackSuspected ? null : o.Vault;

    internal static UnlockedVault AnyVault(UnlockOutcome o) => o.Vault;

    internal static VaultEntry Entry(string title, string user = "anna", string password = "Geheim-123", string url = "https://example.ch",
        string notes = "") =>
        new() { Title = title, Username = user, Password = password, Url = url, Notes = notes };

    internal static bool IsCorrupt(SiegelException e) => e.Code == SiegelErrorCode.CorruptFile;

    internal static async Task<SiegelException> ThrowsAsync(SiegelErrorCode code, Func<Task> body)
    {
        var e = await Assert.ThrowsAsync<SiegelException>(body);
        Assert.Equal(code, e.Code);
        return e;
    }

    internal static async Task<SiegelException> ThrowsAsync(SiegelErrorCode code, string detail, Func<Task> body)
    {
        var e = await ThrowsAsync(code, body);
        Assert.Equal(detail, e.Detail);
        return e;
    }

    /// <summary>Testschalter für die Dauer eines <c>using</c> (AsyncLocal, danach zurückgesetzt).</summary>
    internal static IDisposable Now(DateTimeOffset t)
    {
        var old = TestHooks.Now;
        TestHooks.Now = t;
        return new Undo(() => TestHooks.Now = old);
    }

    internal static IDisposable Hook(Action set, Action reset)
    {
        set();
        return new Undo(reset);
    }

    internal static DateTimeOffset At(double seconds) => Clock.FromSeconds(seconds)!.Value;

    internal static string Hex(IEnumerable<byte> b) => Convert.ToHexStringLower([.. b]);

    private sealed class Undo(Action undo) : IDisposable
    {
        public void Dispose() => undo();
    }
}

/// <summary>Temp-Ordner, der am Ende entfernt wird.</summary>
internal sealed class KernTempDir : IDisposable
{
    internal KernTempDir()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "siegel-kern-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    internal string Path { get; }

    internal string Sub(string name)
    {
        var p = System.IO.Path.Combine(Path, name);
        Directory.CreateDirectory(p);
        return p;
    }

    public void Dispose()
    {
        try
        {
            foreach (var f in Directory.EnumerateFileSystemEntries(Path, "*", SearchOption.AllDirectories))
            {
                try
                {
                    File.SetAttributes(f, FileAttributes.Normal);
                }
                catch (IOException)
                {
                }
            }
            Directory.Delete(Path, recursive: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Aufräumen nach bestem Bemühen
        }
    }
}

/// <summary>Ein Test-Tresor (Testschalter-KDF) samt Ordner.</summary>
internal sealed class KernVault : IDisposable
{
    private KernVault(KernTempDir dir, InMemoryRollbackGuard guardian, VaultStore store, UnlockedVault vault, PendingRecovery pending)
    {
        Dir = dir;
        Guardian = guardian;
        Store = store;
        Vault = vault;
        Pending = pending;
    }

    internal KernTempDir Dir { get; }
    internal InMemoryRollbackGuard Guardian { get; }
    internal VaultStore Store { get; }
    internal UnlockedVault Vault { get; set; }
    internal PendingRecovery Pending { get; }

    internal static KernVault Make(string password = KT.Pw1, KdfParameters? kdf = null)
    {
        var dir = new KernTempDir();
        var guardian = new InMemoryRollbackGuard();
        var store = VaultStore.ForTesting(Path.Combine(dir.Path, "Siegel"), guardian);
        var (vault, pending) = store.Create(password, kdf ?? KT.Kdf);
        return new KernVault(dir, guardian, store, vault, pending);
    }

    /// <summary>Zweiter Store auf denselben Ordner (eigene Instanz).</summary>
    internal VaultStore ReopenStore(IRollbackGuard? guardian = null) => VaultStore.ForTesting(Store.DirectoryPath, guardian ?? Guardian);

    internal byte[] FileBytes() => File.ReadAllBytes(Store.VaultPath);

    internal void WriteFile(byte[] bytes)
    {
        File.Delete(Store.VaultPath);
        File.WriteAllBytes(Store.VaultPath, bytes);
    }

    internal VaultFile ParsedFile() => VaultFile.Parse(FileBytes());

    internal string Code => Pending.Code.Formatted;

    internal IReadOnlyList<BackupInfo> LocalBackups() => [.. Store.Backups().Where(b => !b.IsExternal && b.VaultId == Vault.VaultId)];

    internal HashSet<string> BackupFileNames() =>
        [.. FileIO.ListFiles(Store.BackupDirectory(Vault.VaultId)).Select(Path.GetFileName).OfType<string>()];

    internal IReadOnlyList<string> TempFiles() => [.. FileIO.ListFiles(Store.DirectoryPath).Where(f => f.EndsWith(".tmp", StringComparison.Ordinal))];

    /// <summary>Klartext-JSON des Inhalts auf der Platte (mit dem DEK des offenen Tresors).</summary>
    internal string JsonOnDisk(UnlockedVault? v = null)
    {
        var file = ParsedFile();
        using var dek = (v ?? Vault).DekForTesting();
        using var padded = Aead.Open(dek, file.Nonce, file.Ciphertext, file.PayloadAd) ?? throw new InvalidOperationException("dek");
        return PayloadCodec.JsonStringForTesting(padded) ?? throw new InvalidOperationException("pad");
    }

    /// <summary>Inhalt einer Datei mit dem Master-Passwort öffnen (Sicherungen prüfen). Gehört dem Aufrufer.</summary>
    internal VaultContent OpenFile(string path, string password = KT.Pw1, FactorSecrets? factors = null)
    {
        var file = VaultFile.Parse(File.ReadAllBytes(path));
        using var pw = PasswordNormalizer.SecureBytes(password);
        var opened = VaultCrypto.OpenWithPassword(file, pw, factors ?? new FactorSecrets(), Store.Limits);
        var c = opened.Content.Clone();
        opened.Dispose();
        return c;
    }

    public void Dispose()
    {
        Vault.Lock();
        Dir.Dispose();
    }
}

/// <summary>Faktor-Material für Tests (zufällig, wie es die Plattformschicht liefern würde) und die rohen Werte.</summary>
internal sealed class KernFaktoren
{
    internal Guid SeKeyId { get; } = Guid.NewGuid();
    internal byte[] EcdhSe { get; } = RandomNumberGenerator.GetBytes(32);
    internal Guid EntryKeyId { get; } = Guid.NewGuid();
    internal byte[] EntryPublicKey { get; } = P256.RandomPoint();
    internal byte[] Q { get; } = RandomNumberGenerator.GetBytes(32);
    internal byte[] CredentialId { get; } = RandomNumberGenerator.GetBytes(48);
    internal byte[] Salt { get; } = NonZero();
    internal byte[] Output { get; } = RandomNumberGenerator.GetBytes(32);
    internal byte[] EntrySalt { get; } = NonZero();
    internal byte[] EntryOutput { get; } = RandomNumberGenerator.GetBytes(32);

    private static byte[] NonZero()
    {
        var b = RandomNumberGenerator.GetBytes(32);
        b[0] |= 1;
        return b;
    }

    internal static FactorSecret Secret(byte[] b) => FactorSecret.Copy(b);

    /// <summary>Rohe Werte für das Öffnen (nur die verlangten; frische Kopien).</summary>
    internal FactorSecrets Secrets(FactorSet set = FactorSet.All) => new()
    {
        SecureEnclave = set.Contains(FactorKind.SecureEnclave) ? Secret(EcdhSe) : null,
        Card = set.Contains(FactorKind.Card) ? Secret(Q) : null,
        SecurityKey = set.Contains(FactorKind.SecurityKey) ? Secret(Output) : null,
    };

    internal SEEnrollment SeEnrollment => new(SeKeyId, Secret(EcdhSe));
    internal EntryKeyEnrollment EntryKey => new(EntryKeyId, EntryPublicKey);
    internal CardEnrollment Card => new(Secret(Q));

    internal SecurityKeyEnrollment SecurityKey => new(CredentialId, Salt, Secret(Output), EntrySalt, Secret(EntryOutput));

    /// <summary>Material für genau die Faktoren einer Stufe (plus Eintrags-SE-Schlüssel).</summary>
    internal NewFactorMaterial Material(SecurityLevel level, bool entryKey = true) => new(
        level.Factors().Contains(FactorKind.SecureEnclave) ? SeEnrollment : null,
        entryKey ? EntryKey : null,
        level.Factors().Contains(FactorKind.Card) ? Card : null,
        level.Factors().Contains(FactorKind.SecurityKey) ? SecurityKey : null);
}

internal static class KernStufen
{
    /// <summary>Bestätigungsgruppen eines vorbereiteten Kits (beide Schemata).</summary>
    internal static string[] Confirmation(PendingRecovery p) =>
        p.Scheme == RecoveryScheme.SingleCode
            ? [.. p.ConfirmationGroups.Select(g => p.Code.Groups[g])]
            : [.. p.ShareConfirmationGroups.Select((g, k) => p.Shares[k].Groups[g])];

    /// <summary>Stufe wechseln; bringt bei Schema-Wechsel ein neues Kit mit (zurückgegeben).</summary>
    internal static PendingRecovery? Change(UnlockedVault vault, SecurityLevel level, KernFaktoren faktoren, FactorSet current,
        NewFactorMaterial? newMaterial = null, string password = KT.Pw1)
    {
        PendingRecovery? pending = null;
        if (vault.HeaderInfo.RecoveryScheme != level.RecoveryScheme())
        {
            pending = vault.PrepareRecovery(password, faktoren.Secrets(current), level.RecoveryScheme());
        }
        vault.ChangeSecurityLevel(level, password, faktoren.Secrets(current), newMaterial ?? faktoren.Material(level), pending,
            pending is null ? [] : Confirmation(pending));
        return pending;
    }

    /// <summary>Test-Tresor direkt auf Stufe <paramref name="level"/> (Testschalter-KDF); auch das gültige Kit.</summary>
    internal static (KernVault F, KernFaktoren K, PendingRecovery? Kit) Make(SecurityLevel level)
    {
        var f = KernVault.Make();
        var k = new KernFaktoren();
        var kit = Change(f.Vault, level, k, FactorSet.None);
        return (f, k, kit);
    }
}

/// <summary>Test-Anbieter für den Eintrags-Schutz: Software-P-256 statt Secure Enclave, Software-Ersatz für Windows Hello
/// (HMAC statt RSA-Signatur), feste q und y2 (aus <see cref="KernFaktoren"/>). Zählt jeden Aufruf; Fehlverhalten pro Art.</summary>
internal sealed class SchutzProvider(KernFaktoren faktoren) : IEntryFactorProvider
{
    internal enum Verhalten { Richtig, Falsch, Abbruch, FremderFehler, NichtVerfuegbar }

    private readonly Lock gate = new();
    private readonly Dictionary<FactorKind, int> calls = [];
    private readonly Dictionary<FactorKind, Verhalten> verhalten = [];
    private Action? beforeAnswer;
    private int helloCalls;

    internal KernFaktoren Faktoren { get; } = faktoren;
    internal Guid EntryKeyId { get; } = Guid.NewGuid();
    internal ECDiffieHellman SeKey { get; } = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    internal Guid HelloKeyId { get; } = Guid.NewGuid();
    internal byte[] HelloSecret { get; } = RandomNumberGenerator.GetBytes(32);

    internal EntryKeyEnrollment EntryKey => new(EntryKeyId, P256.Encode(SeKey));

    internal EntryKeyEnrollment HelloEntryKey => EntryKeyEnrollment.WindowsHello(HelloKeyId);

    internal void Set(FactorKind kind, Verhalten v)
    {
        lock (gate) { verhalten[kind] = v; }
    }

    internal void OnAnswer(Action? body)
    {
        lock (gate) { beforeAnswer = body; }
    }

    internal int Count(FactorKind kind)
    {
        lock (gate) { return calls.GetValueOrDefault(kind); }
    }

    internal int HelloCount
    {
        get { lock (gate) { return helloCalls; } }
    }

    internal int[] Counts => [Count(FactorKind.SecureEnclave), Count(FactorKind.Card), Count(FactorKind.SecurityKey)];

    internal void Reset()
    {
        lock (gate)
        {
            calls.Clear();
            helloCalls = 0;
        }
    }

    private Verhalten Enter(FactorKind kind)
    {
        Verhalten v;
        Action? hook;
        lock (gate)
        {
            calls[kind] = calls.GetValueOrDefault(kind) + 1;
            v = verhalten.GetValueOrDefault(kind, Verhalten.Richtig);
            hook = beforeAnswer;
        }
        hook?.Invoke();
        return v switch
        {
            Verhalten.Abbruch => throw new OperationCanceledException(),
            Verhalten.FremderFehler => throw new InvalidOperationException("fremd: Geheimnis-Text"),
            Verhalten.NichtVerfuegbar => throw new SiegelException(SiegelErrorCode.FactorUnavailable, kind.Code()),
            _ => v,
        };
    }

    public Task<FactorSecret> SecureEnclaveSharedSecretAsync(Guid keyId, ReadOnlyMemory<byte> ephemeralPublicKey, CancellationToken cancellationToken)
    {
        var v = Enter(FactorKind.SecureEnclave);
        if (keyId != EntryKeyId) { throw new SiegelException(SiegelErrorCode.FactorUnavailable, "secureEnclave"); }
        return Task.FromResult(Ecdh(v == Verhalten.Falsch ? ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256) : SeKey, ephemeralPublicKey.Span));
    }

    internal static FactorSecret Ecdh(ECDiffieHellman key, ReadOnlySpan<byte> peer)
    {
        using var pub = P256.Import(peer);
        var raw = key.DeriveRawSecretAgreement(pub.PublicKey);
        try
        {
            return FactorSecret.Copy(raw);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    public Task<FactorSecret> CardSecretAsync(CancellationToken cancellationToken)
    {
        var v = Enter(FactorKind.Card);
        return Task.FromResult(v == Verhalten.Falsch ? CardCode.Generate() : FactorSecret.Copy(Faktoren.Q));
    }

    public Task<FactorSecret> SecurityKeyOutputAsync(ReadOnlyMemory<byte> credentialId, ReadOnlyMemory<byte> salt, CancellationToken cancellationToken)
    {
        var v = Enter(FactorKind.SecurityKey);
        if (!credentialId.Span.SequenceEqual(Faktoren.CredentialId) || !salt.Span.SequenceEqual(Faktoren.EntrySalt))
        {
            throw new SiegelException(SiegelErrorCode.FactorUnavailable, "securityKey");
        }
        return Task.FromResult(FactorSecret.Copy(v == Verhalten.Falsch ? RandomNumberGenerator.GetBytes(32) : Faktoren.EntryOutput));
    }

    /// <summary>Software-Ersatz für Windows Hello: roh = SHA-256("Siegel v2 windows hello entry" ‖ HMAC-SHA256(k, keyID ‖ challenge)).</summary>
    public Task<FactorSecret> WindowsHelloSecretAsync(Guid keyId, ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken)
    {
        var v = Enter(FactorKind.SecureEnclave);
        lock (gate) { helloCalls++; }
        if (keyId != HelloKeyId) { throw new SiegelException(SiegelErrorCode.FactorUnavailable, "secureEnclave"); }
        return Task.FromResult(FactorSecret.Copy(HelloRaw(v == Verhalten.Falsch ? RandomNumberGenerator.GetBytes(32) : HelloSecret, keyId,
            challenge.Span)));
    }

    internal static byte[] HelloRaw(byte[] key, Guid keyId, ReadOnlySpan<byte> challenge)
    {
        byte[] message = [.. Bytes.OfGuid(keyId), .. challenge];
        var signature = HMACSHA256.HashData(key, message);
        byte[] labelled = [.. EntrySealing.HelloRawLabel, .. signature];
        return SHA256.HashData(labelled);
    }
}

/// <summary>Ein Testtresor mit Eintrags-Faktoren, deren Gegenseite <see cref="SchutzProvider"/> kennt.</summary>
internal sealed class SchutzTresor : IDisposable
{
    private SchutzTresor(KernVault f, KernFaktoren k, SchutzProvider p, PendingRecovery? kit)
    {
        F = f;
        K = k;
        P = p;
        Kit = kit;
    }

    internal KernVault F { get; }
    internal KernFaktoren K { get; }
    internal SchutzProvider P { get; }

    /// <summary>Gültiges Kit (bei Schema-Wechsel das neue, sonst das aus Create).</summary>
    internal PendingRecovery? Kit { get; }

    internal UnlockedVault Vault => F.Vault;
    internal VaultStore Store => F.Store;

    /// <summary>Stufe <paramref name="level"/>, Eintrags-Gerätefaktor des Anbieters (Mac-Art oder mit
    /// <paramref name="hello"/> die Windows-Hello-Art), dazu Karte und Sicherheitsschlüssel für Einträge.</summary>
    internal static SchutzTresor Make(SecurityLevel level = SecurityLevel.Standard, FactorSet enroll = FactorSet.All, bool hello = false)
    {
        var f = KernVault.Make();
        var k = new KernFaktoren();
        var p = new SchutzProvider(k);
        var deviceKey = hello ? p.HelloEntryKey : p.EntryKey;
        PendingRecovery? kit = f.Pending;
        if (level != SecurityLevel.Standard)
        {
            var material = k.Material(level, entryKey: false);
            if (enroll.Contains(FactorKind.SecureEnclave)) { material = material with { EntryKey = deviceKey }; }
            kit = KernStufen.Change(f.Vault, level, k, FactorSet.None, material) ?? f.Pending;
        }
        var extra = new NewFactorMaterial(
            null,
            level == SecurityLevel.Standard && enroll.Contains(FactorKind.SecureEnclave) ? deviceKey : null,
            enroll.Contains(FactorKind.Card) && !level.Factors().Contains(FactorKind.Card) ? k.Card : null,
            enroll.Contains(FactorKind.SecurityKey) && !level.Factors().Contains(FactorKind.SecurityKey) ? k.SecurityKey : null);
        if (extra.EntryKey is not null || extra.Card is not null || extra.SecurityKey is not null)
        {
            f.Vault.EnrollFactors(extra, KT.Pw1, k.Secrets(level.Factors()));
        }
        return new SchutzTresor(f, k, p, kit);
    }

    /// <summary>Öffnet erneut (Faktoren der Stufe).</summary>
    internal UnlockedVault Reopen(string password = KT.Pw1)
    {
        var level = Vault.Level;
        Vault.Lock();
        F.Vault = KT.AnyVault(Store.Unlock(password, K.Secrets(level.Factors())));
        return F.Vault;
    }

    public void Dispose() => F.Dispose();
}

/// <summary>Eintrag mit allen Geheimteilen.</summary>
internal static class SchutzEntries
{
    internal static VaultEntry Make(string title, EntryProtection protection, string? password = null) => new()
    {
        Title = title,
        Username = title.ToLowerInvariant() + "@example.ch",
        Password = password ?? "PW-" + title + "-" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(6)),
        Url = "https://" + title.ToLowerInvariant() + ".example.ch",
        Notes = "Notiz zu " + title,
        Totp = "otpauth://totp/" + title + "?secret=JBSWY3DPEHPK3PXP",
        Protection = protection,
        History = [new PasswordHistoryItem("Alt-" + title, KT.At(1_790_000_000))],
    };

    internal static EntrySecrets SecretsOf(VaultEntry e) =>
        new() { Password = e.Password, Notes = e.Notes, Totp = e.Totp, History = [.. e.History] };

    internal static void SameSecrets(VaultEntry expected, EntrySecrets got)
    {
        Assert.Equal(expected.Password, got.Password);
        Assert.Equal(expected.Notes, got.Notes);
        Assert.Equal(expected.Totp, got.Totp);
        Assert.Equal(expected.History.Select(h => h.Password), got.History.Select(h => h.Password));
    }
}

/// <summary>Software-Ersatz für V (nur Tests): der private P-256-Skalar liegt roh in <c>Hardware/&lt;vKeyID&gt;.siegelhw</c>
/// – genau die Datei, die das Vernichten löscht. Fehlt sie, ist V weg (<c>FactorUnavailable(secureEnclave)</c>).</summary>
internal sealed class VernichtungsProvider(SchutzProvider schutz, string hardware, Guid vKeyId) : IEntryFactorProvider
{
    private int vCalls;

    internal int VCount => Volatile.Read(ref vCalls);

    public Task<FactorSecret> SecureEnclaveSharedSecretAsync(Guid keyId, ReadOnlyMemory<byte> ephemeralPublicKey, CancellationToken cancellationToken)
    {
        if (keyId != vKeyId) { return schutz.SecureEnclaveSharedSecretAsync(keyId, ephemeralPublicKey, cancellationToken); }
        Interlocked.Increment(ref vCalls);
        var path = Path.Combine(hardware, Bytes.GuidText(vKeyId) + ".siegelhw");
        if (!File.Exists(path)) { throw new SiegelException(SiegelErrorCode.FactorUnavailable, "secureEnclave"); }
        var raw = File.ReadAllBytes(path);
        if (raw.Length != 32) { throw new SiegelException(SiegelErrorCode.FactorUnavailable, "secureEnclave"); }
        using var key = VTresor.FromScalar(raw);
        return Task.FromResult(SchutzProvider.Ecdh(key, ephemeralPublicKey.Span));
    }

    public Task<FactorSecret> CardSecretAsync(CancellationToken cancellationToken) => schutz.CardSecretAsync(cancellationToken);

    public Task<FactorSecret> SecurityKeyOutputAsync(ReadOnlyMemory<byte> credentialId, ReadOnlyMemory<byte> salt, CancellationToken cancellationToken) =>
        schutz.SecurityKeyOutputAsync(credentialId, salt, cancellationToken);

    public Task<FactorSecret> WindowsHelloSecretAsync(Guid keyId, ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken) =>
        schutz.WindowsHelloSecretAsync(keyId, challenge, cancellationToken);
}

/// <summary>Zählt die Aufrufe der Vernichtungs-Schicht und vernichtet wie der Kern (Datei-Variante).</summary>
internal sealed class ZaehlEraser(bool untaetig = false) : IDestructionKeyEraser
{
    private readonly Lock gate = new();
    private readonly List<Guid> ids = [];

    internal IReadOnlyList<Guid> Destroyed
    {
        get { lock (gate) { return [.. ids]; } }
    }

    public void Destroy(Guid keyId, string directory)
    {
        lock (gate) { ids.Add(keyId); }
        if (untaetig) { throw new SiegelException(SiegelErrorCode.Io, "test.eraser"); }
        new FileDestructionKeyEraser().Destroy(keyId, directory);
    }
}

/// <summary>Testtresor der Stufe 4 oder 5 mit allen Eintrags-Faktoren und einem Software-V.</summary>
internal sealed class VTresor : IDisposable
{
    internal const string DuressPw = "w=8:Q.+F3mYWO6#O8@s~@~4_q:";
    internal const string DuressPw2 = "x_b,DV_>9Ml^Zx./m936@ziw:b";

    internal VTresor(SecurityLevel level = SecurityLevel.Maximal)
    {
        T = SchutzTresor.Make(level, FactorSet.All);
        VKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        Provider = new VernichtungsProvider(T.P, T.Store.HardwareDirectory, VKeyId);
        T.Store.DestructionKeyEraser = Eraser;
        Directory.CreateDirectory(T.Store.HardwareDirectory);
        File.WriteAllBytes(VPath, VKey.ExportParameters(true).D!);
    }

    internal SchutzTresor T { get; }
    internal Guid VKeyId { get; } = Guid.NewGuid();
    internal ECDiffieHellman VKey { get; }
    internal ZaehlEraser Eraser { get; } = new();
    internal VernichtungsProvider Provider { get; }

    internal UnlockedVault Vault => T.F.Vault;
    internal VaultStore Store => T.Store;
    internal string Hardware => Store.HardwareDirectory;
    internal string VPath => Path.Combine(Hardware, Bytes.GuidText(VKeyId) + ".siegelhw");
    internal string StatePath => Path.Combine(Hardware, "zustand.json");

    internal EntryKeyEnrollment VEnrollment => new(VKeyId, P256.Encode(VKey));

    internal FactorSecrets Factors() => T.K.Secrets(Vault.Level.Factors());

    /// <summary>P-256-Schlüssel aus dem rohen Skalar (Q mit BouncyCastle gerechnet: nicht jede Plattform leitet Q beim
    /// Import selbst ab).</summary>
    internal static ECDiffieHellman FromScalar(byte[] d)
    {
        var curve = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName("P-256");
        var q = curve.G.Multiply(new Org.BouncyCastle.Math.BigInteger(1, d)).Normalize();
        return ECDiffieHellman.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = d,
            Q = new ECPoint { X = q.AffineXCoord.GetEncoded(), Y = q.AffineYCoord.GetEncoded() },
        });
    }

    internal VaultEntry Add(string title, EntryProtection protection)
    {
        var e = SchutzEntries.Make(title, protection);
        Vault.Upsert(e);
        return e;
    }

    internal Task<PurgeReport?> Einrichten(DestructionSettings s, IEnumerable<Guid> markieren, string? duress = null, bool vKey = true,
        string password = KT.Pw1) =>
        Vault.ConfigureDestructionAsync(s, duress, markieren.ToHashSet(), password, Factors(), vKey ? VEnrollment : null, Provider);

    /// <summary>Sperren und neu entsperren (Faktoren der Stufe).</summary>
    internal void Reopen(string password = KT.Pw1)
    {
        var f = Factors();
        Vault.Lock();
        T.F.Vault = KT.AnyVault(Store.Unlock(password, f));
    }

    internal UnlockedVault TryUnlock(string password) => KT.AnyVault(Store.Unlock(password, T.K.Secrets(Vault.Level.Factors())));

    internal Task<EntrySecrets> Reveal(Guid id, UnlockedVault? v = null) => (v ?? Vault).RevealSecretsAsync(id, Provider);

    internal DestructionState? State() => DestructionState.Read(Hardware);

    internal HashSet<string> HardwareNames() => [.. FileIO.ListFiles(Hardware).Select(Path.GetFileName).OfType<string>()];

    /// <summary>Kann der aktuelle Umschlag des Vernichtungs-Passworts den DEK des offenen Tresors liefern?</summary>
    internal bool DuressEnvelopeOpens(string password = DuressPw, UnlockedVault? v = null)
    {
        v ??= Vault;
        using var c = v.ContentForTesting;
        var h = v.HeaderForTesting;
        if (c?.Destruction?.Duress is not { } d || h is null || Store.ReadDuressFile(d.FileId) is not { } file) { return false; }
        using var pw = PasswordNormalizer.SecureBytes(password);
        using var dd = DuressCrypto.Derive(pw, d.Salt, h.Kdf, Store.Limits);
        using var binding = DuressCrypto.Binding(h, T.K.Secrets(h.Factors));
        var (recognized, dek) = DuressCrypto.Open(file, dd, binding, h.VaultId);
        using (dek)
        {
            if (!recognized || dek is null) { return false; }
            using var mine = v.DekForTesting();
            return dek.ConstantTimeEquals(mine);
        }
    }

    /// <summary>Offline-Angriff mit einer kopierten Ablage: wird das Passwort erkannt, und öffnet der Umschlag den Inhalt
    /// der Tresordatei <paramref name="vaultFile"/>?</summary>
    internal (bool Recognized, bool Opens) OfflineDuress(byte[] ablage, Guid fileId, byte[] vaultFile, FactorSecrets? factors,
        string password = DuressPw)
    {
        var f = DuressFile.Decode(ablage, fileId);
        var file = VaultFile.Parse(vaultFile);
        using var pw = PasswordNormalizer.SecureBytes(password);
        using var d = DuressCrypto.Derive(pw, f.Salt, file.Header.Kdf, Store.Limits);
        using var binding = factors is null ? null : DuressCrypto.Binding(file.Header, factors);
        var (recognized, dek) = DuressCrypto.Open(f, d, binding, file.Header.VaultId);
        using (dek)
        {
            if (dek is null) { return (recognized, false); }
            try
            {
                using var content = VaultCrypto.DecryptPayload(file, dek).Content;
                return (recognized, true);
            }
            catch (SiegelException)
            {
                return (recognized, false);
            }
        }
    }

    public void Dispose()
    {
        VKey.Dispose();
        T.Dispose();
    }
}
#endif
