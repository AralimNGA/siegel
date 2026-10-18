#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using System.Collections.Concurrent;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Gemeinsame Hilfen der Kern-Tests (Gegenstück zu KernTestSupport.swift).</summary>
internal static partial class KT
{
    // Zufällig erzeugte, starke Passwörter (wie KernTestSupport.swift).
    internal const string Pw1 = "u,F?CfDuMlYWuJASPVQ*6GUG@O";
    internal const string Pw2 = "v,:f,uX&%!kQ>NiIti@!3c>w:~";

    /// <summary>Testschalter-Profile (8 KiB…1 MiB, t 1…3).</summary>
    internal static readonly KdfParameters Kdf = new(1, 8UL << 10);
    internal static readonly KdfParameters Kdf2 = new(2, 16UL << 10);

    internal static byte[] FromHex(string s) => Convert.FromHexString(s);

    internal static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexStringLower(b);

    internal static byte[] Seq(int start, int count) => [.. Enumerable.Range(start, count).Select(i => (byte)i)];

    internal static byte[] Repeat(byte b, int count) => [.. Enumerable.Repeat(b, count)];

    internal static SecureBuffer Secure(byte[] b) => SecureBuffer.Copy(b);

    internal static FactorSecret Factor(byte b) => FactorSecret.Copy(Repeat(b, 32));

    /// <summary>Wirft genau diese SiegelException (Code + Detail)?</summary>
    internal static SiegelException Throws(SiegelErrorCode code, string detail, Action body)
    {
        var e = Assert.Throws<SiegelException>(body);
        Assert.Equal(code, e.Code);
        Assert.Equal(detail, e.Detail);
        return e;
    }

    internal static SiegelException Throws(SiegelErrorCode code, Action body)
    {
        var e = Assert.Throws<SiegelException>(body);
        Assert.Equal(code, e.Code);
        return e;
    }

    internal static void Corrupt(string detail, Action body) => Throws(SiegelErrorCode.CorruptFile, detail, body);

    /// <summary>Prüfsumme neu berechnen (Angreifer-Variante; Label nach der Version im Kopf).</summary>
    internal static byte[] WithFixedChecksum(byte[] b)
    {
        var body = b[..^FileFormat.ChecksumBytes];
        return [.. body, .. FileFormat.FileChecksum(body)];
    }

    internal static int HeaderLength(byte[] bytes)
    {
        try
        {
            return VaultFile.Parse(bytes).Header.Bytes.Length;
        }
        catch (SiegelException)
        {
            return VaultHeader.V1Size;
        }
    }
}

/// <summary>Findet die eingefrorenen Mac-Fixtures und die Python-Referenz (Repo-Wurzel über dem Testordner).</summary>
internal static class Fixtures
{
    private static readonly Lazy<string> RootDir = new(() =>
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Tests", "SiegelCoreTests", "Fixtures", "v1_beispiel.siegel"))
                && Directory.Exists(Path.Combine(dir.FullName, "windows")))
            {
                return dir.FullName;
            }
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Siegel-Wurzel mit Tests/SiegelCoreTests/Fixtures nicht gefunden");
    });

    internal static string Root => RootDir.Value;

    internal static string Mac(string name) => Path.Combine(Root, "Tests", "SiegelCoreTests", "Fixtures", name);

    internal static string Windows(string name) => Path.Combine(Root, "windows", "tests", "Fixtures", name);

    internal static string Referenz(string name) => Path.Combine(Root, "referenz", name);

    internal static byte[] MacBytes(string name) => File.ReadAllBytes(Mac(name));
}

/// <summary>Sammelt Befunde aus parallelen Läufen.</summary>
internal sealed class Findings
{
    private readonly ConcurrentQueue<string> items = new();

    internal void Add(string s) => items.Enqueue(s);

    internal IReadOnlyList<string> All => [.. items];
}

/// <summary>
/// Ein Test-Tresor im Speicher (ohne VaultStore, der erst in Stufe B kommt): Kopf, Slots und Inhalt über die
/// Kern-Bausteine gebaut, mit Testschalter-KDF. Faktoren je nach Stufe mit Zufallswerten.
/// </summary>
internal sealed class TestTresor : IDisposable
{
    private TestTresor(byte[] bytes, SecureBuffer password, SecureBuffer r, FactorSecrets factors, string code,
        IReadOnlyList<string> shares, VaultContent content)
    {
        Bytes = bytes;
        Password = password;
        R = r;
        Factors = factors;
        Code = code;
        Shares = shares;
        Content = content;
    }

    internal byte[] Bytes { get; }
    internal SecureBuffer Password { get; }
    internal SecureBuffer R { get; }
    internal FactorSecrets Factors { get; }
    internal string Code { get; }
    internal IReadOnlyList<string> Shares { get; }
    internal VaultContent Content { get; }

    internal VaultFile File => VaultFile.Parse(Bytes);

    internal static VaultEntry Entry(string title, string user = "anna", string password = "Geheim-123",
        string url = "https://example.ch", string notes = "") =>
        new() { Title = title, Username = user, Password = password, Url = url, Notes = notes };

    internal static TestTresor Create(SecurityLevel level = SecurityLevel.Standard, KdfParameters? kdf = null,
        IEnumerable<VaultEntry>? entries = null, string password = KT.Pw1, ulong generation = 1)
    {
        var vaultId = Zufall.Bytes(16);
        var r = SecureBuffer.Random(32);
        var pk = RecoveryKem.DerivePublicKeys(r, vaultId);
        var mask = level.Factors();
        var factors = new FactorSecrets();
        var fields = HeaderFactorFields.None;
        if (mask.Contains(FactorKind.SecureEnclave))
        {
            factors.SecureEnclave = FactorSecret.Copy(Zufall.Bytes(32));
            fields = fields with { SeKeyId = Zufall.NewGuid() };
        }
        if (mask.Contains(FactorKind.Card))
        {
            factors.Card = CardCode.Generate();
            fields = fields with { CardTag = CardCode.TagBytesFor(factors.Card, vaultId) };
        }
        if (mask.Contains(FactorKind.SecurityKey))
        {
            factors.SecurityKey = FactorSecret.Copy(Zufall.Bytes(32));
            var salt = Zufall.Bytes(32);
            salt[0] |= 1;
            fields = fields with { FidoCredentialId = Zufall.Bytes(64), FidoSalt = salt };
        }
        var pw = PasswordNormalizer.SecureBytes(password);
        var (header, slots, dek) = VaultCrypto.Rekey(vaultId, kdf ?? KT.Kdf, fields, level.RecoveryScheme(), pk, pw, factors,
            KdfLimits.Testing);
        using (dek)
        {
            var content = new VaultContent(Clock.Now(), null, level, EntryFactorKeys.None,
                [.. entries ?? [Entry("Bank", password: "Konto-123", notes: "Notiz"), Entry("Mail", "anna@example.ch", "Post-456")]])
            {
                EntryKey = EntryBaseKey.Generate(),
            };
            content.PrepareForSave(Clock.Now());
            var (bytes, _)= VaultCrypto.BuildFile(header, slots, generation, dek, content);
            var code = RecoveryCodeCodec.Format(r);
            var shares = RecoveryMatching.SharesFor(r, pk).Select(s => s.Formatted).ToList();
            return new TestTresor(bytes, pw, r, factors, code, shares, content);
        }
    }

    public void Dispose()
    {
        Password.Dispose();
        R.Dispose();
        Factors.SecureEnclave?.Dispose();
        Factors.Card?.Dispose();
        Factors.SecurityKey?.Dispose();
        Content.Dispose();
    }
}

/// <summary>Serielle Sammlung für Tests mit echten Argon2-Profilen (≥ 256 MiB), wie Swift <c>.serialized</c>.</summary>
[CollectionDefinition("EchteProfile", DisableParallelization = true)]
public sealed class EchteProfileSammlung;
#endif
