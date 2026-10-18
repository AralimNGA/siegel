#if DEBUG
using System.Security.Cryptography;
using System.Text.Json;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Erwartete Werte von <c>windows/tests/Fixtures/cs_v2_beispiel.siegel</c> (SPEC-WINDOWS W7). NIE ändern – sie
/// stehen auch in <c>windows/tests/Fixtures/README.md</c>. Faktoren nach der Konvention von <c>v2_beispiel.siegel</c>.</summary>
internal static class CsBeispiel
{
    internal const string Name = "cs_v2_beispiel.siegel";
    internal const string Section = "## `cs_v2_beispiel.siegel`";
    internal const string Password = "Fj8#qW2!xN5@tR9$kP3&vL6*hZ4m";
    internal static readonly KdfParameters Kdf = new(3, 256UL << 20);

    /// <summary>Zeitpunkt aller Änderungen bei der Erzeugung (Testschalter <c>Now</c>).</summary>
    internal static readonly DateTimeOffset Erzeugt = KT.At(1_792_317_600); // 2026-10-18 10:00:00 UTC
    internal static readonly DateTimeOffset AltesPasswort = KT.At(1_760_000_000);

    internal static readonly Guid SeKeyId = Guid.Parse("11111111-2222-4333-8444-555555555555");
    internal static readonly Guid EntryKeyId = Guid.Parse("66666666-7777-4888-8999-AAAAAAAAAAAA");
    internal static byte[] EntryScalar => KT.Repeat(0x88, 32);
    internal static byte[] CredentialId => KT.Repeat(0x44, 64);
    internal static byte[] FidoSalt => KT.Repeat(0x55, 32);
    internal static byte[] EntrySalt => KT.Repeat(0x66, 32);

    /// <summary>Faktoren der Stufe 4 zum Öffnen (Secure Enclave 11…, Karte 22…).</summary>
    internal static FactorSecrets Factors() => new() { SecureEnclave = KT.Factor(0x11), Card = KT.Factor(0x22) };

    internal static byte[] EntryPublicKey()
    {
        using var k = VTresor.FromScalar(EntryScalar);
        return P256.Encode(k);
    }

    internal static NewFactorMaterial Material() => new(
        new SEEnrollment(SeKeyId, KT.Factor(0x11)),
        new EntryKeyEnrollment(EntryKeyId, EntryPublicKey()),
        new CardEnrollment(KT.Factor(0x22)),
        new SecurityKeyEnrollment(CredentialId, FidoSalt, KT.Factor(0x33), EntrySalt, KT.Factor(0x77)));

    internal sealed record Erwartet(string Title, string Username, string Password, string Url, string Notes, string Totp,
        string[] History, EntryProtection Protection, bool Deleted = false);

    internal const string Notiz = "Zeilen\nmit Umlauten: äöü, Zeichen: «» – Ende";

    /// <summary>Die sechs Einträge (Reihenfolge der Datei). „Bibliothek Bern“ entstand in Stufe 1 (Schutz 1 bleibt beim
    /// Stufenwechsel), die übrigen in Stufe 4.</summary>
    internal static readonly Erwartet[] Eintraege =
    [
        new("Bibliothek Bern", "leserin.muster", "Buecher-Regal-42!", "https://bibliothek.example.ch", "Ausweisnummer steht auf der Karte.", "",
            [], EntryProtection.Normal),
        new("Velo-Club", "velofahrer", "Kette+Sattel-77", "velo.example.ch", "",
            "otpauth://totp/Velo-Club:velofahrer?secret=JBSWY3DPEHPK3PXP&issuer=Velo-Club", ["Rad&Weg-2026"], EntryProtection.Fingerabdruck),
        new("Krankenkasse", "versicherte.4711", "Praemie-2027!", "https://kasse.example.ch", "Versichertennummer 756.0000.0000.00", "",
            [], EntryProtection.Hoch),
        new("Bank Thun", "kunde-0815", "Konto#Sicher-4", "https://bank.example.ch",
            "PIN-Brief im Ordner «Bank», Karte gültig bis 12/29", "otpauth://totp/Bank:kunde-0815?secret=KRSXG5CTMVRXEZLU&issuer=Bank",
            ["Alt-Konto-3", "Alt-Konto-2"], EntryProtection.Maximal),
        new("Krypto-Wallet", "", "Seed+Phrase-55", "", Notiz, "", [], EntryProtection.Festung),
        new("Alter Shop", "kaeufer", "Warenkorb-99", "https://shop.example.ch", "Konto gekündigt", "", [], EntryProtection.Hoch, Deleted: true),
    ];

    internal static string Path => Fixtures.Windows(Name);

    /// <summary>Wert aus der README-Tabelle dieses Abschnitts (Spalte 2, in Backticks).</summary>
    internal static string? Expected(string key)
    {
        var readme = Fixtures.Windows("README.md");
        if (!File.Exists(readme)) { return null; }
        var inSection = false;
        foreach (var line in File.ReadAllLines(readme))
        {
            if (line.StartsWith("## ", StringComparison.Ordinal)) { inSection = line.StartsWith(Section, StringComparison.Ordinal); }
            if (inSection && line.StartsWith("| " + key + " |", StringComparison.Ordinal))
            {
                var start = line.IndexOf('`', StringComparison.Ordinal);
                var end = line.LastIndexOf('`');
                return start >= 0 && end > start ? line[(start + 1)..end] : null;
            }
        }
        return null;
    }

    internal static string[] Shares() =>
        [.. Enumerable.Range(1, 3).Select(i => Expected("Teil " + i + " von 3") ?? throw new InvalidOperationException("README"))];

    /// <summary>Kopie der Fixture in einem frischen Store-Ordner (echte KDF-Grenzen).</summary>
    internal static (KernTempDir Dir, VaultStore Store) CopyToStore()
    {
        var dir = new KernTempDir();
        var store = VaultStore.ForTesting(System.IO.Path.Combine(dir.Path, "Siegel"), new InMemoryRollbackGuard(), testKdf: false);
        FileIO.EnsureDirectory(store.DirectoryPath);
        File.Copy(Path, store.VaultPath);
        return (dir, store);
    }

    internal static void CheckSecrets(Erwartet e, EntrySecrets s)
    {
        Assert.Equal(e.Password, s.Password);
        Assert.Equal(e.Notes, s.Notes);
        Assert.Equal(e.Totp, s.Totp);
        Assert.Equal(e.History, s.History.Select(h => h.Password));
    }
}

/// <summary>Software-Gegenseite der Eintrags-Faktoren der Fixture (wie die Plattform sie liefern würde): Eintrags-SE-Schlüssel
/// mit Skalar 88…, Karte q = 22…, Sicherheitsschlüssel (Eintrags-Salz 66…) → 77….</summary>
internal sealed class CsBeispielProvider : IEntryFactorProvider, IDisposable
{
    private readonly ECDiffieHellman entryKey = VTresor.FromScalar(CsBeispiel.EntryScalar);
    private int se, card, key;

    internal int[] Counts => [Volatile.Read(ref se), Volatile.Read(ref card), Volatile.Read(ref key)];

    public Task<FactorSecret> SecureEnclaveSharedSecretAsync(Guid keyId, ReadOnlyMemory<byte> ephemeralPublicKey, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref se);
        if (keyId != CsBeispiel.EntryKeyId) { throw new SiegelException(SiegelErrorCode.FactorUnavailable, "secureEnclave"); }
        return Task.FromResult(SchutzProvider.Ecdh(entryKey, ephemeralPublicKey.Span));
    }

    public Task<FactorSecret> CardSecretAsync(CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref card);
        return Task.FromResult(KT.Factor(0x22));
    }

    public Task<FactorSecret> SecurityKeyOutputAsync(ReadOnlyMemory<byte> credentialId, ReadOnlyMemory<byte> salt, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref key);
        if (!credentialId.Span.SequenceEqual(CsBeispiel.CredentialId) || !salt.Span.SequenceEqual(CsBeispiel.EntrySalt))
        {
            throw new SiegelException(SiegelErrorCode.FactorUnavailable, "securityKey");
        }
        return Task.FromResult(KT.Factor(0x77));
    }

    public void Dispose() => entryKey.Dispose();
}

/// <summary>
/// Interop-Datei des C#-Kerns (Stufe B): <c>windows/tests/Fixtures/cs_v2_beispiel.siegel</c> – Stufe 4, Notfall 2 aus 3,
/// Einträge mit Schutz 1–5 (versiegelt mit den festen Software-Faktoren), TOTP, Verlauf, ein gelöschter Eintrag. Erzeugt nur
/// von Hand (<c>SIEGEL_CS_BEISPIEL_ZIEL</c> = Ordner); danach eingefroren wie die Mac-Fixtures.
/// </summary>
[Collection("EchteProfile")]
public class CsBeispielTests
{
    [Fact]
    public void Erzeugen_nur_von_Hand()
    {
        var target = Environment.GetEnvironmentVariable("SIEGEL_CS_BEISPIEL_ZIEL");
        if (string.IsNullOrEmpty(target)) { return; }
        using var hooks = KT.Hook(() =>
        {
            TestHooks.LevelKdfOverride = CsBeispiel.Kdf;
            TestHooks.Now = CsBeispiel.Erzeugt;
        }, () =>
        {
            TestHooks.LevelKdfOverride = null;
            TestHooks.Now = null;
        });
        using var dir = new KernTempDir();
        var store = VaultStore.ForTesting(Path.Combine(dir.Path, "Siegel"), new InMemoryRollbackGuard(), testKdf: false);
        var (vault, setup) = store.Create(CsBeispiel.Password, CsBeispiel.Kdf);
        using (vault)
        {
            vault.CommitRecovery(setup, KernStufen.Confirmation(setup));
            VaultEntry Make(CsBeispiel.Erwartet e) => new()
            {
                Title = e.Title,
                Username = e.Username,
                Password = e.Password,
                Url = e.Url,
                Notes = e.Notes,
                Totp = e.Totp,
                Protection = e.Protection,
                History = [.. e.History.Select((p, i) => new PasswordHistoryItem(p, CsBeispiel.AltesPasswort.AddDays(-i)))],
                Created = CsBeispiel.Erzeugt,
                Modified = CsBeispiel.Erzeugt,
            };
            // Schutz 1 in Stufe 1 anlegen (in Stufe 4 ist das Minimum Schutz 2), dann Stufe 4 mit festen Faktoren.
            vault.Upsert(Make(CsBeispiel.Eintraege[0]));
            var shamir = vault.PrepareRecovery(CsBeispiel.Password, new FactorSecrets(), RecoveryScheme.Shamir2Of3);
            vault.ChangeSecurityLevel(SecurityLevel.Maximal, CsBeispiel.Password, new FactorSecrets(), CsBeispiel.Material(), shamir,
                KernStufen.Confirmation(shamir));
            foreach (var e in CsBeispiel.Eintraege.Skip(1))
            {
                var entry = Make(e);
                vault.Upsert(entry);
                if (e.Deleted) { vault.Delete(entry.Id); }
            }
            Directory.CreateDirectory(target);
            var path = Path.Combine(target, CsBeispiel.Name);
            File.Copy(store.VaultPath, path, overwrite: true);
            var bytes = File.ReadAllBytes(path);
            var file = VaultFile.Parse(bytes);
            var lines = new List<string>
            {
                "vaultID=" + Bytes.GuidText(file.Header.Uuid),
                "kitID=" + file.Header.Pk.KitId,
                "generation=" + file.Generation,
                "sha256=" + KT.Hex(SHA256.HashData(bytes)),
                "size=" + bytes.Length,
                "salt=" + KT.Hex(file.Header.Salt),
                "cardTag=" + KT.Hex(file.Header.FactorFields.CardTag ?? []),
            };
            lines.AddRange(shamir.Shares.Select(s => "teil" + s.Index + "=" + s.Formatted));
            File.WriteAllLines(Path.Combine(target, CsBeispiel.Name + ".werte.txt"), lines);
        }
    }

    [Fact]
    public void Kopf_und_Werte_wie_im_README()
    {
        Assert.True(File.Exists(CsBeispiel.Path), "Fixture fehlt: " + CsBeispiel.Path);
        var bytes = File.ReadAllBytes(CsBeispiel.Path);
        Assert.Equal(CsBeispiel.Expected("SHA-256 der Datei"), KT.Hex(SHA256.HashData(bytes)));
        Assert.Equal(CsBeispiel.Expected("Grösse"), bytes.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var info = VaultStore.Inspect(CsBeispiel.Path);
        Assert.Equal(CsBeispiel.Expected("vaultID"), Bytes.GuidText(info.VaultId));
        Assert.Equal(CsBeispiel.Expected("Kit-Kennung"), info.KitId);
        Assert.Equal(SecurityLevel.Maximal.Factors(), info.Factors);
        Assert.Equal(RecoveryScheme.Shamir2Of3, info.RecoveryScheme);
        Assert.Equal(CsBeispiel.SeKeyId, info.SeKeyId);
        var file = VaultFile.Parse(bytes);
        Assert.Equal(2, file.Header.FormatVersion);
        Assert.Equal(CsBeispiel.Kdf, file.Header.Kdf);
        Assert.Equal(CsBeispiel.Expected("Generation"), file.Generation.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal(CsBeispiel.Expected("kdfSalt"), KT.Hex(file.Header.Salt));
        Assert.Equal(CsBeispiel.Expected("cardTag"), KT.Hex(file.Header.FactorFields.CardTag ?? []));
        // Gleicher Eintrags-SE-Schlüssel (Skalar 88…) wie in der Mac-Datei v2_beispiel.siegel.
        using var mr = RecoveryMatching.CombineShares([BeispielDateien.V2Shares[0], BeispielDateien.V2Shares[1]]);
        using var mac = VaultCrypto.OpenWithRecovery(VaultFile.Parse(Fixtures.MacBytes("v2_beispiel.siegel")), mr);
        Assert.Equal(mac.Content.EntryFactors.SecureEnclave!.PublicKey, CsBeispiel.EntryPublicKey());
    }

    [Fact]
    public async Task Entsperren_ueber_den_Store_und_alle_Eintraege_aufdecken()
    {
        var (dir, store) = CsBeispiel.CopyToStore();
        using (dir)
        {
            using var provider = new CsBeispielProvider();
            using var vault = KT.Unlocked(store.Unlock(CsBeispiel.Password, CsBeispiel.Factors()))!;
            Assert.Equal(SecurityLevel.Maximal, vault.Level);
            Assert.Equal(CsBeispiel.Kdf, vault.Kdf);
            Assert.True(vault.RecoveryConfirmed);
            Assert.Equal(FactorSet.All, vault.EnrolledFactors);
            Assert.Equal(DeviceKeyKind.SecureEnclaveP256, vault.EntryDeviceKeyKind);
            Assert.Equal(CsBeispiel.Expected("Kit-Kennung"), vault.KitId);
            var live = CsBeispiel.Eintraege.Where(e => !e.Deleted).ToArray();
            Assert.Equal(live.Select(e => e.Title), vault.Entries.Select(e => e.Title));
            Assert.Equal(["Alter Shop"], vault.DeletedEntries.Select(e => e.Title));
            foreach (var e in CsBeispiel.Eintraege)
            {
                var stored = (e.Deleted ? vault.DeletedEntries : vault.Entries).Single(x => x.Title == e.Title);
                Assert.Equal((e.Username, e.Url, e.Protection), (stored.Username, stored.Url, stored.Protection));
                Assert.Equal(e.Protection > EntryProtection.Normal, stored.SecretsSealed);
                Assert.Equal(CsBeispiel.Erzeugt, stored.Created);
                if (e.Deleted)
                {
                    Assert.Equal(CsBeispiel.Erzeugt, stored.DeletedAt);
                    continue;
                }
                var before = provider.Counts;
                CsBeispiel.CheckSecrets(e, await vault.RevealSecretsAsync(stored.Id, e.Protection == EntryProtection.Normal ? null : provider));
                var m = e.Protection.Factors();
                Assert.Equal([before[0] + (m.Contains(FactorKind.SecureEnclave) ? 1 : 0), before[1] + (m.Contains(FactorKind.Card) ? 1 : 0),
                    before[2] + (m.Contains(FactorKind.SecurityKey) ? 1 : 0)], provider.Counts);
            }
            // Gelöschter Eintrag: wiederherstellen und aufdecken.
            var deleted = vault.DeletedEntries.Single();
            vault.Restore(deleted.Id);
            CsBeispiel.CheckSecrets(CsBeispiel.Eintraege[^1], await vault.RevealSecretsAsync(deleted.Id, provider));
            // Der C#-Kern schreibt die Kopie weiter (Generation + 1) und öffnet sie wieder.
            var generation = vault.Generation;
            vault.Lock();
            using var again = KT.Unlocked(store.Unlock(CsBeispiel.Password, CsBeispiel.Factors()))!;
            Assert.Equal(generation, again.Generation);
            Assert.Equal(6, again.Entries.Count);
        }
    }

    [Fact]
    public void Notfallweg_mit_je_zwei_Teilen()
    {
        var shares = CsBeispiel.Shares();
        var file = VaultFile.Parse(File.ReadAllBytes(CsBeispiel.Path));
        foreach (var (i, j) in new[] { (0, 1), (1, 2), (2, 0) })
        {
            Assert.Equal([RecoveryCodeMatch.Exact, RecoveryCodeMatch.Exact],
                RecoveryMatching.MatchRecoveryShares(RecoveryMatching.ParseShareInputs([shares[i], shares[j]]), file.Header));
        }
        var (dir, store) = CsBeispiel.CopyToStore();
        using (dir)
        {
            Assert.Equal([RecoveryCodeMatch.Exact, RecoveryCodeMatch.Exact], store.CheckRecoveryShares([shares[2], shares[0]]));
            using var r = store.Recover([shares[2], shares[0]], KT.Pw2, CsBeispiel.Kdf);
            Assert.Equal(SecurityLevel.Standard, r.Level);
            foreach (var e in CsBeispiel.Eintraege)
            {
                var got = (e.Deleted ? r.DeletedEntries : r.Entries).Single(x => x.Title == e.Title);
                Assert.False(got.SecretsSealed);
                CsBeispiel.CheckSecrets(e, VaultContent.SecretsOf(got));
            }
        }
    }

    [Fact]
    public void Inhalt_wird_bytegleich_neu_kodiert()
    {
        var file = VaultFile.Parse(File.ReadAllBytes(CsBeispiel.Path));
        using var pw = PasswordNormalizer.SecureBytes(CsBeispiel.Password);
        using var opened = VaultCrypto.OpenWithPassword(file, pw, CsBeispiel.Factors(), KdfLimits.Production);
        using var padded = Aead.Open(opened.Dek, file.Nonce, file.Ciphertext, file.PayloadAd)!;
        var (again, _) = PayloadCodec.Encode(opened.Content);
        using (again) { Assert.True(padded.ConstantTimeEquals(again)); }
        var json = PayloadCodec.JsonStringForTesting(padded)!;
        // Mac-Art: keine Schlüssel der Windows-Hello-Art.
        Assert.DoesNotContain("windowsHello", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"hello\"", json, StringComparison.Ordinal);
        Assert.Equal(5, opened.Content.Sealed.Count);
        Assert.Equal(3, opened.Content.RecoveryGroups.Count);
        Assert.Equal(6, opened.Content.Meta.Count);
        opened.Content.CheckSealing(Fehler.Corrupt);
    }

    [Fact]
    public void Python_Referenz_liest_Kopf_und_Inhalt()
    {
        // Wie CsFixtureTests: nur mit Python 3.12 und libsodium an den Mac-Standardorten, sonst ohne Prüfung.
        const string Python = "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3";
        if (!File.Exists(Python) || !File.Exists("/opt/homebrew/opt/libsodium/lib/libsodium.dylib")) { return; }
        var psi = new System.Diagnostics.ProcessStartInfo(Python)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in new[] { "-I", Fixtures.Referenz("siegel_referenz.py"), "siegel", CsBeispiel.Path, "--se", new string('1', 64), "--karte",
                     new string('2', 64) })
        {
            psi.ArgumentList.Add(a);
        }
        using var p = System.Diagnostics.Process.Start(psi)!;
        p.StandardInput.Write(CsBeispiel.Password);
        p.StandardInput.Close();
        var output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        Assert.Equal(0, p.ExitCode);
        using var doc = JsonDocument.Parse(output);
        var root = doc.RootElement;
        Assert.Equal(2, root.GetProperty("formatVersion").GetInt32());
        Assert.Equal(3, root.GetProperty("factorMask").GetInt32());
        Assert.Equal(CsBeispiel.Expected("Kit-Kennung"), root.GetProperty("kitID").GetString());
        var inhalt = root.GetProperty("inhalt");
        var entries = inhalt.GetProperty("entries");
        Assert.Equal("Buecher-Regal-42!", entries[0].GetProperty("password").GetString());
        // Versiegelte Einträge: leer im Klartext, die Geheimteile nur im Siegel.
        Assert.Equal("", entries[1].GetProperty("password").GetString());
        Assert.Equal(JsonValueKind.Object, entries[1].GetProperty("sealed").ValueKind);
        Assert.Equal(5, entries.EnumerateArray().Count(e => e.TryGetProperty("sealed", out var x) && x.ValueKind == JsonValueKind.Object));
        Assert.Equal(6, entries.GetArrayLength());
        Assert.Equal(3, inhalt.GetProperty("recoveryGroups").GetArrayLength());
        Assert.Equal(4, inhalt.GetProperty("level").GetInt32());
    }
}
#endif
