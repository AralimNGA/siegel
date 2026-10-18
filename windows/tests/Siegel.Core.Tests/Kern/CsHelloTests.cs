#if DEBUG
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Erwartete Werte der Interop-Dateien der Windows-Hello-Art (SPEC-WINDOWS W4.1, W7):
/// <c>cs_v2_hello.siegel</c> (Tresordatei), <c>cs_inhalt_hello.json</c> (Klartext-Inhalt mit V der Hello-Art) und
/// <c>swift_hello_aus_cs.siegel</c> (vom Swift-Kern weitergeschrieben). NIE ändern – die Werte stehen auch in
/// <c>windows/tests/Fixtures/README.md</c>. Faktoren nach der Konvention von <c>cs_v2_beispiel.siegel</c>, dazu ein fester
/// Schlüssel für den Software-Ersatz von Windows Hello.</summary>
internal static class CsHello
{
    internal const string Name = "cs_v2_hello.siegel";
    internal const string InhaltName = "cs_inhalt_hello.json";
    internal const string SwiftName = "swift_hello_aus_cs.siegel";
    internal const string Section = "## `cs_v2_hello.siegel`";
    internal const string Password = "Rk5$wT9!bN2#qX7@mH4&zP8*vC3j";
    internal static readonly KdfParameters Kdf = new(3, 256UL << 20);

    /// <summary>Zeitpunkt aller Änderungen bei der Erzeugung (Testschalter <c>Now</c>).</summary>
    internal static readonly DateTimeOffset Erzeugt = KT.At(1_792_321_200); // 2026-10-18 11:00:00 UTC

    /// <summary>Gerätefaktor zum Entsperren (Kopf). Unter Windows liefert ihn Windows Hello; im Test der feste Wert 11….</summary>
    internal static readonly Guid SeKeyId = Guid.Parse("A1111111-2222-4333-8444-555555555555");

    /// <summary>Eintrags-Gerätefaktor der Windows-Hello-Art (Schlüssel <c>Siegel-&lt;vaultID&gt;-&lt;keyID&gt;</c>).</summary>
    internal static readonly Guid HelloKeyId = Guid.Parse("B6666666-7777-4888-8999-AAAAAAAAAAAA");

    /// <summary>Schlüssel des Software-Ersatzes für Windows Hello: roh = SHA-256("Siegel v2 windows hello entry" ‖
    /// HMAC-SHA256(99…, keyID ‖ Herausforderung)) statt der RSA-Signatur (wie <see cref="SchutzProvider.HelloRaw"/>).</summary>
    internal static byte[] HelloSecret => KT.Repeat(0x99, 32);

    /// <summary>Faktoren der Stufe 4 zum Öffnen (Gerätefaktor 11…, Karte 22…).</summary>
    internal static FactorSecrets Factors() => new() { SecureEnclave = KT.Factor(0x11), Card = KT.Factor(0x22) };

    internal static NewFactorMaterial Material() => new(
        new SEEnrollment(SeKeyId, KT.Factor(0x11)),
        EntryKeyEnrollment.WindowsHello(HelloKeyId),
        new CardEnrollment(KT.Factor(0x22)),
        new SecurityKeyEnrollment(CsBeispiel.CredentialId, CsBeispiel.FidoSalt, KT.Factor(0x33), CsBeispiel.EntrySalt, KT.Factor(0x77)));

    /// <summary>Dieselben sechs Einträge wie <c>cs_v2_beispiel.siegel</c>, hier mit der Windows-Hello-Art versiegelt.</summary>
    internal static CsBeispiel.Erwartet[] Eintraege => CsBeispiel.Eintraege;

    /// <summary>Was der Swift-Kern in <c>swift_hello_aus_cs.siegel</c> geändert hat (Tests/SiegelCoreTests/Interop,
    /// <c>macAenderungen</c>): neues Passwort des offenen Eintrags „Bibliothek Bern“, „Velo-Club“ (versiegelt) umbenannt.
    /// Neue Einträge kann der Mac in diesem Tresor nicht anlegen (Stufe 4 verlangt Schutz ≥ 2, Versiegeln braucht
    /// Windows Hello).</summary>
    internal const string SwiftNeuesPasswort = "Mac-Eintrag-61!";
    internal const string SwiftUmbenannt = "Velo-Club Bern";

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

    /// <summary>Kopie einer Fixture in einem frischen Store-Ordner (echte KDF-Grenzen).</summary>
    internal static (KernTempDir Dir, VaultStore Store) CopyToStore(string name = Name)
    {
        var dir = new KernTempDir();
        var store = VaultStore.ForTesting(System.IO.Path.Combine(dir.Path, "Siegel"), new InMemoryRollbackGuard(), testKdf: false);
        FileIO.EnsureDirectory(store.DirectoryPath);
        File.Copy(Fixtures.Windows(name), store.VaultPath);
        return (dir, store);
    }

    /// <summary>JSON-Text (ohne Polster) → gepolsterter Klartext wie in der Datei.</summary>
    internal static SecureBuffer Padded(string json) => SchutzTests.Padded(json);
}

/// <summary>Software-Gegenseite der Eintrags-Faktoren von <c>cs_v2_hello.siegel</c>: Windows-Hello-Ersatz (HMAC mit 99…),
/// Karte q = 22…, Sicherheitsschlüssel (Eintrags-Salz 66…) → 77…. Die Mac-Art (ECDH) ist hier nie gefragt.</summary>
internal sealed class CsHelloProvider : IEntryFactorProvider
{
    private int hello, card, key, mac;

    /// <summary>Aufrufe: Windows Hello, Karte, Sicherheitsschlüssel.</summary>
    internal int[] Counts => [Volatile.Read(ref hello), Volatile.Read(ref card), Volatile.Read(ref key)];
    internal int MacCount => Volatile.Read(ref mac);

    public Task<FactorSecret> WindowsHelloSecretAsync(Guid keyId, ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref hello);
        if (keyId != CsHello.HelloKeyId) { throw new SiegelException(SiegelErrorCode.FactorUnavailable, "secureEnclave"); }
        return Task.FromResult(FactorSecret.Copy(SchutzProvider.HelloRaw(CsHello.HelloSecret, keyId, challenge.Span)));
    }

    public Task<FactorSecret> SecureEnclaveSharedSecretAsync(Guid keyId, ReadOnlyMemory<byte> ephemeralPublicKey, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref mac);
        throw new SiegelException(SiegelErrorCode.FactorUnavailable, "secureEnclave");
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
}

/// <summary>
/// Interop der Windows-Hello-Art (SPEC-WINDOWS W4.1, W7; SPEC §12 v4.6): <c>cs_v2_hello.siegel</c> – Stufe 4, Notfall 2
/// aus 3, Eintrags-Gerätefaktor der Windows-Hello-Art, Einträge Schutz 1–5, ein gelöschter – und
/// <c>cs_inhalt_hello.json</c> – Inhalt einer Stufe 4 mit V der Windows-Hello-Art (vernichtbarer Eintrag, Totmann, Zähler,
/// Vernichtungs-Passwort). Der Swift-Kern öffnet beide und erkennt die Einträge als „anderes Gerät“
/// (<c>Tests/SiegelCoreTests/Interop/CSharpFixtureTests.swift</c>); <c>swift_hello_aus_cs.siegel</c> hat er weitergeschrieben,
/// und C# deckt darin wieder alles über Windows Hello auf. Erzeugt nur von Hand (<c>SIEGEL_CS_HELLO_ZIEL</c> = Ordner),
/// danach eingefroren.
/// </summary>
[Collection("EchteProfile")]
public class CsHelloTests
{
    private static VaultEntry Make(CsBeispiel.Erwartet e) => new()
    {
        Title = e.Title,
        Username = e.Username,
        Password = e.Password,
        Url = e.Url,
        Notes = e.Notes,
        Totp = e.Totp,
        Protection = e.Protection,
        History = [.. e.History.Select((p, i) => new PasswordHistoryItem(p, CsBeispiel.AltesPasswort.AddDays(-i)))],
        Created = CsHello.Erzeugt,
        Modified = CsHello.Erzeugt,
    };

    [Fact]
    public async Task Erzeugen_nur_von_Hand()
    {
        var target = Environment.GetEnvironmentVariable("SIEGEL_CS_HELLO_ZIEL");
        if (string.IsNullOrEmpty(target)) { return; }
        Directory.CreateDirectory(target);
        var provider = new CsHelloProvider();
        using (KT.Hook(() =>
        {
            TestHooks.LevelKdfOverride = CsHello.Kdf;
            TestHooks.Now = CsHello.Erzeugt;
        }, () =>
        {
            TestHooks.LevelKdfOverride = null;
            TestHooks.Now = null;
        }))
        {
            using var dir = new KernTempDir();
            var store = VaultStore.ForTesting(Path.Combine(dir.Path, "Siegel"), new InMemoryRollbackGuard(), testKdf: false);
            var (vault, setup) = store.Create(CsHello.Password, CsHello.Kdf);
            using (vault)
            {
                vault.CommitRecovery(setup, KernStufen.Confirmation(setup));
                // Schutz 1 in Stufe 1, dann Stufe 4 mit den festen Faktoren (Eintrags-Gerätefaktor: Windows Hello).
                vault.Upsert(Make(CsHello.Eintraege[0]));
                var shamir = vault.PrepareRecovery(CsHello.Password, new FactorSecrets(), RecoveryScheme.Shamir2Of3);
                await vault.ChangeSecurityLevelAsync(SecurityLevel.Maximal, CsHello.Password, new FactorSecrets(), CsHello.Material(), shamir,
                    KernStufen.Confirmation(shamir), provider);
                foreach (var e in CsHello.Eintraege.Skip(1))
                {
                    var entry = Make(e);
                    await vault.UpsertAsync(entry, provider);
                    if (e.Deleted) { vault.Delete(entry.Id); }
                }
                var path = Path.Combine(target, CsHello.Name);
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
                File.WriteAllLines(Path.Combine(target, CsHello.Name + ".werte.txt"), lines);
            }
        }

        // Inhalt mit V der Windows-Hello-Art (Testschalter-KDF, nur das JSON zählt).
        using var t = SchutzTresor.Make(SecurityLevel.Maximal, hello: true);
        var hv = new HelloVProvider(t.P, Guid.Parse("C7777777-8888-4999-8AAA-BBBBBBBBBBBB"));
        t.Store.DestructionKeyEraser = hv.Eraser;
        var bank = SchutzEntries.Make("Bank", EntryProtection.Maximal);
        var mail = SchutzEntries.Make("Mail", EntryProtection.Fingerabdruck);
        var wallet = SchutzEntries.Make("Wallet «Kalt»", EntryProtection.Festung);
        var alt = SchutzEntries.Make("Alt/Weg", EntryProtection.Hoch);
        foreach (var e in new[] { bank, mail, wallet, alt }) { await t.Vault.UpsertAsync(e, hv); }
        t.Vault.Delete(alt.Id);
        await t.Vault.ConfigureDestructionAsync(new DestructionSettings(DeadmanDays: 30, MaxFailedAttempts: 20, DuressEnabled: true), KT.Pw3,
            new HashSet<Guid> { bank.Id }, KT.Pw1, t.K.Secrets(SecurityLevel.Maximal.Factors()), hv.Enrollment, hv);
        File.WriteAllText(Path.Combine(target, CsHello.InhaltName), t.F.JsonOnDisk(), new UTF8Encoding(false));
    }

    [Fact]
    public void Kopf_und_Werte_wie_im_README()
    {
        Assert.True(File.Exists(CsHello.Path), "Fixture fehlt: " + CsHello.Path);
        var bytes = File.ReadAllBytes(CsHello.Path);
        Assert.Equal(CsHello.Expected("SHA-256 der Datei"), KT.Hex(SHA256.HashData(bytes)));
        Assert.Equal(CsHello.Expected("Grösse"), bytes.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var info = VaultStore.Inspect(CsHello.Path);
        Assert.Equal(CsHello.Expected("vaultID"), Bytes.GuidText(info.VaultId));
        Assert.Equal(CsHello.Expected("Kit-Kennung"), info.KitId);
        Assert.Equal(SecurityLevel.Maximal.Factors(), info.Factors);
        Assert.Equal(RecoveryScheme.Shamir2Of3, info.RecoveryScheme);
        Assert.Equal(CsHello.SeKeyId, info.SeKeyId);
        var file = VaultFile.Parse(bytes);
        Assert.Equal(CsHello.Kdf, file.Header.Kdf);
        Assert.Equal(CsHello.Expected("Generation"), file.Generation.ToString(System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal(CsHello.Expected("kdfSalt"), KT.Hex(file.Header.Salt));
        Assert.Equal(CsHello.Expected("cardTag"), KT.Hex(file.Header.FactorFields.CardTag ?? []));
    }

    [Fact]
    public async Task Entsperren_und_alle_Eintraege_ueber_Windows_Hello_aufdecken()
    {
        var (dir, store) = CsHello.CopyToStore();
        using (dir)
        {
            var provider = new CsHelloProvider();
            using var vault = KT.Unlocked(store.Unlock(CsHello.Password, CsHello.Factors()))!;
            Assert.Equal(SecurityLevel.Maximal, vault.Level);
            Assert.Equal(FactorSet.All, vault.EnrolledFactors);
            Assert.Equal(DeviceKeyKind.WindowsHello, vault.EntryDeviceKeyKind);
            Assert.Equal(CsHello.Eintraege.Where(e => !e.Deleted).Select(e => e.Title), vault.Entries.Select(e => e.Title));
            foreach (var e in CsHello.Eintraege.Where(e => !e.Deleted))
            {
                var stored = vault.Entries.Single(x => x.Title == e.Title);
                Assert.Equal((e.Username, e.Url, e.Protection, CsHello.Erzeugt), (stored.Username, stored.Url, stored.Protection, stored.Created));
                var before = provider.Counts;
                CsBeispiel.CheckSecrets(e, await vault.RevealSecretsAsync(stored.Id, e.Protection == EntryProtection.Normal ? null : provider));
                var m = e.Protection.Factors();
                Assert.Equal([before[0] + (m.Contains(FactorKind.SecureEnclave) ? 1 : 0), before[1] + (m.Contains(FactorKind.Card) ? 1 : 0),
                    before[2] + (m.Contains(FactorKind.SecurityKey) ? 1 : 0)], provider.Counts);
            }
            var deleted = vault.DeletedEntries.Single();
            Assert.Equal("Alter Shop", deleted.Title);
            vault.Restore(deleted.Id);
            CsBeispiel.CheckSecrets(CsHello.Eintraege[^1], await vault.RevealSecretsAsync(deleted.Id, provider));
            Assert.Equal(0, provider.MacCount);
        }
    }

    [Fact]
    public void Notfallweg_mit_zwei_Teilen_ohne_Windows_Hello()
    {
        var shares = CsHello.Shares();
        var (dir, store) = CsHello.CopyToStore();
        using (dir)
        {
            Assert.Equal([RecoveryCodeMatch.Exact, RecoveryCodeMatch.Exact], store.CheckRecoveryShares([shares[1], shares[2]]));
            using var r = store.Recover([shares[1], shares[2]], KT.Pw2, CsHello.Kdf);
            Assert.Equal(SecurityLevel.Standard, r.Level);
            Assert.Null(r.EntryDeviceKeyKind);
            foreach (var e in CsHello.Eintraege)
            {
                var got = (e.Deleted ? r.DeletedEntries : r.Entries).Single(x => x.Title == e.Title);
                Assert.False(got.SecretsSealed);
                CsBeispiel.CheckSecrets(e, VaultContent.SecretsOf(got));
            }
        }
    }

    [Fact]
    public void Inhalt_der_Hello_Art_bytegleich_neu_kodiert()
    {
        var file = VaultFile.Parse(File.ReadAllBytes(CsHello.Path));
        using var pw = PasswordNormalizer.SecureBytes(CsHello.Password);
        using var opened = VaultCrypto.OpenWithPassword(file, pw, CsHello.Factors(), KdfLimits.Production);
        using var padded = Aead.Open(opened.Dek, file.Nonce, file.Ciphertext, file.PayloadAd)!;
        var (again, _) = PayloadCodec.Encode(opened.Content);
        using (again) { Assert.True(padded.ConstantTimeEquals(again)); }
        var json = PayloadCodec.JsonStringForTesting(padded)!;
        Assert.Contains("\"windowsHello\":{\"keyID\":\"" + Bytes.GuidText(CsHello.HelloKeyId) + "\",\"version\":1}", json, StringComparison.Ordinal);
        Assert.Null(opened.Content.EntryFactors.SecureEnclave);
        // Jedes Siegel mit Gerätefaktor trägt die Hello-Art, keines die Mac-Art.
        Assert.Equal(5, opened.Content.Sealed.Count);
        Assert.All(opened.Content.Sealed.Values, s => Assert.True(s.Blob.Factors.Hello is not null && s.Blob.Factors.SeEphemeral is null));
        Assert.Equal(3, opened.Content.RecoveryGroups.Count);
        Assert.All(opened.Content.RecoveryGroups, g => Assert.NotNull(g.Anchor.Factors.Hello));
        Assert.DoesNotContain("\"se\":\"", json, StringComparison.Ordinal);
        opened.Content.CheckSealing(Fehler.Corrupt);
    }

    [Fact]
    public void Inhalt_mit_V_der_Hello_Art_bytegleich_neu_kodiert()
    {
        var path = Fixtures.Windows(CsHello.InhaltName);
        Assert.True(File.Exists(path), "Fixture fehlt: " + path);
        var bytes = File.ReadAllBytes(path);
        Assert.Equal(CsHello.Expected("SHA-256 von cs_inhalt_hello.json"), KT.Hex(SHA256.HashData(bytes)));
        var json = Encoding.UTF8.GetString(bytes);
        using var padded = CsHello.Padded(json);
        var (content, _) = PayloadCodec.Decode(padded);
        using (content)
        {
            Assert.True(content.Destruction!.VKey!.IsWindowsHello);
            Assert.Single(content.Destructible);
            Assert.NotNull(content.Destructible.Values.Single().Factors.Hello);
            Assert.NotNull(content.Destruction.Duress);
            Assert.Equal(new DestructionSettings(30, 20, true), content.Destruction.Settings);
            var (again, _) = PayloadCodec.Encode(content);
            using (again) { Assert.Equal(json, PayloadCodec.JsonStringForTesting(again)); }
        }
        Assert.Contains("\"windowsHello\":1}", json, StringComparison.Ordinal);
    }

    /// <summary>Gegenrichtung: der Swift-Kern hat <c>cs_v2_hello.siegel</c> entsperrt, das Passwort des offenen Eintrags
    /// geändert und einen Hello-Eintrag umbenannt (ohne ihn aufzudecken). Die Siegel der Hello-Art blieben dabei
    /// unverändert, C# deckt alles wieder über Windows Hello auf.</summary>
    [Fact]
    public async Task Vom_Swift_Kern_weitergeschrieben_alles_ueber_Windows_Hello_lesbar()
    {
        var bytes = File.ReadAllBytes(Fixtures.Windows(CsHello.SwiftName));
        Assert.Equal(CsHello.Expected("SHA-256 von swift_hello_aus_cs.siegel"), KT.Hex(SHA256.HashData(bytes)));
        var (dir, store) = CsHello.CopyToStore(CsHello.SwiftName);
        using (dir)
        {
            var provider = new CsHelloProvider();
            using var vault = KT.Unlocked(store.Unlock(CsHello.Password, CsHello.Factors()))!;
            Assert.Equal(DeviceKeyKind.WindowsHello, vault.EntryDeviceKeyKind);
            Assert.Equal(CsHello.Eintraege.Length - 1, vault.Entries.Count);
            var bib = vault.Entries.Single(e => e.Title == "Bibliothek Bern");
            var offen = await vault.RevealSecretsAsync(bib.Id, null);
            Assert.Equal(CsHello.SwiftNeuesPasswort, offen.Password);
            Assert.Equal(["Buecher-Regal-42!"], offen.History.Select(h => h.Password));
            foreach (var e in CsHello.Eintraege.Where(e => !e.Deleted && e.Protection > EntryProtection.Normal))
            {
                var title = e.Title == "Velo-Club" ? CsHello.SwiftUmbenannt : e.Title;
                var stored = vault.Entries.Single(x => x.Title == title);
                Assert.True(stored.SecretsSealed);
                CsBeispiel.CheckSecrets(e, await vault.RevealSecretsAsync(stored.Id, provider));
            }
            Assert.Equal(["Alter Shop"], vault.DeletedEntries.Select(e => e.Title));
            Assert.Equal(0, provider.MacCount);
            // Gleiche Siegel wie in der C#-Datei (der Mac schrieb sie nur durch).
            using var pw = PasswordNormalizer.SecureBytes(CsHello.Password);
            using var original = VaultCrypto.OpenWithPassword(VaultFile.Parse(File.ReadAllBytes(CsHello.Path)), pw, CsHello.Factors(), KdfLimits.Production);
            using var swift = VaultCrypto.OpenWithPassword(VaultFile.Parse(bytes), pw, CsHello.Factors(), KdfLimits.Production);
            Assert.Equal(original.Content.EntryFactors, swift.Content.EntryFactors);
            Assert.Equal(original.Content.Sealed.OrderBy(x => x.Key), swift.Content.Sealed.OrderBy(x => x.Key));
            Assert.Equal(original.Content.RecoveryGroups, swift.Content.RecoveryGroups);
        }
    }

    [Fact]
    public void Python_Referenz_liest_die_Hello_Datei()
    {
        const string Python = "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3";
        if (!File.Exists(Python) || !File.Exists("/opt/homebrew/opt/libsodium/lib/libsodium.dylib")) { return; }
        var psi = new System.Diagnostics.ProcessStartInfo(Python)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in new[] { "-I", Fixtures.Referenz("siegel_referenz.py"), "siegel", CsHello.Path, "--se", new string('1', 64), "--karte",
                     new string('2', 64) })
        {
            psi.ArgumentList.Add(a);
        }
        using var p = System.Diagnostics.Process.Start(psi)!;
        p.StandardInput.Write(CsHello.Password);
        p.StandardInput.Close();
        var output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        Assert.Equal(0, p.ExitCode);
        using var doc = JsonDocument.Parse(output);
        var root = doc.RootElement;
        Assert.Equal(CsHello.Expected("Kit-Kennung"), root.GetProperty("kitID").GetString());
        var inhalt = root.GetProperty("inhalt");
        Assert.Equal(Bytes.GuidText(CsHello.HelloKeyId), inhalt.GetProperty("factors").GetProperty("windowsHello").GetProperty("keyID").GetString());
        Assert.Equal(JsonValueKind.Null, inhalt.GetProperty("factors").GetProperty("secureEnclave").ValueKind);
        var entries = inhalt.GetProperty("entries");
        Assert.Equal("Buecher-Regal-42!", entries[0].GetProperty("password").GetString());
        Assert.Equal(32, Convert.FromBase64String(entries[1].GetProperty("sealed").GetProperty("blob").GetProperty("hello").GetProperty("salt").GetString()!).Length);
    }
}
#endif
