#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using System.Security.Cryptography;
using System.Text.Json;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>
/// Interop-Datei des C#-Kerns (Stufe A): <c>windows/tests/Fixtures/cs_v2_stufe_a.siegel</c>, geschrieben von C#,
/// gelesen von C#, der Python-Referenz und dem Swift-Kern (Werte in windows/tests/Fixtures/README.md). Erzeugt nur von
/// Hand mit der Umgebungsvariable <c>SIEGEL_CS_FIXTURE_ZIEL</c> (Ordner); danach eingefroren wie die Mac-Fixtures.
/// </summary>
[Collection("EchteProfile")]
public class CsFixtureTests
{
    internal const string Name = "cs_v2_stufe_a.siegel";
    internal const string Password = "Wq7!vTz#2pLm9@Xc4$Rb8&Hn6*Kd";
    internal static readonly Guid SeKeyId = Guid.Parse("11111111-2222-4333-8444-555555555555");

    internal static FactorSecrets Factors() =>
        new() { SecureEnclave = KT.Factor(0x11), Card = KT.Factor(0x22), SecurityKey = KT.Factor(0x33) };

    /// <summary>Teil i (1…3) laut README.</summary>
    internal static string Share(int i) => Expected("Teil " + i + " von 3") ?? throw new InvalidOperationException("README");

    internal static string? Expected(string key)
    {
        var readme = Fixtures.Windows("README.md");
        if (!File.Exists(readme)) { return null; }
        foreach (var line in File.ReadAllLines(readme))
        {
            if (line.StartsWith("| " + key + " |", StringComparison.Ordinal))
            {
                var start = line.IndexOf('`', StringComparison.Ordinal);
                var end = line.LastIndexOf('`');
                return start >= 0 && end > start ? line[(start + 1)..end] : null;
            }
        }
        return null;
    }

    [Fact]
    public void Erzeugen_nur_von_Hand()
    {
        var target = Environment.GetEnvironmentVariable("SIEGEL_CS_FIXTURE_ZIEL");
        if (string.IsNullOrEmpty(target)) { return; }
        // Wie Swift UUID(): Version-4-UUID als vaultID.
        var vaultId = Bytes.OfGuid(Zufall.NewGuid());
        using var r = SecureBuffer.Random(32);
        var pk = RecoveryKem.DerivePublicKeys(r, vaultId);
        var factors = Factors();
        var fields = new HeaderFactorFields(SeKeyId, CardCode.TagBytesFor(factors.Card!, vaultId), KT.Repeat(0x44, 64), KT.Repeat(0x55, 32));
        using var pw = PasswordNormalizer.SecureBytes(Password);
        var kdf = new KdfParameters(3, 256UL << 20);
        var (header, slots, dek) = VaultCrypto.Rekey(vaultId, kdf, fields, RecoveryScheme.Shamir2Of3, pk, pw, factors, KdfLimits.Production);
        using (dek)
        {
            var now = Clock.Now();
            var entries = new List<VaultEntry>
            {
                new() { Title = "Bibliothek Bern", Username = "leserin.muster", Password = "Buecher-Regal-42!",
                    Url = "https://bibliothek.example.ch", Notes = "Ausweisnummer steht auf der Karte.", Created = now, Modified = now },
                new() { Title = "Velo-Club", Username = "velofahrer", Password = "Kette+Sattel-77", Url = "velo.example.ch",
                    Totp = "otpauth://totp/Velo-Club:velofahrer?secret=JBSWY3DPEHPK3PXP&issuer=Velo-Club",
                    History = [new PasswordHistoryItem("Rad&Weg-2026", now)], Created = now, Modified = now },
                new() { Title = "Notiz ohne Website", Notes = BeispielDateien.Notiz3, Created = now, Modified = now },
            };
            // Eintrags-Faktoren wie beim Mac-Fixture: öffentlicher Eintrags-SE-Schlüssel (Skalar 88…88, aus der Mac-Datei
            // übernommen, hängt nicht an der vaultID), Karte und Sicherheitsschlüssel aus q bzw. y2 für DIESE vaultID.
            var mac = VaultFile.Parse(Fixtures.MacBytes("v2_beispiel.siegel"));
            EntryFactorKeys.SecureEnclaveKey seEntry;
            using (var mr = RecoveryMatching.CombineShares([BeispielDateien.V2Shares[0], BeispielDateien.V2Shares[1]]))
            using (var macOpened = VaultCrypto.OpenWithRecovery(mac, mr))
            {
                seEntry = macOpened.Content.EntryFactors.SecureEnclave!;
            }
            using var y2 = KT.Factor(0x77);
            var entryFactors = new EntryFactorKeys(seEntry,
                new EntryFactorKeys.CardKey(fields.CardTag!, EntryKeyDerivation.CardPublicKeys(factors.Card!, vaultId)),
                new EntryFactorKeys.SecurityKeyInfo(KT.Repeat(0x44, 64), KT.Repeat(0x55, 32), FactorKdf.FidoCheck(factors.SecurityKey!, vaultId),
                    KT.Repeat(0x66, 32), EntryKeyDerivation.FidoPublicKeys(y2, vaultId)));
            using var content = new VaultContent(now, now, SecurityLevel.Festung, entryFactors, entries)
            {
                EntryKey = EntryBaseKey.Generate(),
            };
            content.PrepareForSave(now);
            var (bytes, _) = VaultCrypto.BuildFile(header, slots, 1, dek, content);
            Directory.CreateDirectory(target);
            File.WriteAllBytes(Path.Combine(target, Name), bytes);
            var shares = RecoveryMatching.SharesFor(r, pk);
            var lines = new List<string>
            {
                "vaultID=" + Bytes.GuidText(header.Uuid),
                "kitID=" + pk.KitId,
                "sha256=" + KT.Hex(SHA256.HashData(bytes)),
                "size=" + bytes.Length,
                "salt=" + KT.Hex(header.Salt),
                "cardTag=" + KT.Hex(fields.CardTag),
            };
            lines.AddRange(shares.Select(s => "teil" + s.Index + "=" + s.Formatted));
            File.WriteAllLines(Path.Combine(target, Name + ".werte.txt"), lines);
        }
    }

    [Fact]
    public void Oeffnet_ueber_Passwort_und_Faktoren_sowie_ueber_zwei_Teile()
    {
        var path = Fixtures.Windows(Name);
        Assert.True(File.Exists(path), "Fixture fehlt: " + path);
        var bytes = File.ReadAllBytes(path);
        Assert.Equal(Expected("SHA-256 der Datei"), KT.Hex(SHA256.HashData(bytes)));
        var file = VaultFile.Parse(bytes);
        var info = VaultFile.Inspect(bytes);
        Assert.Equal(Expected("vaultID"), Bytes.GuidText(info.VaultId));
        Assert.Equal(Expected("Kit-Kennung"), info.KitId);
        Assert.Equal(FactorSet.All, info.Factors);
        Assert.Equal(RecoveryScheme.Shamir2Of3, info.RecoveryScheme);
        Assert.Equal(SeKeyId, info.SeKeyId);
        using var pw = PasswordNormalizer.SecureBytes(Password);
        using var a = VaultCrypto.OpenWithPassword(file, pw, Factors(), KdfLimits.Production);
        Check(a.Content);
        var shares = new[] { Expected("Teil 1 von 3")!, Expected("Teil 2 von 3")!, Expected("Teil 3 von 3")! };
        foreach (var (i, j) in new[] { (0, 1), (1, 2), (2, 0) })
        {
            Assert.Equal([RecoveryCodeMatch.Exact, RecoveryCodeMatch.Exact],
                RecoveryMatching.MatchRecoveryShares(RecoveryMatching.ParseShareInputs([shares[i], shares[j]]), file.Header));
            using var r = RecoveryMatching.CombineShares([shares[i], shares[j]]);
            using var b = VaultCrypto.OpenWithRecovery(file, r);
            Check(b.Content);
            Assert.True(a.Dek.ConstantTimeEquals(b.Dek));
        }
        // Gleiche Mac-Werte für die Faktoren → gleiche Kennung wie dort berechnet
        using var q = KT.Factor(0x22);
        Assert.Equal(Expected("cardTag"), KT.Hex(CardCode.Tag(q, info.VaultId)));
    }

    private static void Check(VaultContent c)
    {
        Assert.Equal(SecurityLevel.Festung, c.Level);
        Assert.Equal(FactorSet.All, c.EntryFactors.Enrolled);
        Assert.Equal(Guid.Parse("66666666-7777-4888-8999-AAAAAAAAAAAA"), c.EntryFactors.SecureEnclave!.KeyId);
        Assert.NotNull(c.RecoveryConfirmedAt);
        Assert.NotNull(c.EntryKey);
        Assert.Equal(["Bibliothek Bern", "Velo-Club", "Notiz ohne Website"], c.Entries.Select(e => e.Title));
        Assert.Equal(["Rad&Weg-2026"], c.Entries[1].History.Select(h => h.Password));
        Assert.Equal("otpauth://totp/Velo-Club:velofahrer?secret=JBSWY3DPEHPK3PXP&issuer=Velo-Club", c.Entries[1].Totp);
        Assert.Equal(BeispielDateien.Notiz3, c.Entries[2].Notes);
    }

    [Fact]
    public void Python_Referenz_liest_die_CSharp_Datei()
    {
        // Läuft nur, wenn Python 3.12 und libsodium an den Mac-Standardorten liegen (wie ReferenzTests.swift);
        // sonst ohne Prüfung (z. B. Windows-CI).
        const string Python = "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3";
        if (!File.Exists(Python) || !File.Exists("/opt/homebrew/opt/libsodium/lib/libsodium.dylib")) { return; }
        var path = Fixtures.Windows(Name);
        var psi = new System.Diagnostics.ProcessStartInfo(Python)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in new[] { "-I", Fixtures.Referenz("siegel_referenz.py"), "siegel", path, "--se", new string('1', 64), "--karte",
                     new string('2', 64), "--fido", new string('3', 64) })
        {
            psi.ArgumentList.Add(a);
        }
        using var p = System.Diagnostics.Process.Start(psi)!;
        p.StandardInput.Write(Password);
        p.StandardInput.Close();
        var output = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        Assert.Equal(0, p.ExitCode);
        using var doc = JsonDocument.Parse(output);
        var root = doc.RootElement;
        Assert.Equal(2, root.GetProperty("formatVersion").GetInt32());
        Assert.Equal(7, root.GetProperty("factorMask").GetInt32());
        Assert.Equal(Expected("Kit-Kennung"), root.GetProperty("kitID").GetString());
        var entries = root.GetProperty("inhalt").GetProperty("entries");
        Assert.Equal("Buecher-Regal-42!", entries[0].GetProperty("password").GetString());
        Assert.Equal(BeispielDateien.Notiz3, entries[2].GetProperty("notes").GetString());
    }
}
#endif
