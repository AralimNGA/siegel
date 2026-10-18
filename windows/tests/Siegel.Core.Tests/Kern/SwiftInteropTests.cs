#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using System.Text;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>
/// Gegenrichtung zu <see cref="CsFixtureTests"/>: Dateien, die der heutige Swift-Kern geschrieben hat
/// (windows/tests/Fixtures/README.md): ein Inhalts-JSON mit allem (versiegelt, vernichtbar, Gruppen, Vernichtung,
/// meta) und die C#-Datei, nachdem Swift sie weitergeschrieben hat. C# liest beides und kodiert das JSON bytegleich.
/// </summary>
[Collection("EchteProfile")]
public class SwiftInteropTests
{
    private static string RoundTrip(string swiftJson)
    {
        using var c = InhaltTests.Decode(swiftJson);
        var (padded, _) = PayloadCodec.Encode(c);
        using (padded) { return PayloadCodec.JsonStringForTesting(padded)!; }
    }

    [Fact]
    public void Reiches_Swift_JSON_wird_gelesen_und_bytegleich_neu_kodiert()
    {
        var raw = File.ReadAllBytes(Fixtures.Windows("swift_inhalt_stufe_b.json"));
        Assert.Equal("c0ae0e5fbeaaa1727e996fdeb0c18490fd70a0ccba9325ef4f721f46d6377595",
            KT.Hex(System.Security.Cryptography.SHA256.HashData(raw)));
        var json = Encoding.UTF8.GetString(raw);
        Assert.Equal(json, RoundTrip(json));
        using var c = InhaltTests.Decode(json);
        Assert.Equal(SecurityLevel.Festung, c.Level);
        Assert.Equal(7, c.Entries.Count);
        Assert.All(c.Entries, e => Assert.True(e.SecretsSealed));
        Assert.Equal(6, c.Sealed.Count);
        var max = Assert.Single(c.Destructible);
        Assert.Equal("Max", c.Entries.Single(e => e.Id == max.Key).Title);
        Assert.Equal(2, c.RecoveryGroups.Count);
        Assert.Equal(7, c.Meta.Count);
        Assert.NotNull(c.EntryKey);
        Assert.Equal(FactorSet.All, c.EntryFactors.Enrolled);
        Assert.Equal(new DestructionSettings(30, 20, true), c.Destruction!.Settings);
        Assert.NotNull(c.Destruction.VKey);
        Assert.NotNull(c.Destruction.Duress);
        Assert.NotNull(c.Entries.Single(e => e.Title == "Weg").DeletedAt);
        var sonder = c.Entries.Single(e => e.Title.StartsWith("Sonder", StringComparison.Ordinal));
        Assert.Equal("Sonder \"/\\ \u0001\u007f", sonder.Title);
        Assert.Equal("ä@ö.ch", sonder.Username);
        Assert.Equal("https://x.example/a?b=c", sonder.Url);
        Assert.Equal(["Offen", "Finger", "Hoch", "Max", "Festung"],
            c.Entries.Take(5).Select(e => e.Title));
        Assert.Equal([EntryProtection.Fingerabdruck, EntryProtection.Fingerabdruck, EntryProtection.Hoch, EntryProtection.Maximal,
            EntryProtection.Festung], c.Entries.Take(5).Select(e => e.Protection));
    }

    [Fact]
    public void Von_Swift_weitergeschriebene_CSharp_Datei_oeffnet_auf_beiden_Wegen()
    {
        var bytes = File.ReadAllBytes(Fixtures.Windows("swift_v2_aus_cs.siegel"));
        Assert.Equal("8716d4047941c8dc98d079aa4fec58dd00662576f05ab49e8741bc4c23ee1308",
            KT.Hex(System.Security.Cryptography.SHA256.HashData(bytes)));
        var file = VaultFile.Parse(bytes);
        Assert.Equal(2UL, file.Generation);
        using var pw = PasswordNormalizer.SecureBytes(CsFixtureTests.Password);
        using var a = VaultCrypto.OpenWithPassword(file, pw, CsFixtureTests.Factors(), KdfLimits.Production);
        var c = a.Content;
        Assert.Equal(["Bibliothek Bern", "Velo-Club", "Notiz ohne Website", "Von Swift"], c.Entries.Select(e => e.Title));
        var swift = c.Entries[3];
        Assert.True(swift.SecretsSealed);
        Assert.Equal(EntryProtection.Fingerabdruck, swift.Protection);
        Assert.Equal("", swift.Password);
        Assert.Single(c.Sealed);
        Assert.Single(c.RecoveryGroups);
        Assert.Equal(4, c.Meta.Count);
        Assert.Equal("Buecher-Regal-42!", c.Entries[0].Password);
        // Der Grundschlüssel bleibt über das Speichern von Swift derselbe wie in der C#-Datei.
        var original = VaultFile.Parse(File.ReadAllBytes(Fixtures.Windows(CsFixtureTests.Name)));
        using (var r0 = RecoveryMatching.CombineShares(
                   [CsFixtureTests.Share(1), CsFixtureTests.Share(2)]))
        using (var o = VaultCrypto.OpenWithRecovery(original, r0))
        {
            Assert.True(o.Content.EntryKey!.Key.ConstantTimeEquals(c.EntryKey!.Key));
        }
        using var r = RecoveryMatching.CombineShares([CsFixtureTests.Share(2), CsFixtureTests.Share(3)]);
        using var b = VaultCrypto.OpenWithRecovery(file, r);
        Assert.True(a.Dek.ConstantTimeEquals(b.Dek));
        // JSON des Swift-Speicherns bytegleich neu kodiert
        using var padded = Aead.Open(a.Dek, file.Nonce, file.Ciphertext, file.PayloadAd)!;
        var json = PayloadCodec.JsonStringForTesting(padded)!;
        Assert.Equal(json, RoundTrip(json));
    }
}
#endif
