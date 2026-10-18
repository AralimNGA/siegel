#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using System.Text;
using System.Text.Json;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Werte der eingefrorenen Mac-Beispieldateien (Tests/SiegelCoreTests/Fixtures/README.md). NIE ändern.</summary>
internal static class BeispielDateien
{
    internal const string V1Password = "7:etFa_0+Isq#jQ0oeTb8nWKFM*9";
    internal const string V1Code = "NHZZD-BYYYZ-ZYMNR-W0S31-BZK7X-0S860-H7KZ4-YEBE7-7JNMC-G8367-YZ2N0";
    internal const string V1VaultId = "06CAF7C7-5BFA-4C75-ABEC-76E7488CC7A2";

    internal const string V2Password = "6Bn__S?ZC37umQe_9A!^6K!9_nNk";
    internal const string V2VaultId = "D4F9B640-FECB-4BAB-A72D-28DBA1D1636D";

    internal static readonly string[] V2Shares =
    [
        "04A6Z-0CJEQ-E7T55-1KVCB-7K5WQ-E3V63-2BGH5-P3KM3-RQF38-40TW4-Y1XQ2-N",
        "08F19-MM81R-FAMDM-D44N1-N36HJ-M1QKG-CG8GG-G7JF2-Q81KE-637EJ-35EMW-0",
        "0CC3V-RVQ4Y-MYEA3-0QP6Q-TH83H-XZKYW-YS0G3-X8F9M-CS43D-TAC0W-CSJTH-6",
    ];

    internal static FactorSecrets V2Factors() =>
        new() { SecureEnclave = KT.Factor(0x11), Card = KT.Factor(0x22), SecurityKey = KT.Factor(0x33) };

    /// <summary>Vergleicht einen geöffneten Tresor mit referenz/erwartet_v*.json (von Hand aus dem README übernommen).</summary>
    internal static void CheckAgainstReference(string referenceName, VaultFile file, VaultContent content, int fileSize)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(Fixtures.Referenz(referenceName)));
        var x = doc.RootElement;
        Assert.Equal(x.GetProperty("formatVersion").GetInt32(), file.Header.FormatVersion);
        Assert.Equal(x.GetProperty("vaultID").GetString(), Bytes.GuidText(file.Header.Uuid));
        Assert.Equal(x.GetProperty("kitID").GetString(), file.Header.Pk.KitId);
        Assert.Equal(x.GetProperty("generation").GetUInt64(), file.Generation);
        Assert.Equal(x.GetProperty("dateigroesse").GetInt32(), fileSize);
        Assert.Equal(x.GetProperty("kdf").GetProperty("memLimitBytes").GetUInt64(), file.Header.Kdf.MemLimitBytes);
        Assert.Equal(x.GetProperty("kdf").GetProperty("opsLimit").GetUInt32(), file.Header.Kdf.OpsLimit);
        Assert.Equal(x.GetProperty("factorMask").GetInt32(), (int)file.Header.Factors);
        Assert.Equal(x.GetProperty("recoveryScheme").GetInt32(), (int)file.Header.RecoveryScheme);
        Assert.Equal(x.GetProperty("notfallkitBestaetigt").GetBoolean(), content.RecoveryConfirmedAt is not null);
        var expected = x.GetProperty("eintraege").EnumerateArray().ToList();
        Assert.Equal(expected.Count, content.Entries.Count);
        foreach (var e in expected)
        {
            var title = e.GetProperty("title").GetString();
            var found = Assert.Single(content.Entries, v => v.Title == title);
            Assert.Equal(e.GetProperty("username").GetString(), found.Username);
            Assert.Equal(e.GetProperty("password").GetString(), found.Password);
            Assert.Equal(e.GetProperty("url").GetString(), found.Url);
            if (e.TryGetProperty("notes", out var notes)) { Assert.Equal(notes.GetString(), found.Notes); }
            if (e.TryGetProperty("notesEnthaelt", out var parts))
            {
                foreach (var p in parts.EnumerateArray()) { Assert.Contains(p.GetString()!, found.Notes, StringComparison.Ordinal); }
            }
            if (e.TryGetProperty("totp", out var totp)) { Assert.Equal(totp.GetString(), found.Totp); }
            Assert.Equal(e.GetProperty("verlauf").EnumerateArray().Select(v => v.GetString()), found.History.Select(h => h.Password));
            Assert.False(found.SecretsSealed);
            Assert.Equal(EntryProtection.Normal, found.Protection);
        }
    }

    /// <summary>Notiz des dritten Eintrags genau (Fixtures-Test der Mac-Seite).</summary>
    internal const string Notiz3 = "Zeilen\nmit Umlauten: äöü, Zeichen: «» – Ende";
}

/// <summary>Vergleicht zwei JSON-Texte rekursiv: gleiche Schlüsselreihenfolge, Werte bytegleich (Rohtext); zusätzliche
/// Schlüssel im neuen Text nur aus <c>meta</c>, <c>sealed</c>, <c>entryKey</c>, <c>recoveryGroups</c> mit null bzw. [].</summary>
internal static class JsonVergleich
{
    private static readonly HashSet<string> Neu = ["meta", "sealed", "entryKey", "recoveryGroups"];

    internal static void AssertGleichBisAufNeueNullFelder(string alt, string neu)
    {
        using var a = JsonDocument.Parse(alt);
        using var b = JsonDocument.Parse(neu);
        Vergleiche(a.RootElement, b.RootElement, "$");
    }

    private static void Vergleiche(JsonElement a, JsonElement b, string pfad)
    {
        Assert.Equal(a.ValueKind, b.ValueKind);
        switch (a.ValueKind)
        {
            case JsonValueKind.Object:
                var ka = a.EnumerateObject().ToList();
                var kb = b.EnumerateObject().Where(p => !(Neu.Contains(p.Name) && !a.TryGetProperty(p.Name, out _)
                    && (p.Value.ValueKind == JsonValueKind.Null
                        || (p.Value.ValueKind == JsonValueKind.Array && p.Value.GetArrayLength() == 0)))).ToList();
                Assert.Equal(ka.Select(p => p.Name), kb.Select(p => p.Name));
                for (var i = 0; i < ka.Count; i++) { Vergleiche(ka[i].Value, kb[i].Value, pfad + "." + ka[i].Name); }
                break;
            case JsonValueKind.Array:
                var ea = a.EnumerateArray().ToList();
                var eb = b.EnumerateArray().ToList();
                Assert.Equal(ea.Count, eb.Count);
                for (var i = 0; i < ea.Count; i++) { Vergleiche(ea[i], eb[i], pfad + "[" + i + "]"); }
                break;
            default:
                Assert.Equal(a.GetRawText(), b.GetRawText());
                break;
        }
    }
}

/// <summary>
/// (b)/(d) Die Mac-Beispieldateien mit echtem Argon2 (256 MiB, t = 3), seriell. Beide Wege (Passwort mit Faktoren,
/// Notfallcode bzw. zwei Teile); Inhalt gegen referenz/erwartet_v*.json; JSON bytegleich neu kodiert.
/// </summary>
[Collection("EchteProfile")]
public class BeispielDateiTests
{
    [Fact]
    public void V1_oeffnet_ueber_das_Master_Passwort()
    {
        var bytes = Fixtures.MacBytes("v1_beispiel.siegel");
        Assert.Equal("ee16046c2a50bd47250a276d62f5aa63e60f9aee231da379d9ad44904b43aa13",
            KT.Hex(System.Security.Cryptography.SHA256.HashData(bytes)));
        var file = VaultFile.Parse(bytes);
        using var pw = PasswordNormalizer.SecureBytes(BeispielDateien.V1Password);
        using var opened = VaultCrypto.OpenWithPassword(file, pw, null, KdfLimits.Production);
        BeispielDateien.CheckAgainstReference("erwartet_v1_beispiel.json", file, opened.Content, bytes.Length);
        Assert.Equal(BeispielDateien.Notiz3, opened.Content.Entries.Single(e => e.Title == "Notiz ohne Website").Notes);
        // v1 über den Passwortweg liefert den Migrations-KEK (gleiches Salz, Maske 0) für ein späteres v2-Speichern.
        Assert.NotNull(opened.MigrationKek);
        Assert.Equal(SecurityLevel.Standard, opened.Content.Level);
        Assert.Null(opened.Content.EntryKey);
    }

    [Fact]
    public void V1_oeffnet_ueber_den_Notfallcode()
    {
        var bytes = Fixtures.MacBytes("v1_beispiel.siegel");
        var file = VaultFile.Parse(bytes);
        var symbols = RecoveryCodeCodec.ParseSymbols(BeispielDateien.V1Code, allowUnknown: true);
        Assert.Equal(RecoveryCodeMatch.Exact, RecoveryMatching.MatchRecoveryCode(symbols, file.Header));
        using var r = RecoveryCodeCodec.Decode(BeispielDateien.V1Code);
        using var opened = VaultCrypto.OpenWithRecovery(file, r);
        BeispielDateien.CheckAgainstReference("erwartet_v1_beispiel.json", file, opened.Content, bytes.Length);
    }

    [Fact]
    public void V1_falsches_Passwort_und_KDF_Fehler_unterscheiden_sich()
    {
        var file = VaultFile.Parse(Fixtures.MacBytes("v1_beispiel.siegel"));
        using var wrong = PasswordNormalizer.SecureBytes(KT.Pw1);
        KT.Throws(SiegelErrorCode.WrongPassword, () => VaultCrypto.OpenWithPassword(file, wrong, null, KdfLimits.Production));
        using var right = PasswordNormalizer.SecureBytes(BeispielDateien.V1Password);
        TestHooks.ForceKdfFailure = true;
        try
        {
            KT.Throws(SiegelErrorCode.KdfFailed, () => VaultCrypto.OpenWithPassword(file, right, null, KdfLimits.Production));
        }
        finally
        {
            TestHooks.ForceKdfFailure = false;
        }
    }

    [Fact]
    public void V2_oeffnet_ueber_Passwort_und_alle_drei_Faktoren()
    {
        var bytes = Fixtures.MacBytes("v2_beispiel.siegel");
        var file = VaultFile.Parse(bytes);
        using var pw = PasswordNormalizer.SecureBytes(BeispielDateien.V2Password);
        // KAT: echtes Argon2 ergibt das festgehaltene p
        using (var p = Kdf.DeriveKek(pw, file.Header.Salt, file.Header.Kdf, KdfLimits.Production))
        {
            Assert.Equal("0aba515de29ce382121b9355eb693daebc778d6378affdf4719f2c25f618b2d0", p.HexForTesting());
        }
        var factors = BeispielDateien.V2Factors();
        using var opened = VaultCrypto.OpenWithPassword(file, pw, factors, KdfLimits.Production);
        BeispielDateien.CheckAgainstReference("erwartet_v2_beispiel.json", file, opened.Content, bytes.Length);
        Assert.Equal(BeispielDateien.Notiz3, opened.Content.Entries.Single(e => e.Title == "Notiz ohne Website").Notes);
        Assert.Equal(SecurityLevel.Festung, opened.Content.Level);
        Assert.Null(opened.MigrationKek);
        // Die Datei stammt aus Stufe A des Mac-Kerns: noch ohne Grundschlüssel, meta und sealed.
        Assert.Null(opened.Content.EntryKey);
        Assert.Empty(opened.Content.Meta);
    }

    [Fact]
    public void V2_falscher_Faktor_oder_falsches_Passwort_ist_WrongPassword()
    {
        var file = VaultFile.Parse(Fixtures.MacBytes("v2_beispiel.siegel"));
        using var pw = PasswordNormalizer.SecureBytes(BeispielDateien.V2Password);
        var wrongSe = BeispielDateien.V2Factors();
        wrongSe.SecureEnclave = KT.Factor(0x12);
        KT.Throws(SiegelErrorCode.WrongPassword, () => VaultCrypto.OpenWithPassword(file, pw, wrongSe, KdfLimits.Production));
        var wrongKey = BeispielDateien.V2Factors();
        wrongKey.SecurityKey = KT.Factor(0x34);
        // Gleiches Salz und gleiche Parameter: der Cache spart das zweite Argon2.
        using var cache = new KekCache();
        KT.Throws(SiegelErrorCode.WrongPassword, () => VaultCrypto.OpenWithPassword(file, pw, wrongKey, KdfLimits.Production, cache));
        using var other = PasswordNormalizer.SecureBytes(KT.Pw1);
        KT.Throws(SiegelErrorCode.WrongPassword,
            () => VaultCrypto.OpenWithPassword(file, other, BeispielDateien.V2Factors(), KdfLimits.Production));
    }

    [Fact]
    public void V2_oeffnet_ueber_je_zwei_Teile_alle_Paare_beide_Reihenfolgen()
    {
        var bytes = Fixtures.MacBytes("v2_beispiel.siegel");
        var file = VaultFile.Parse(bytes);
        foreach (var (a, b) in new[] { (0, 1), (0, 2), (1, 2) })
        {
            foreach (var pair in new[] { (a, b), (b, a) })
            {
                var inputs = RecoveryMatching.ParseShareInputs([BeispielDateien.V2Shares[pair.Item1], BeispielDateien.V2Shares[pair.Item2]]);
                Assert.Equal([RecoveryCodeMatch.Exact, RecoveryCodeMatch.Exact], RecoveryMatching.MatchRecoveryShares(inputs, file.Header));
                using var r = RecoveryMatching.CombineShares([BeispielDateien.V2Shares[pair.Item1], BeispielDateien.V2Shares[pair.Item2]]);
                using var opened = VaultCrypto.OpenWithRecovery(file, r);
                BeispielDateien.CheckAgainstReference("erwartet_v2_beispiel.json", file, opened.Content, bytes.Length);
            }
        }
    }

    [Fact]
    public void Inhalt_der_Mac_Dateien_wird_bytegleich_neu_kodiert()
    {
        // Der stärkste Beleg für „gleiches JSON“: Swift-Klartext entschlüsseln, mit C# neu kodieren, vergleichen.
        foreach (var (name, code, isShares) in new[] { ("v1_beispiel.siegel", BeispielDateien.V1Code, false),
                     ("v2_beispiel.siegel", "", true) })
        {
            var file = VaultFile.Parse(Fixtures.MacBytes(name));
            using var r = isShares ? RecoveryMatching.CombineShares([BeispielDateien.V2Shares[0], BeispielDateien.V2Shares[1]])
                : RecoveryCodeCodec.Decode(code);
            using var kek = RecoveryKem.Decapsulate(r, file.Header.VaultId, file.Header.Pk, file.Slots.CtM, file.Slots.CtX,
                file.Header.Labels.HybridKem);
            using var dek = Aead.Unwrap(kek, file.Slots.RecSlot, VaultSlots.RecAd(file.Header))!;
            using var padded = Aead.Open(dek, file.Nonce, file.Ciphertext, file.PayloadAd)!;
            var swiftJson = PayloadCodec.JsonStringForTesting(padded)!;
            var (content, digest) = PayloadCodec.Decode(padded);
            using (content)
            {
                var (again, digest2) = PayloadCodec.Encode(content, legacyV1: file.Header.FormatVersion == 1);
                using (again)
                {
                    var csJson = PayloadCodec.JsonStringForTesting(again)!;
                    if (file.Header.FormatVersion == 1)
                    {
                        Assert.Equal(swiftJson, csJson);
                        Assert.Equal(digest, digest2);
                        Assert.Equal(padded.Length, again.Length);
                    }
                    else
                    {
                        // Stufe-A-Inhalt: heute kommen nur Felder mit null bzw. [] dazu, alles andere bytegleich.
                        JsonVergleich.AssertGleichBisAufNeueNullFelder(swiftJson, csJson);
                    }
                }
            }
            Assert.Contains("\\/", swiftJson, StringComparison.Ordinal);
            Assert.Equal(swiftJson, Encoding.UTF8.GetString(Encoding.UTF8.GetBytes(swiftJson)));
        }
    }
}
#endif
