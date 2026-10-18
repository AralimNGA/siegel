using System.Text;
using Siegel.Modell;

namespace Siegel.Werkzeuge.Tests;

internal static class TotpHilfe
{
    /// <summary>Erwartet <see cref="SiegelErrorCode.TotpInvalid"/> mit genau diesem Code.</summary>
    internal static void Invalid(string code, Action action)
    {
        var e = Assert.Throws<SiegelException>(action);
        Assert.Equal(SiegelErrorCode.TotpInvalid, e.Code);
        Assert.Equal(code, e.Detail);
    }

    internal static TotpParameters MitLabel(TotpParameters p, string issuer, string account)
    {
        byte[] kopie;
        using (var l = p.LeiheSchluessel()) { kopie = l.Span.ToArray(); }
        try
        {
            return new(kopie, p.Algorithm, p.Digits, p.Period, issuer, account);
        }
        finally
        {
            Array.Clear(kopie);
        }
    }

    /// <summary>HOTP mit dem Geheimnis aus <paramref name="p"/> (über eine Leihe).</summary>
    internal static string Hotp(TotpParameters p, ulong counter, int digits, TotpAlgorithm algorithm)
    {
        using var l = p.LeiheSchluessel();
        return Totp.Hotp(l.Span, counter, digits, algorithm);
    }

    internal const string SeedSha1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    internal const string SeedSha256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA====";
    internal static readonly string SeedSha512 = string.Concat(Enumerable.Repeat("GEZDGNBVGY3TQOJQ", 6)) + "GEZDGNA=";

    internal static string Uri(string seed, string algorithm) =>
        $"otpauth://totp/RFC6238:test?secret={seed}&algorithm={algorithm}&digits=8&period=30";
}

/// <summary>TOTP-Testvektoren aus RFC 6238 Anhang B und RFC 4226 Anhang D (TOTPTests.swift).</summary>
public class TotpVectorTests
{
    public static TheoryData<long, string, string, string> Vectors => new()
    {
        { 59, "94287082", "46119246", "90693936" },
        { 1_111_111_109, "07081804", "68084774", "25091201" },
        { 1_111_111_111, "14050471", "67062674", "99943326" },
        { 1_234_567_890, "89005924", "91819424", "93441116" },
        { 2_000_000_000, "69279037", "90698825", "38618901" },
        { 20_000_000_000, "65353130", "77737706", "47863826" },
    };

    [Theory]
    [MemberData(nameof(Vectors))]
    public void Rfc6238(long time, string expected1, string expected256, string expected512)
    {
        using var sha1 = Totp.Parse(TotpHilfe.Uri(TotpHilfe.SeedSha1, "SHA1"));
        using var sha256 = Totp.Parse(TotpHilfe.Uri(TotpHilfe.SeedSha256, "SHA256"));
        using var sha512 = Totp.Parse(TotpHilfe.Uri(TotpHilfe.SeedSha512, "SHA512"));
        Assert.Equal(TotpAlgorithm.Sha1, sha1.Algorithm);
        Assert.Equal(TotpAlgorithm.Sha256, sha256.Algorithm);
        Assert.Equal(TotpAlgorithm.Sha512, sha512.Algorithm);
        Assert.Equal(20, sha1.SecretByteCount);
        Assert.Equal(32, sha256.SecretByteCount);
        Assert.Equal(64, sha512.SecretByteCount);
        var date = DateTimeOffset.FromUnixTimeSeconds(time);
        Assert.Equal((expected1, (int)(30 - time % 30)), Totp.Code(sha1, date));
        Assert.Equal(expected256, Totp.Code(sha256, date).Code);
        Assert.Equal(expected512, Totp.Code(sha512, date).Code);
    }

    [Fact]
    public void Rfc4226()
    {
        string[] expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
        using var p = Totp.Parse(TotpHilfe.SeedSha1);
        for (var counter = 0; counter < expected.Length; counter++)
        {
            Assert.Equal(expected[counter], TotpHilfe.Hotp(p, (ulong)counter, 6, TotpAlgorithm.Sha1));
        }
    }

    [Fact]
    public void RestsekundenUndPeriodengrenzen()
    {
        using var p = Totp.Parse($"otpauth://totp/x?secret={TotpHilfe.SeedSha1}&period=60");
        Assert.Equal(60, Totp.Code(p, DateTimeOffset.FromUnixTimeSeconds(120)).Remaining);
        Assert.Equal(1, Totp.Code(p, DateTimeOffset.FromUnixTimeMilliseconds(179_900)).Remaining);
        Assert.Equal(Totp.Code(p, DateTimeOffset.FromUnixTimeSeconds(120)).Code, Totp.Code(p, DateTimeOffset.FromUnixTimeSeconds(179)).Code);
        var zero = TotpHilfe.Hotp(p, 0, 6, TotpAlgorithm.Sha1);
        Assert.Equal(zero, Totp.Code(p, DateTimeOffset.FromUnixTimeSeconds(-5000)).Code);
        Assert.Equal(zero, Totp.Code(p, DateTimeOffset.MinValue).Code);
        for (var t = 0.0; t < 200; t += 7.3)
        {
            Assert.InRange(Totp.Code(p, DateTimeOffset.FromUnixTimeMilliseconds((long)(t * 1000))).Remaining, 1, 60);
        }
        // Nicht 1970-basiert: eine DateTimeOffset mit Zeitzone ergibt denselben Zähler
        var lokal = new DateTimeOffset(2026, 10, 18, 12, 0, 0, TimeSpan.FromHours(2));
        Assert.Equal(Totp.Code(p, lokal.ToUniversalTime()), Totp.Code(p, lokal));
    }

    [Fact]
    public void SechsZiffernMitFuehrendenNullen()
    {
        using var p = Totp.Parse($"otpauth://totp/x?secret={TotpHilfe.SeedSha1}");
        Assert.Equal(6, p.Digits);
        Assert.Equal("081804", Totp.Code(p, DateTimeOffset.FromUnixTimeSeconds(1_111_111_109)).Code);
    }
}

/// <summary>Base32 und otpauth-Parser (TOTPTests.swift).</summary>
public class TotpParserTests
{
    [Fact]
    public void Base32Tolerant()
    {
        using var reference = Totp.Parse("JBSWY3DPEHPK3PXP");
        Assert.Equal(10, reference.SecretByteCount);
        Assert.Equal(TotpAlgorithm.Sha1, reference.Algorithm);
        Assert.Equal(6, reference.Digits);
        Assert.Equal(30, reference.Period);
        foreach (var variant in new[] { "jbswy3dpehpk3pxp", "JBSW Y3DP EHPK 3PXP", "  jbsw y3dp\tehpk 3pxp \n", "JbSwY3dPeHpK3pXp" })
        {
            using var v = Totp.Parse(variant);
            Assert.Equal(reference, v);
        }
        using var padded = Totp.Parse("AAAQEAYEAUDAOCAJBI======");
        using var unpadded = Totp.Parse("aaaqeayeaudaocajbi");
        Assert.Equal(padded, unpadded);
        Assert.Equal(11, padded.SecretByteCount);
        using var mit = Totp.Parse(TotpHilfe.Uri(TotpHilfe.SeedSha256, "SHA256"));
        using var ohne = Totp.Parse(TotpHilfe.Uri(TotpHilfe.SeedSha256[..^4], "SHA256"));
        Assert.Equal(mit, ohne);
    }

    [Fact]
    public void Base32StrengWoNoetig()
    {
        foreach (var bad in new[] { "JBSWY3DPEHPK3PX1", "JBSWY3DPEHPK3PX8", "JBSWY3DP=EHPK3PXP", "AAAQEAYEAUDAOCAJBI===",
                     "JBSWY3DPEHPK3PXP========", "JBSWY3DPEHPK3PXPA", "JBSWY3DPEHPK3PXPAAA", "JBSWY3DP-EHPK3PXP", "JBSWY3DPEHPK3PXPÄ" })
        {
            TotpHilfe.Invalid("totp.base32", () => Totp.Parse(bad));
        }
    }

    [Fact]
    public void GeheimnisLaenge()
    {
        TotpHilfe.Invalid("totp.secret.length", () => Totp.Parse("JBSWY3DP"));
        TotpHilfe.Invalid("totp.secret.length", () => Totp.Parse("JBSWY3DPEHPK3PY"));
        using (var maximum = Totp.Parse(new string('A', 128 * 8 / 5))) { Assert.Equal(127, maximum.SecretByteCount); }
        var tooLong = string.Concat(Enumerable.Repeat("AAAAAAAA", 25)) + "AAAAAAA";
        TotpHilfe.Invalid("totp.secret.length", () => Totp.Parse(tooLong));
        TotpHilfe.Invalid("totp.secret.length", () => _ = new TotpParameters(new byte[9]));
        TotpHilfe.Invalid("totp.secret.length", () => _ = new TotpParameters(new byte[129]));
        using var p = new TotpParameters(new byte[128]);
        Assert.Equal(128, p.SecretByteCount);
    }

    [Fact]
    public void GoogleBeispiel()
    {
        using var p = Totp.Parse("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example");
        Assert.Equal("Example", p.Issuer);
        Assert.Equal("alice@google.com", p.Account);
        Assert.Equal(TotpAlgorithm.Sha1, p.Algorithm);
        Assert.Equal(6, p.Digits);
        Assert.Equal(30, p.Period);
        using (var basis = Totp.Parse("JBSWY3DPEHPK3PXP"))
        using (var gleich = TotpHilfe.MitLabel(basis, "Example", "alice@google.com"))
        {
            Assert.Equal(gleich, p);
        }

        using var q = Totp.Parse("OTPAUTH://TOTP/ACME%20Co:%20john.doe@email.com?SECRET=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ"
            + "&Issuer=ACME%20Co&algorithm=sha256&digits=8&period=60&image=https%3A%2F%2Fx.example%2Fa.png");
        Assert.Equal("ACME Co", q.Issuer);
        Assert.Equal("john.doe@email.com", q.Account);
        Assert.Equal(TotpAlgorithm.Sha256, q.Algorithm);
        Assert.Equal(8, q.Digits);
        Assert.Equal(60, q.Period);

        using (var a = Totp.Parse("otpauth://totp/anna?secret=JBSWY3DPEHPK3PXP")) { Assert.Equal("anna", a.Account); }
        using (var b = Totp.Parse("otpauth://totp?secret=JBSWY3DPEHPK3PXP")) { Assert.Equal("", b.Account); }
        using (var r = Totp.Parse("otpauth://totp/Alt:anna?secret=JBSWY3DPEHPK3PXP&issuer=Neu"))
        {
            Assert.Equal("Neu", r.Issuer);
            Assert.Equal("anna", r.Account);
        }
        using var s = Totp.Parse("otpauth://totp/Mein Dienst:a+b?secret=JBSW%20Y3DP%20EHPK%203PXP");
        Assert.Equal("Mein Dienst", s.Issuer);
        Assert.Equal("a+b", s.Account);
        using var basis2 = Totp.Parse("JBSWY3DPEHPK3PXP");
        using var gleich2 = TotpHilfe.MitLabel(basis2, "Mein Dienst", "a+b");
        Assert.Equal(gleich2, s);
    }

    [Fact]
    public void ZiffernPeriodeAlgorithmen()
    {
        const string basis = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";
        using (var p = Totp.Parse(basis + "&digits=8")) { Assert.Equal(8, p.Digits); }
        using (var p = Totp.Parse(basis + "&digits=06")) { Assert.Equal(6, p.Digits); }
        foreach (var bad in new[] { "7", "5", "9", "10", "", "6a", "-6", "+6", "6.0", "0006" })
        {
            TotpHilfe.Invalid("totp.digits", () => Totp.Parse(basis + "&digits=" + bad));
        }
        using (var p = Totp.Parse(basis + "&period=15")) { Assert.Equal(15, p.Period); }
        using (var p = Totp.Parse(basis + "&period=120")) { Assert.Equal(120, p.Period); }
        foreach (var bad in new[] { "14", "121", "0", "", "30s", "1000", "-30" })
        {
            TotpHilfe.Invalid("totp.period", () => Totp.Parse(basis + "&period=" + bad));
        }
        foreach (var bad in new[] { "MD5", "SHA-1", "SHA384", "", "sha3" })
        {
            TotpHilfe.Invalid("totp.algorithm", () => Totp.Parse(basis + "&algorithm=" + bad));
        }
        TotpHilfe.Invalid("totp.digits", () => _ = new TotpParameters(new byte[10], Digits: 7));
        TotpHilfe.Invalid("totp.period", () => _ = new TotpParameters(new byte[10], Period: 10));
    }

    [Fact]
    public void StrengerUriParserFehlercodes()
    {
        TotpHilfe.Invalid("totp.empty", () => Totp.Parse(""));
        TotpHilfe.Invalid("totp.empty", () => Totp.Parse(" \n\t "));
        TotpHilfe.Invalid("totp.tooLong", () => Totp.Parse(new string('A', 2049)));
        TotpHilfe.Invalid("totp.type", () => Totp.Parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1"));
        TotpHilfe.Invalid("totp.type", () => Totp.Parse("otpauth://steam/x?secret=JBSWY3DPEHPK3PXP"));
        TotpHilfe.Invalid("totp.secret.missing", () => Totp.Parse("otpauth://totp/x?issuer=A"));
        TotpHilfe.Invalid("totp.secret.missing", () => Totp.Parse("otpauth://totp/x?secret="));
        TotpHilfe.Invalid("totp.secret.missing", () => Totp.Parse("otpauth://totp/x"));
        TotpHilfe.Invalid("totp.duplicate", () => Totp.Parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&secret=GEZDGNBVGY3TQOJQ"));
        TotpHilfe.Invalid("totp.duplicate", () => Totp.Parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=6&DIGITS=8"));
        TotpHilfe.Invalid("totp.uri", () => Totp.Parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP#frag"));
        TotpHilfe.Invalid("totp.uri", () => Totp.Parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&lock"));
        TotpHilfe.Invalid("totp.uri", () => Totp.Parse("otpauth://totp/x%G1?secret=JBSWY3DPEHPK3PXP"));
        TotpHilfe.Invalid("totp.uri", () => Totp.Parse("otpauth://totp/x%4?secret=JBSWY3DPEHPK3PXP"));
        TotpHilfe.Invalid("totp.uri", () => Totp.Parse("otpauth://totp/%FF%FE?secret=JBSWY3DPEHPK3PXP"));
        TotpHilfe.Invalid("totp.uri", () => Totp.Parse("otpauth-migration://offline?data=CjEKCkhlbGxv"));
        TotpHilfe.Invalid("totp.uri", () => Totp.Parse("https://example.com/?secret=JBSWY3DPEHPK3PXP"));
        var many = string.Join("&", Enumerable.Range(0, 33).Select(i => $"x{i}=1"));
        TotpHilfe.Invalid("totp.uri", () => Totp.Parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&" + many));
        var longIssuer = new string('a', 257);
        TotpHilfe.Invalid("totp.label", () => Totp.Parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=" + longIssuer));
        TotpHilfe.Invalid("totp.label", () => Totp.Parse($"otpauth://totp/a:{longIssuer}?secret=JBSWY3DPEHPK3PXP"));
    }

    [Fact]
    public void SteuerUndRichtungszeichenEntfernt()
    {
        using var p = Totp.Parse("otpauth://totp/Bank%E2%80%AEevil:an%00na?secret=JBSWY3DPEHPK3PXP");
        Assert.Equal("Bankevil", p.Issuer);
        Assert.Equal("anna", p.Account);
    }

    [Fact]
    public void AlleCodesStehenInDerFestenListe()
    {
        Assert.Equal(Totp.ReasonCodes.Length, Totp.ReasonCodes.Distinct(StringComparer.Ordinal).Count());
        string[] inputs = ["", new string('A', 3000), "otpauth://hotp/x", "otpauth://totp/x", "JBSWY3DP1", "JBSWY3DP",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=x", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=7",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=1", "otpauth://totp/x?secret=A&secret=B", "otpauth://totp/x#",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&issuer=" + new string('b', 300)];
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var input in inputs)
        {
            var e = Assert.Throws<SiegelException>(() => Totp.Parse(input));
            Assert.Equal(SiegelErrorCode.TotpInvalid, e.Code);
            Assert.Contains(e.Detail, Totp.ReasonCodes);
            seen.Add(e.Detail);
        }
        Assert.Equal(12, seen.Count);
    }

    [Fact]
    public void ZufallseingabenNurFesteCodes()
    {
        var alphabet = "otpauth:/?&=%#ABCDEFGHIJKLMNOPQRSTUVWXYZ234567abcdefghijklmnopqrstuvwxyz0189 -+.\u0000\u202Eé".ToCharArray();
        var random = new Random(4711);
        for (var i = 0; i < 3000; i++)
        {
            var text = new StringBuilder(random.Next(2) == 0 ? "otpauth://totp/" : "");
            var length = random.Next(0, 81);
            for (var k = 0; k < length; k++) { text.Append(alphabet[random.Next(alphabet.Length)]); }
            try
            {
                using var p = Totp.Parse(text.ToString());
                Assert.True(p.Digits is 6 or 8);
                Assert.InRange(p.Period, 15, 120);
                Assert.InRange(p.SecretByteCount, 10, 128);
            }
            catch (SiegelException e)
            {
                Assert.Equal(SiegelErrorCode.TotpInvalid, e.Code);
                Assert.Contains(e.Detail, Totp.ReasonCodes);
            }
        }
    }

    [Fact]
    public void GleichheitUndSchwaerzung()
    {
        using var a = Totp.Parse("JBSWY3DPEHPK3PXP");
        using var b = Totp.Parse("GEZDGNBVGY3TQOJQ");
        Assert.NotEqual(a, b);
        using var c = new TotpParameters([0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF]);
        Assert.Equal(a, c);
        Assert.Equal(a.GetHashCode(), c.GetHashCode());
        using var p = Totp.Parse("otpauth://totp/Geheimdienst:anna?secret=JBSWY3DPEHPK3PXP");
        var text = p.ToString();
        Assert.DoesNotContain("JBSWY3DP", text, StringComparison.Ordinal);
        Assert.DoesNotContain("Hello", text, StringComparison.Ordinal);
        Assert.DoesNotContain("anna", text, StringComparison.Ordinal);
        Assert.DoesNotContain("Geheimdienst", text, StringComparison.Ordinal);
        // Das Geheimnis verlässt das Objekt nicht (keine öffentliche Eigenschaft, hygiene-4); Neubau über die Leihe
        using var ohneLabel = TotpHilfe.MitLabel(p, "", "");
        Assert.Equal(a, ohneLabel);
    }

    [Fact]
    public void KopieMitWithHatEigenesGeheimnis()
    {
        var original = Totp.Parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8");
        using var kopie = original with { };
        var erwartet = Totp.Code(original, DateTimeOffset.FromUnixTimeSeconds(59));
        original.Dispose();
        Assert.Equal(erwartet, Totp.Code(kopie, DateTimeOffset.FromUnixTimeSeconds(59)));
    }

    [Fact]
    public void FreigegebeneParameterWerfenFestenCode()
    {
        var p = Totp.Parse("JBSWY3DPEHPK3PXP");
        p.Dispose();
        var e = Assert.Throws<SiegelException>(() => Totp.Code(p, DateTimeOffset.UnixEpoch));
        Assert.Equal("secure.disposed", e.Detail);
    }
}
