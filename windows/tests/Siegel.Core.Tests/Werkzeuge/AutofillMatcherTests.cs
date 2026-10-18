using System.Text;

namespace Siegel.Werkzeuge.Tests;

/// <summary>AutofillMatcher (SPEC §20; Port von AutofillMatcherTests.swift): Host oder Unterdomain, öffentliche
/// Suffixe, http nie für https, Ports und Phishing-Beispiele, die nie treffen dürfen.</summary>
public class AutofillTrefferTests
{
    private static bool Match(string entry, string service) => AutofillMatcher.Matches(entry, service);

    [Fact]
    public void GleicherHostUndUnterdomains()
    {
        Assert.True(Match("https://example.com", "https://example.com"));
        Assert.True(Match("https://example.com/login", "https://example.com/other?x=1"));
        Assert.True(Match("https://example.com", "https://login.example.com/"));
        Assert.True(Match("https://example.com", "https://a.b.c.example.com"));
        Assert.True(Match("https://example.com", "https://www.example.com"));
        Assert.True(Match("https://Example.COM", "https://EXAMPLE.com."));
        Assert.True(Match("velo.example.ch", "https://velo.example.ch/anmelden"));
        Assert.True(Match("https://example.com", "example.com"));
        Assert.True(Match("https://user:pw@example.com", "https://example.com"));
    }

    [Fact]
    public void Idna()
    {
        Assert.True(Match("https://bücher.de", "https://xn--bcher-kva.de/login"));
        Assert.True(Match("https://xn--bcher-kva.de", "https://www.bücher.de"));
        Assert.True(Match("https://straße.de", "https://xn--strae-oqa.de"));
    }

    [Fact]
    public void Schema()
    {
        Assert.True(Match("http://intranet.example.ch", "https://intranet.example.ch"));
        Assert.True(Match("http://intranet.example.ch", "http://intranet.example.ch"));
        Assert.False(Match("https://bank.example.ch", "http://bank.example.ch"));
        Assert.False(Match("bank.example.ch", "http://bank.example.ch"));
        Assert.False(Match("https://bank.example.ch", "ftp://bank.example.ch"));
        Assert.False(Match("ftp://bank.example.ch", "https://bank.example.ch"));
        Assert.False(Match("android://abc==@com.example.app/", "https://com.example.app"));
        Assert.False(Match("javascript:alert(1)", "https://example.com"));
    }

    [Fact]
    public void Ports()
    {
        Assert.True(Match("https://nas.example.ch:5001", "https://nas.example.ch:5001/"));
        Assert.False(Match("https://nas.example.ch:5001", "https://nas.example.ch"));
        Assert.False(Match("https://nas.example.ch:5001", "https://nas.example.ch:5002"));
        Assert.False(Match("https://nas.example.ch", "https://nas.example.ch:8443"));
        Assert.True(Match("https://nas.example.ch", "https://nas.example.ch:443"));
        Assert.True(Match("https://nas.example.ch:443", "https://nas.example.ch"));
        Assert.True(Match("http://router.example.ch", "https://router.example.ch"));
        Assert.False(Match("http://router.example.ch:8080", "https://router.example.ch:8443"));
        Assert.False(Match("https://x.example.ch:0", "https://x.example.ch"));
        Assert.False(Match("https://x.example.ch", "https://x.example.ch:70000"));
    }

    [Fact]
    public void IpUndEinteilig()
    {
        Assert.True(Match("https://192.168.1.1", "https://192.168.1.1/admin"));
        Assert.False(Match("https://192.168.1.1", "https://10.192.168.1.1"));
        Assert.False(Match("https://1.1", "https://evil.1.1"));
        Assert.True(Match("https://[fd00::1]:8443", "https://[fd00::1]:8443"));
        Assert.False(Match("https://[fd00::1]", "https://[fd00::2]"));
        Assert.True(Match("http://localhost:8080", "http://localhost:8080"));
        Assert.False(Match("http://localhost", "http://evil.localhost"));
        Assert.False(Match("https://ch", "https://bank.ch"));
    }
}

public class AutofillPhishingTests
{
    private static bool Match(string entry, string service) => AutofillMatcher.Matches(entry, service);

    [Fact]
    public void PhishingBeispieleTreffenNie()
    {
        const string bank = "https://beispiel-bank.example";
        foreach (var service in new[]
        {
            "https://beispiel-bank.example.evil.com", "https://beispiel-bank.example.evil.com/login",
            "https://evil-beispiel-bank.example", "https://beispielbank.example", "https://beispiel-bank.examp1e",
            "https://beispiel-bank.example@evil.com", "https://evil.com/beispiel-bank.example",
            "https://evil.com?beispiel-bank.example", "https://evil.com#beispiel-bank.example",
            "https://evil.com\\@beispiel-bank.example", "https://beispiel-bank.example%2F@evil.com", "https://example",
            "https://xn--beispiel-bnk-ndb.example",
        })
        {
            Assert.False(Match(bank, service), $"darf nicht treffen: {service}");
        }
        Assert.False(Match("https://paypal.com", "https://paypal.com.evil.com"));
        Assert.False(Match("https://paypal.com", "https://evilpaypal.com"));
        Assert.False(Match("https://paypal.com", "https://paypal.co"));
        Assert.False(Match("https://login.paypal.com", "https://paypal.com"));
        Assert.False(Match("https://login.paypal.com", "https://www.paypal.com"));
    }

    [Fact]
    public void PunycodeDoppelgaenger()
    {
        Assert.False(Match("https://apple.com", "https://аррӏе.com"));
        Assert.False(Match("https://apple.com", "https://xn--80ak6aa92e.com"));
        Assert.False(Match("https://аррӏе.com", "https://apple.com"));
        Assert.False(Match("https://paypal.com", "https://pаypal.com"));
        Assert.False(Match("https://google.com", "https://gοοgle.com"));
        Assert.True(Match("https://аррӏе.com", "https://xn--80ak6aa92e.com"));
        Assert.True(Match("https://example.com", "https://ｅｘａｍｐｌｅ.com"));
    }

    [Fact]
    public void OeffentlicheSuffixe()
    {
        Assert.False(Match("https://co.uk", "https://bank.co.uk"));
        Assert.False(Match("https://com.au", "https://bank.com.au"));
        Assert.False(Match("https://github.io", "https://evil.github.io"));
        Assert.True(Match("https://github.io", "https://github.io"));
        Assert.True(Match("https://alice.github.io", "https://alice.github.io/projekt"));
        Assert.True(Match("https://alice.github.io", "https://docs.alice.github.io"));
        Assert.False(Match("https://alice.github.io", "https://bob.github.io"));
        Assert.True(Match("https://bank.co.uk", "https://secure.bank.co.uk"));
        Assert.False(Match("https://bank.co.uk", "https://evil.co.uk"));
        Assert.False(Match("https://ch", "https://admin.ch"));
        Assert.All(AutofillMatcher.PublicSuffixes, s =>
        {
            Assert.Contains('.', s);
            Assert.Equal(s.ToLowerInvariant(), s);
        });
    }

    [Fact]
    public void UngueltigeEingabenTreffenNie()
    {
        foreach (var bad in new[] { "", "   ", "https://", "https:///pfad", "https://exa mple.com", "https://a..example.com",
                     "https://.example.com", "https://example.com\u0000", "https://exa\u202Emple.com", "https://example.com\\",
                     "https://%65xample.com", new string('a', 2100) + ".com", "https://ex\u200Bample.com", "https://a\uD800.com" })
        {
            Assert.False(Match(bad, "https://example.com"), $"Eintrag: {bad[..Math.Min(40, bad.Length)]}");
            Assert.False(Match("https://example.com", bad), $"Website: {bad[..Math.Min(40, bad.Length)]}");
        }
    }

    [Fact]
    public void ZufallseingabenTrefferNurBeiHostBeziehung()
    {
        var alphabet = "abc.-:/@\\?#%[]1 äаxn-0".ToCharArray();
        var random = new Random(20261018);
        for (var i = 0; i < 3000; i++)
        {
            string Zufall()
            {
                var s = new StringBuilder(random.Next(2) == 0 ? "https://" : "");
                var n = random.Next(0, 21);
                for (var k = 0; k < n; k++) { s.Append(alphabet[random.Next(alphabet.Length)]); }
                return s.ToString();
            }
            var entry = Zufall();
            var service = Zufall();
            if (Match(entry, service) && AutofillMatcher.Origin.Parse(entry) is { } e && AutofillMatcher.Origin.Parse(service) is { } s)
            {
                Assert.True(s.Host == e.Host || s.Host.EndsWith("." + e.Host, StringComparison.Ordinal));
            }
        }
    }
}
