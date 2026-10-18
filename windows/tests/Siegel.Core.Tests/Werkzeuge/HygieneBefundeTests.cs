using System.Reflection;
using System.Text.Json;
using Siegel.Modell;

namespace Siegel.Werkzeuge.Tests;

/// <summary>
/// Hygiene-Befunde vom 18.10.2026 (Windows, Etappe 1) in den Werkzeugen: hygiene-1 (Geheimpuffer ohne Leihe →
/// paralleles Dispose während der TOTP-Rechnung liest freigegebenen Speicher, Prozessabsturz) und hygiene-4
/// (öffentliche Eigenschaft <c>TotpParameters.Secret</c> gab das Geheimnis bei jedem Lesen als Kopie heraus).
/// </summary>
public class HygieneBefundeTests
{
    private const string Uri = "otpauth://totp/Geheimdienst:anna?secret=JBSWY3DPEHPK3PXP";

    /// <summary>Base32 JBSWY3DPEHPK3PXP = „Hello!“ ‖ DE AD BE EF.</summary>
    private static readonly byte[] GeheimnisBytes = [0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0xDE, 0xAD, 0xBE, 0xEF];

    // MARK: hygiene-1

    /// <summary>Eine laufende Leihe hält den sodium-Speicher: Dispose markiert den Puffer nur, freigegeben (geschlossen)
    /// wird erst mit dem Ende der Leihe (vorher: sodium_free sofort, Lesen danach = SIGSEGV).</summary>
    [Fact]
    public void Leihe_haelt_Speicher_ueber_Dispose_hinaus()
    {
        var puffer = Geheimpuffer.Kopie(GeheimnisBytes);
        var l = puffer.Lesen();
        try
        {
            puffer.Dispose();
            Assert.False(puffer.IsClosed);
            Assert.Equal(GeheimnisBytes, l.Span.ToArray());
        }
        finally
        {
            l.Dispose();
        }
        Assert.True(puffer.IsClosed);
        var e = Assert.Throws<SiegelException>(() =>
        {
            using var danach = puffer.Lesen();
        });
        Assert.Equal((SiegelErrorCode.Crypto, "secure.disposed"), (e.Code, e.Detail));

        // Schreibende Leihe ebenso; schreibgeschützte Puffer verweigern sie.
        var flaeche = Geheimpuffer.Rechenflaeche(8);
        var w = flaeche.Schreiben();
        try
        {
            flaeche.Dispose();
            w.Span.Fill(0x5A);
            Assert.All(w.Span.ToArray(), b => Assert.Equal(0x5A, b));
        }
        finally
        {
            w.Dispose();
        }
        Assert.Equal("secure.disposed", Assert.Throws<SiegelException>(() =>
        {
            using var danach = flaeche.Schreiben();
        }).Detail);
        using var nurLesen = Geheimpuffer.Kopie(GeheimnisBytes);
        Assert.Equal("secure.readonly", Assert.Throws<SiegelException>(() =>
        {
            using var s = nurLesen.Schreiben();
        }).Detail);
    }

    /// <summary>Die Leihe auf den TOTP-Schlüssel überlebt ein Dispose der Parameter; der Code bleibt richtig.</summary>
    [Fact]
    public void Totp_Leihe_ueberlebt_Dispose_der_Parameter()
    {
        var p = Totp.Parse(Uri);
        var erwartet = Totp.Code(p, DateTimeOffset.FromUnixTimeSeconds(59)).Code;
        var l = p.LeiheSchluessel();
        try
        {
            p.Dispose();
            Assert.Equal(erwartet, Totp.Hotp(l.Span, 1, 6, TotpAlgorithm.Sha1));
        }
        finally
        {
            l.Dispose();
        }
        Assert.Equal("secure.disposed", Assert.Throws<SiegelException>(() => Totp.Code(p, DateTimeOffset.UnixEpoch)).Detail);
    }

    /// <summary>Das Messszenario des Befunds: Thread A rechnet in einer Schleife Codes, der Testthread gibt die Parameter
    /// zu wechselnden Zeitpunkten frei (vor dem ersten Code bis tief in der Schleife). Erwartet wird nur die feste Ausnahme
    /// <c>Crypto("secure.disposed")</c>. Vorher stürzte der Testhost ab (SIGSEGV, gemessen 3 von 3 Läufen mit genau
    /// diesem Test gegen den alten Geheimpuffer). Alle drei Algorithmen, 60-Byte-Geheimnis wie in der Probe.</summary>
    [Fact]
    public void Totp_Code_und_paralleles_Dispose_ohne_Absturz()
    {
        string[] uris =
        [
            "otpauth://totp/x?secret=" + string.Concat(Enumerable.Repeat("JBSWY3DPEHPK3PXP", 6)),
            "otpauth://totp/x?secret=" + TotpHilfe.SeedSha256 + "&algorithm=SHA256",
            "otpauth://totp/x?secret=" + TotpHilfe.SeedSha512 + "&algorithm=SHA512&digits=8",
        ];
        for (var runde = 0; runde < 600; runde++)
        {
            var p = Totp.Parse(uris[runde % uris.Length]);
            using var los = new ManualResetEventSlim();
            Exception? ende = null;
            var a = new Thread(() =>
            {
                los.Wait();
                try
                {
                    for (var i = 0; i < 10_000_000; i++) { _ = Totp.Code(p, DateTimeOffset.FromUnixTimeSeconds(i * 30L)); }
                }
                catch (Exception e)
                {
                    ende = e;
                }
            })
            { IsBackground = true };
            a.Start();
            los.Set();
            Thread.SpinWait(runde % 100 * 100);
            p.Dispose();
            Assert.True(a.Join(TimeSpan.FromSeconds(30)), "Thread A endet nicht");
            var e = Assert.IsType<SiegelException>(ende);
            Assert.Equal((SiegelErrorCode.Crypto, "secure.disposed"), (e.Code, e.Detail));
        }
    }

    /// <summary>Kopie (<c>with</c>) und Gleichheit laufen ebenfalls über Leihen: freigegeben → feste Ausnahme.</summary>
    [Fact]
    public void Kopie_und_Gleichheit_nach_Dispose_mit_festem_Code()
    {
        var p = Totp.Parse(Uri);
        using var q = Totp.Parse(Uri);
        Assert.Equal(p, q);
        p.Dispose();
        Assert.Equal("secure.disposed", Assert.Throws<SiegelException>(() => p with { }).Detail);
        Assert.Equal("secure.disposed", Assert.Throws<SiegelException>(() => q.Equals(p)).Detail);
        Assert.Equal("secure.disposed", Assert.Throws<SiegelException>(() => p.Equals(q)).Detail);
    }

    // MARK: hygiene-4

    /// <summary>Nach aussen wie <c>TOTP.Parameters</c> auf dem Mac: keine öffentliche Eigenschaft gibt das Geheimnis heraus,
    /// nur <see cref="TotpParameters.SecretByteCount"/>. Ein Reflexions-Serialisierer (Diagnose, Logger) findet nichts.</summary>
    [Fact]
    public void TotpParameters_gibt_das_Geheimnis_nicht_heraus()
    {
        var oeffentlich = typeof(TotpParameters).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(x => x.Name).Order(StringComparer.Ordinal).ToArray();
        Assert.Equal(["Account", "Algorithm", "Digits", "Issuer", "Period", "SecretByteCount"], oeffentlich);
        Assert.DoesNotContain(typeof(TotpParameters).GetMembers(BindingFlags.Public | BindingFlags.Instance),
            m => m.Name.Replace(nameof(TotpParameters.SecretByteCount), "", StringComparison.Ordinal)
                .Contains("Secret", StringComparison.Ordinal));

        using var p = Totp.Parse(Uri);
        Assert.Equal(GeheimnisBytes.Length, p.SecretByteCount);
        var json = JsonSerializer.Serialize(p);
        var base64 = Convert.ToBase64String(GeheimnisBytes);
        Assert.DoesNotContain(base64, json, StringComparison.Ordinal);
        Assert.DoesNotContain(base64.Replace("+", "\\u002B", StringComparison.Ordinal), json, StringComparison.Ordinal);
        Assert.DoesNotContain("Secret\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("JBSWY3DP", json, StringComparison.Ordinal);
    }
}
