#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>
/// Hygiene-Befunde vom 18.10.2026 (Windows, Etappe 1) im Kern: hygiene-2 (Klartext-CSV unter 4 KiB blieb im
/// FileStream-Puffer), hygiene-3 (entryKey-Rohkopie bei jedem Dekodieren), hygiene-5 (Symbole des ersten Teils
/// ungenullt, wenn der zweite einen Formatfehler hat), hygiene-6 (ungekürztes Symbolfeld bei der Fehlerkorrektur).
/// hygiene-1 und hygiene-4 (Werkzeuge) prüft <c>Siegel.Werkzeuge.Tests.HygieneBefundeTests</c>.
/// Ungenullte verwaltete Kopien lassen sich nicht plattformneutral im Speicher suchen; die Tests prüfen darum die
/// Ursache: kein Puffer (Strategie des FileStreams), kein Zwischenfeld (Allokationen des Threads), Nullen im Fehlerpfad.
/// </summary>
public class HygieneBefundeWindowsTests
{
    /// <summary>Bytes, die <paramref name="body"/> auf diesem Thread verwaltet anlegt (Minimum aus 5 Läufen nach dem Aufwärmen).</summary>
    private static long Allokiert(Action body)
    {
        body();
        var min = long.MaxValue;
        for (var i = 0; i < 5; i++)
        {
            var vor = GC.GetAllocatedBytesForCurrentThread();
            body();
            min = Math.Min(min, GC.GetAllocatedBytesForCurrentThread() - vor);
        }
        return min;
    }

    /// <summary>Vergleichswert: genau ein byte[] dieser Länge (nicht inline, damit nichts auf den Stack wandert).</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static byte[] Feld(int length) => new byte[length];

    // MARK: hygiene-2

    private static string Strategie(FileStream stream)
    {
        var feld = typeof(FileStream).GetField("_strategy", BindingFlags.NonPublic | BindingFlags.Instance);
        Assert.NotNull(feld);
        return feld.GetValue(stream)!.GetType().Name;
    }

    /// <summary>Schreiben ohne FileStream-Puffer: Mit dem Standard (4096) kopierte die BufferedFileStreamStrategy jedes
    /// Write unter 4 KiB in ihren eigenen, nie genullten byte[] – beim CSV-Export die ganze Klartext-Datei.</summary>
    [Fact]
    public void Schreiben_ohne_FileStream_Puffer()
    {
        Assert.Equal(0, FileIO.WriteOptions(FileMode.CreateNew).BufferSize);
        Assert.Equal(0, FileIO.WriteOptions(FileMode.Create).BufferSize);
        using var d = new KernTempDir();
        // Gegenprobe: Mit den Standardoptionen puffert der FileStream (die Sonde misst also etwas).
        using (var standard = new FileStream(Path.Combine(d.Path, "standard"),
            new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write }))
        {
            Assert.Equal("BufferedFileStreamStrategy", Strategie(standard));
        }
        using (var exklusiv = FileIO.CreateExclusive(Path.Combine(d.Path, "export.csv")))
        {
            Assert.NotEqual("BufferedFileStreamStrategy", Strategie(exklusiv));
        }
        using (var anOrt = new FileStream(Path.Combine(d.Path, "anort"), FileIO.WriteOptions(FileMode.Create)))
        {
            Assert.NotEqual("BufferedFileStreamStrategy", Strategie(anOrt));
        }
        // Inhalt unverändert, klein (bisher gepuffert) und gross.
        foreach (var n in new[] { 0, 1, 182, 4095, 4096, 70_000 })
        {
            var bytes = Zufall.Bytes(n);
            var a = Path.Combine(d.Path, "a" + n);
            var b = Path.Combine(d.Path, "b" + n);
            FileIO.WriteExclusive(a, bytes);
            FileIO.WriteInPlace(b, bytes);
            FileIO.WriteInPlace(b, bytes);
            Assert.Equal(bytes, File.ReadAllBytes(a));
            Assert.Equal(bytes, File.ReadAllBytes(b));
        }
    }

    // MARK: hygiene-3

    private static JString S(string s) => new(s);

    /// <summary>Die bisherige Dekodierung (Puffer s.Length / 4 · 3, dann gekürzt) als Referenz: Die neue muss genau dieselben
    /// Eingaben annehmen und dieselben Bytes liefern.</summary>
    private static byte[]? Bisher(string s)
    {
        if (s.Length % 4 != 0) { return null; }
        var pad = s.EndsWith("==", StringComparison.Ordinal) ? 2 : s.EndsWith('=') ? 1 : 0;
        for (var i = 0; i < s.Length - pad; i++)
        {
            var c = s[i];
            if (!(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '+' or '/')) { return null; }
        }
        var output = new byte[s.Length / 4 * 3];
        return Convert.TryFromBase64String(s, output, out var written) ? output[..written] : null;
    }

    [Fact]
    public void Data_und_SecretData_streng_wie_bisher()
    {
        var korpus = new List<string> { "", "A", "AA=", "AA==", "AAA=", "AAAA", "A===", "====", "AA=A", "AB==CD==", "AB==",
            "AAB=", " AAA", "AA A", "AAA\n", "Zm9v\r\n", "AAA-", "AAA_", "AAAä", "Zg", "Zg=", "Zg==" };
        for (var n = 0; n <= 70; n++)
        {
            var text = Convert.ToBase64String(Zufall.Bytes(n));
            korpus.Add(text);
            if (text.Length > 0)
            {
                korpus.Add(text[..^1]);
                korpus.Add(text.TrimEnd('='));
                korpus.Add(text[..^1] + "*");
                korpus.Add("=" + text[1..]);
            }
        }
        foreach (var s in korpus)
        {
            var erwartet = Bisher(s);
            if (erwartet is null)
            {
                KT.Corrupt("payload.json", () => JRead.Data(S(s)));
                KT.Corrupt("payload.json", () => JRead.SecretData(S(s)).Dispose());
                continue;
            }
            Assert.Equal(erwartet, JRead.Data(S(s)));
            using var geheim = JRead.SecretData(S(s));
            Assert.True(geheim.IsReadOnly);
            using var l = geheim.Borrow();
            Assert.Equal(erwartet, l.Span.ToArray());
        }
    }

    /// <summary>Data legt nur das Ergebnis an – vorher zuerst 33 B, dann die gekürzte Kopie (32 B), das Original ungenullt.</summary>
    [Fact]
    public void Data_ohne_ungekuerzten_Zwischenpuffer()
    {
        var schluessel = S(Convert.ToBase64String(KT.Seq(1, 32)));               // 44 Zeichen, ein „=“
        Assert.Equal(Allokiert(() => Feld(32)), Allokiert(() => JRead.Data(schluessel)));
        var zwei = S(Convert.ToBase64String(KT.Seq(1, 31)));                      // „==“
        Assert.Equal(Allokiert(() => Feld(31)), Allokiert(() => JRead.Data(zwei)));
    }

    /// <summary>Der entryKey geht ohne verwaltete Rohkopie in sodium-Speicher: Die Allokationen hängen nicht von der
    /// Schlüssellänge ab (nur das SecureBuffer-Objekt selbst), es entsteht also kein byte[] mit dem Schlüssel.</summary>
    [Fact]
    public void SecretData_ohne_verwaltete_Kopie()
    {
        var kurz = S("AAA=");
        var schluessel = S(Convert.ToBase64String(KT.Seq(1, 32)));
        var lang = S(Convert.ToBase64String(KT.Seq(0, 255)));
        var basis = Allokiert(() => JRead.SecretData(kurz).Dispose());
        Assert.Equal(basis, Allokiert(() => JRead.SecretData(schluessel).Dispose()));
        Assert.Equal(basis, Allokiert(() => JRead.SecretData(lang).Dispose()));
    }

    // MARK: hygiene-5

    /// <summary>Alle oder keine: Scheitert eine Eingabe, sind die schon erzeugten Felder genullt (der Aufrufer bekommt sie
    /// nie). Vorher blieben die 56 Symbole des gültigen ersten Teils liegen.</summary>
    [Fact]
    public void Teile_parsen_nullt_bei_Fehler_die_schon_erzeugten()
    {
        var erzeugt = new List<byte[]>();
        KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => RecoveryMatching.ParseAllOrWipe(["a", "b", "c"], s =>
        {
            if (s == "c") { throw Fehler.InvalidCodeFormat(); }
            var b = KT.Repeat(7, Shamir.SymbolCount);
            erzeugt.Add(b);
            return b;
        }));
        Assert.Equal(2, erzeugt.Count);
        Assert.All(erzeugt, b => Assert.All(b, x => Assert.Equal(0, x)));
        var ok = RecoveryMatching.ParseAllOrWipe(["a", "b"], _ => KT.Repeat(7, 3));
        Assert.All(ok, b => Assert.Equal(KT.Repeat(7, 3), b));

        // Echte Teile: gültig + Tippfehler („U“ gibt es im Alphabet nicht) → wie bisher InvalidRecoveryCodeFormat.
        using var r = SecureBuffer.Random(32);
        var shares = RecoveryMatching.SharesFor(r, RecoveryKem.DerivePublicKeys(r, Zufall.Bytes(16)));
        KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => RecoveryMatching.ParseShareInputs([shares[0].Formatted, "UUUUU"]));
        KT.Throws(SiegelErrorCode.InvalidRecoveryCodeFormat, () => RecoveryMatching.ParseShareInputs(["UUUUU", shares[0].Formatted]));
        var beide = RecoveryMatching.ParseShareInputs([shares[0].Formatted, shares[1].Formatted]);
        Assert.All(beide, b => Assert.Equal(Shamir.SymbolCount, b.Length));
        foreach (var b in beide) { CryptographicOperations.ZeroMemory(b); }
    }

    // MARK: hygiene-6

    [Fact]
    public void Symbole_direkt_ins_Ziel()
    {
        foreach (var n in new[] { 0, 1, 4, 5, 34, 35, 36 })
        {
            var bytes = Zufall.Bytes(n);
            var alle = RecoveryCodeCodec.SymbolsFromBytes(bytes);
            Assert.Equal((n * 8 + 4) / 5, alle.Length);
            for (var k = 0; k <= alle.Length; k++)
            {
                var ziel = new byte[k];
                RecoveryCodeCodec.SymbolsFromBytes(bytes, ziel);
                Assert.Equal(alle[..k], ziel);
            }
            KT.Throws(SiegelErrorCode.Crypto, "recovery.symbolCount",
                () => RecoveryCodeCodec.SymbolsFromBytes(bytes, new byte[alle.Length + 1]));
        }
    }

    /// <summary>Treffer-Symbole (Code: 55, Teil: 56) entstehen direkt im Ergebnis – vorher blieb das ungekürzte bzw.
    /// kopierte Zwischenfeld mit den richtigen Symbolen ungenullt liegen, der Aufrufer nullte nur die Kopie.</summary>
    [Fact]
    public void Treffer_Symbole_ohne_Zwischenfeld()
    {
        var p = Zufall.Bytes(RecoveryCodeCodec.PackedBytes + 1);              // mit Reservebyte wie in der Suche
        var alle = RecoveryCodeCodec.SymbolsFromBytes(p.AsSpan(0, RecoveryCodeCodec.PackedBytes));
        Assert.Equal(alle[..RecoveryCodeCodec.SymbolCount], RecoveryCodeCorrection.SymbolsOf(p));
        Assert.Equal(Allokiert(() => Feld(RecoveryCodeCodec.SymbolCount)), Allokiert(() => RecoveryCodeCorrection.SymbolsOf(p)));

        using var c = new Shamir.Candidate(SecureBuffer.Copy(p.AsSpan(0, RecoveryCodeCodec.PackedBytes)), []);
        Assert.Equal(alle, c.Symbols());
        Assert.Equal(Allokiert(() => Feld(Shamir.SymbolCount)), Allokiert(() => c.Symbols()));
    }

    /// <summary>Die Korrektur liefert nach dem Umbau dieselben Treffer (ein falsches Zeichen im Code bzw. im Teil).</summary>
    [Fact]
    public void Korrektur_unveraendert()
    {
        using var r = SecureBuffer.Random(32);
        var code = RecoveryCodeCodec.Format(r);
        var symbole = RecoveryCodeCodec.ParseSymbols(code, allowUnknown: true, RecoveryCodeCodec.SymbolCount);
        var falsch = (byte[])symbole.Clone();
        falsch[10] = (byte)((falsch[10] + 1) & 31);
        var hit = RecoveryCodeCorrection.Search(falsch, x =>
        {
            using var rb = SecureBuffer.Copy(x);
            return rb.ConstantTimeEquals(r);
        });
        Assert.NotNull(hit);
        Assert.Equal(symbole, hit.Symbols);
        Assert.Equal(new[] { 10 }, hit.Changed);
    }
}
#endif
