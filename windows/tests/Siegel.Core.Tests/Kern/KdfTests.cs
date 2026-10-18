#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using System.Text;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>KDF-Grenzen (§1.1), Testschalter, Normalisierung (RFC 8265), KdfFailed ≠ WrongPassword.</summary>
public class KdfTests
{
    [Fact]
    public void Grenzen_der_Produktion_und_des_Testschalters()
    {
        var prod = KdfLimits.Production;
        prod.Validate(KdfParameters.Standard);
        prod.Validate(KdfParameters.Strong);
        prod.Validate(new KdfParameters(3, 256UL << 20));
        prod.Validate(new KdfParameters(10, 4UL << 30));
        foreach (var bad in new[]
                 {
                     new KdfParameters(3, (256UL << 20) - 1024), new KdfParameters(3, (4UL << 30) + 1024),
                     new KdfParameters(2, 1UL << 30), new KdfParameters(11, 1UL << 30), new KdfParameters(3, (1UL << 30) + 1),
                     KT.Kdf,
                 })
        {
            KT.Throws(SiegelErrorCode.KdfParametersOutOfRange, () => prod.Validate(bad));
        }
        var test = KdfLimits.Testing;
        test.Validate(KT.Kdf);
        test.Validate(new KdfParameters(3, 1UL << 20));
        // Der Testschalter verschiebt den Bereich, er hebt keine Prüfung auf.
        KT.Throws(SiegelErrorCode.KdfParametersOutOfRange, () => test.Validate(KdfParameters.Standard));
        KT.Throws(SiegelErrorCode.KdfParametersOutOfRange, () => test.Validate(new KdfParameters(0, 8UL << 10)));
        KT.Throws(SiegelErrorCode.KdfParametersOutOfRange, () => test.Validate(new KdfParameters(1, 4UL << 10)));
        Assert.Equal(new KdfParameters(1, 8UL << 10), test.Profile(SecurityLevel.Erhoeht));
        Assert.Equal(new KdfParameters(2, 16UL << 10), test.Profile(SecurityLevel.Hoch));
        Assert.Equal(KdfParameters.Strong, prod.Profile(SecurityLevel.Festung));
        Assert.True(prod.IsWeaker(KdfParameters.Standard, SecurityLevel.Hoch));
        Assert.False(prod.IsWeaker(KdfParameters.Strong, SecurityLevel.Standard));
    }

    [Fact]
    public void Grenzen_greifen_beim_Lesen_vor_Argon2()
    {
        using var t = TestTresor.Create();
        // Mit Produktionsgrenzen ist die Testdatei (8 KiB) ausserhalb → kein Argon2, KdfParametersOutOfRange.
        var counter = new TestHooks.Counter();
        TestHooks.KdfCounter = counter;
        try
        {
            KT.Throws(SiegelErrorCode.KdfParametersOutOfRange,
                () => VaultCrypto.OpenWithPassword(t.File, t.Password, null, KdfLimits.Production));
            Assert.Equal(0, counter.Value);
        }
        finally
        {
            TestHooks.KdfCounter = null;
        }
        // Angreifer setzt m = 8 GiB (Prüfsumme neu): DoS-Grenze.
        var b = (byte[])t.Bytes.Clone();
        BitConverter.TryWriteBytes(b.AsSpan(29, 8), 8UL << 30);
        var forged = VaultFile.Parse(KT.WithFixedChecksum(b));
        KT.Throws(SiegelErrorCode.KdfParametersOutOfRange, () => VaultCrypto.OpenWithPassword(forged, t.Password, null, KdfLimits.Testing));
    }

    [Fact]
    public void Grenzen_greifen_beim_Schreiben()
    {
        using var pw = PasswordNormalizer.SecureBytes(KT.Pw1);
        using var r = SecureBuffer.Random(32);
        var vid = Zufall.Bytes(16);
        var pk = RecoveryKem.DerivePublicKeys(r, vid);
        KT.Throws(SiegelErrorCode.KdfParametersOutOfRange, () => VaultCrypto.Rekey(vid, new KdfParameters(4, 2UL << 20),
            HeaderFactorFields.None, RecoveryScheme.SingleCode, pk, pw, new FactorSecrets(), KdfLimits.Testing));
        KT.Throws(SiegelErrorCode.KdfParametersOutOfRange, () => VaultCrypto.Rekey(vid, KT.Kdf, HeaderFactorFields.None,
            RecoveryScheme.SingleCode, pk, pw, new FactorSecrets(), KdfLimits.Production));
    }

    [Fact]
    public void KdfFailed_ist_nicht_WrongPassword()
    {
        using var t = TestTresor.Create();
        TestHooks.ForceKdfFailure = true;
        try
        {
            KT.Throws(SiegelErrorCode.KdfFailed, () => VaultCrypto.OpenWithPassword(t.File, t.Password, null, KdfLimits.Testing));
        }
        finally
        {
            TestHooks.ForceKdfFailure = false;
        }
        using var wrong = PasswordNormalizer.SecureBytes(KT.Pw2);
        KT.Throws(SiegelErrorCode.WrongPassword, () => VaultCrypto.OpenWithPassword(t.File, wrong, null, KdfLimits.Testing));
        KT.Corrupt("header.salt", () => Kdf.DeriveKek(t.Password, new byte[15], KT.Kdf, KdfLimits.Testing));
    }

    [Fact]
    public void Argon2id_ist_libsodium_crypto_pwhash_mit_festem_Wert()
    {
        // Unabhängig mit Python (libsodium per ctypes) nachgerechnet: pw "Siegel", Salz 00…0f, t = 1, m = 8 KiB.
        using var pw = PasswordNormalizer.SecureBytes("Siegel");
        using var a = Kdf.DeriveKek(pw, KT.Seq(0, 16), KT.Kdf, KdfLimits.Testing);
        Assert.Equal("1e2082c0d126ee50f6511072e4f0a57cf6a1435e0f18adabf4eb1ccce091c91b", a.HexForTesting());
        using var b = Kdf.DeriveKek(pw, KT.Seq(0, 16), KT.Kdf, KdfLimits.Testing);
        Assert.True(a.ConstantTimeEquals(b));
        using var c = Kdf.DeriveKek(pw, KT.Seq(1, 16), KT.Kdf, KdfLimits.Testing);
        Assert.False(a.ConstantTimeEquals(c));
        Assert.Equal(32, a.Length);
    }

    [Fact]
    public void Normalisierung_RFC8265()
    {
        Assert.Equal(PasswordNormalizer.Normalize("a b"), PasswordNormalizer.Normalize("a b"));
        Assert.Equal(PasswordNormalizer.Normalize("é"), PasswordNormalizer.Normalize("é"));
        Assert.Equal("a b c d e", PasswordNormalizer.Normalize("a b　c d e"));
        // Nichts trimmen; Tabulator und Zeilenumbruch sind kein Zs.
        Assert.Equal(" x\t\n ", PasswordNormalizer.Normalize(" x\t\n "));
        // NFC, nicht NFKC: Ligaturen bleiben.
        Assert.Equal("ﬁ", PasswordNormalizer.Normalize("ﬁ"));
        // Einzelne Surrogate werden U+FFFD (wie UTF-8), statt eine Ausnahme zu werfen.
        Assert.Equal("a�b", PasswordNormalizer.Normalize("a\uD800b"));
        Assert.Equal("😀", PasswordNormalizer.Normalize("😀"));
        using var bytes = PasswordNormalizer.SecureBytes("é ");
        Assert.True(bytes.ConstantTimeEquals(Encoding.UTF8.GetBytes("é ")));
    }

    [Fact]
    public void Normalisierte_Passwoerter_oeffnen_denselben_Tresor()
    {
        using var t = TestTresor.Create(password: "Sehr-langes Passwort-é-2026!");
        using var variant = PasswordNormalizer.SecureBytes("Sehr-langes Passwort-é-2026!");
        using var opened = VaultCrypto.OpenWithPassword(t.File, variant, null, KdfLimits.Testing);
        Assert.Equal(2, opened.Content.Entries.Count);
    }

    [Fact]
    public void Oberflaechen_Thread_Pruefung()
    {
        using var pw = PasswordNormalizer.SecureBytes("x");
        // Nur dieser Thread gilt als Oberflächen-Thread: parallel laufende Tests bleiben unberührt.
        var thread = Environment.CurrentManagedThreadId;
        CoreEnvironment.IsUiThread = () => Environment.CurrentManagedThreadId == thread;
        try
        {
            KT.Throws(SiegelErrorCode.Crypto, "kdf.uiThread", () => Kdf.DeriveKek(pw, new byte[16], KT.Kdf, KdfLimits.Testing));
        }
        finally
        {
            CoreEnvironment.IsUiThread = null;
        }
    }
}
#endif
