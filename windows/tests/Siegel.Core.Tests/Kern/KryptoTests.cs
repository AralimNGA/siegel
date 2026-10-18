#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>SecureBuffer, AEAD, X25519, hybrides KEM und Kombinierer (§1.3, §1.4, §5).</summary>
public class KryptoTests
{
    [Fact]
    public void SecureBuffer_schreibgeschuetzt_geschwaerzt_und_nach_Freigabe_unbenutzbar()
    {
        var b = SecureBuffer.Copy([1, 2, 3]);
        Assert.Equal(3, b.Length);
        Assert.True(b.IsReadOnly);
        Assert.Equal("SecureBuffer(redacted)", b.ToString());
        KT.Throws(SiegelErrorCode.Crypto, "secure.readonly", () => b.BorrowWritable().Dispose());
        using (var l = b.Borrow()) { Assert.Equal([1, 2, 3], l.Span.ToArray()); }
        Assert.True(b.ConstantTimeEquals([1, 2, 3]));
        Assert.False(b.ConstantTimeEquals([1, 2, 4]));
        Assert.False(b.ConstantTimeEquals([1, 2]));
        using (var s = b.Slice(1, 2)) { Assert.True(s.ConstantTimeEquals([2, 3])); }
        KT.Throws(SiegelErrorCode.Crypto, "secure.range", () => b.Slice(2, 2));
        b.Dispose();
        KT.Throws(SiegelErrorCode.Crypto, "secure.disposed", () => b.Borrow().Dispose());
        using var empty = SecureBuffer.Copy([]);
        Assert.Equal(0, empty.Length);
        Assert.True(empty.ConstantTimeEquals([]));
        using var scratch = SecureBuffer.Scratch(4);
        using (var w = scratch.BorrowWritable()) { w.Span[0] = 9; }
        scratch.Freeze();
        Assert.True(scratch.ConstantTimeEquals([9, 0, 0, 0]));
        KT.Throws(SiegelErrorCode.Crypto, "secure.readonly", () => scratch.BorrowWritable().Dispose());
        using var r1 = SecureBuffer.Random(32);
        using var r2 = SecureBuffer.Random(32);
        Assert.False(r1.ConstantTimeEquals(r2));
    }

    [Fact]
    public void Aead_Rundlauf_und_jede_Aenderung_scheitert()
    {
        using var key = SecureBuffer.Random(32);
        using var secret = SecureBuffer.Random(32);
        var ad = Bytes.Ascii("Siegel v2 slot pw");
        var wrapped = Aead.Wrap(key, secret, ad);
        Assert.Equal(72, wrapped.Length);
        using (var back = Aead.Unwrap(key, wrapped, ad)) { Assert.True(back!.ConstantTimeEquals(secret)); }
        Assert.Null(Aead.Unwrap(key, wrapped, Bytes.Ascii("Siegel v2 slot rec")));
        for (var i = 0; i < wrapped.Length; i++)
        {
            var x = (byte[])wrapped.Clone();
            x[i] ^= 1;
            Assert.Null(Aead.Unwrap(key, x, ad));
        }
        using var other = SecureBuffer.Random(32);
        Assert.Null(Aead.Unwrap(other, wrapped, ad));
        Assert.Null(Aead.Unwrap(key, wrapped.AsSpan(0, 71), ad));
        using var plain = SecureBuffer.Copy(Bytes.Ascii("Inhalt"));
        var (nonce, ct) = Aead.Seal(key, plain, ad);
        Assert.Equal(24, nonce.Length);
        Assert.Equal(6 + 16, ct.Length);
        using (var opened = Aead.Open(key, nonce, ct, ad)) { Assert.True(opened!.ConstantTimeEquals(Bytes.Ascii("Inhalt"))); }
        Assert.Null(Aead.Open(key, nonce, ct, []));
        Assert.Null(Aead.Open(key, nonce, ct.AsSpan(0, 15), ad));
        var (n2, _) = Aead.Seal(key, plain, ad);
        Assert.NotEqual(nonce, n2);
        using var empty = SecureBuffer.Copy([]);
        var (n3, c3) = Aead.Seal(key, empty, ad);
        using (var e = Aead.Open(key, n3, c3, ad)) { Assert.Equal(0, e!.Length); }
    }

    [Fact]
    public void X25519_Nullpunkt_und_Kleinordnung_werden_abgelehnt()
    {
        using var sk = SecureBuffer.Random(32);
        Assert.Null(X25519.SharedSecret(sk, new byte[32]));
        var one = new byte[32];
        one[0] = 1;
        Assert.Null(X25519.SharedSecret(sk, one));
        var pkX = new RecoveryPublicKeys(Zufall.Bytes(RecoveryPublicKeys.PkMBytes), new byte[32]);
        // Ein ungültiger ML-KEM-Schlüssel (zufällig, Modulus-Prüfung) scheitert zuerst; mit gültigem pkM der X25519-Teil.
        KT.Throws(SiegelErrorCode.Crypto, "kem.encapsulate", () => RecoveryKem.Encapsulate(pkX, RecoveryKem.CombinerLabel));
        using var r = SecureBuffer.Random(32);
        var good = RecoveryKem.DerivePublicKeys(r, Zufall.Bytes(16));
        KT.Throws(SiegelErrorCode.Crypto, "kem.x25519",
            () => RecoveryKem.Encapsulate(new RecoveryPublicKeys(good.PkM, new byte[32]), RecoveryKem.CombinerLabel));
    }

    [Fact]
    public void Hybrid_KEM_Rundlauf_mit_und_ohne_Zusatzfeld()
    {
        using var r = SecureBuffer.Random(32);
        var vid = Zufall.Bytes(16);
        var pk = RecoveryKem.DerivePublicKeys(r, vid);
        var label = Bytes.Ascii("Siegel v2 hybrid KEM");
        using var enc = RecoveryKem.Encapsulate(pk, label);
        Assert.Equal(1568, enc.CtM.Length);
        Assert.Equal(32, enc.CtX.Length);
        using (var kek = RecoveryKem.Decapsulate(r, vid, pk, enc.CtM, enc.CtX, label)) { Assert.True(kek.ConstantTimeEquals(enc.Kek)); }
        // Anderes Label (Version) → anderer KEK; gekipptes ctM → anderer KEK (implizite Ablehnung), nie eine Ausnahme mit Inhalt.
        using (var kek1 = RecoveryKem.Decapsulate(r, vid, pk, enc.CtM, enc.CtX, RecoveryKem.CombinerLabel))
        {
            Assert.False(kek1.ConstantTimeEquals(enc.Kek));
        }
        var ctM = (byte[])enc.CtM.Clone();
        ctM[100] ^= 1;
        using (var kek2 = RecoveryKem.Decapsulate(r, vid, pk, ctM, enc.CtX, label)) { Assert.False(kek2.ConstantTimeEquals(enc.Kek)); }
        // Kleinordnungs-ctX nach bestandener pk-Prüfung → corruptFile
        KT.Corrupt("rec.decapsulate", () => RecoveryKem.Decapsulate(r, vid, pk, enc.CtM, new byte[32], label));
        // Mit Zusatzfeld (Eintrags-Schutz): über die geprüften privaten Schlüssel
        var context = Zufall.Bytes(16);
        using var enc2 = RecoveryKem.Encapsulate(pk, Bytes.Ascii("Siegel v2 entry card"), context);
        using var keys = RecoveryKem.PrivateKeys(r, vid, RecoveryKem.SeedInfo, RecoveryKem.X25519Info, pk);
        Assert.NotNull(keys);
        using (var k = RecoveryKem.Decapsulate(keys!, enc2.CtM, enc2.CtX, Bytes.Ascii("Siegel v2 entry card"), context))
        {
            Assert.True(k.ConstantTimeEquals(enc2.Kek));
        }
        using (var k = RecoveryKem.Decapsulate(keys!, enc2.CtM, enc2.CtX, Bytes.Ascii("Siegel v2 entry card"), Zufall.Bytes(16)))
        {
            Assert.False(k.ConstantTimeEquals(enc2.Kek));
        }
        KT.Throws(SiegelErrorCode.Crypto, "kem.decapsulate",
            () => RecoveryKem.Decapsulate(keys!, enc2.CtM, new byte[32], Bytes.Ascii("Siegel v2 entry card"), context));
        // Falsches Geheimnis bzw. falsche Infos → keine privaten Schlüssel
        using var r2 = SecureBuffer.Random(32);
        Assert.Null(RecoveryKem.PrivateKeys(r2, vid, RecoveryKem.SeedInfo, RecoveryKem.X25519Info, pk));
        Assert.Null(RecoveryKem.PrivateKeys(r, vid, EntryKeyDerivation.CardSeedInfo, EntryKeyDerivation.CardX25519Info, pk));
    }

    [Fact]
    public void Kombinierer_bindet_jedes_Feld_in_fester_Reihenfolge()
    {
        var label = Bytes.Ascii("Siegel v1 hybrid KEM");
        var ssM = KT.Repeat(1, 32);
        var ssX = KT.Repeat(2, 32);
        var ctX = KT.Repeat(3, 32);
        var pkX = KT.Repeat(4, 32);
        var ctM = KT.Repeat(5, 1568);
        var pkM = KT.Repeat(6, 1568);
        using var a = RecoveryKem.Combine(label, null, ssM, ssX, ctX, pkX, ctM, pkM);
        // Unabhängig: SHA3(label ‖ ssM ‖ ssX ‖ ctX ‖ pkX ‖ SHA3(ctM) ‖ SHA3(pkM))
        var expected = Sha3Hasher.Hash(label, ssM, ssX, ctX, pkX, Sha3Hasher.Of(ctM), Sha3Hasher.Of(pkM));
        Assert.True(a.ConstantTimeEquals(expected));
        using var swapped = RecoveryKem.Combine(label, null, ssX, ssM, ctX, pkX, ctM, pkM);
        Assert.False(swapped.ConstantTimeEquals(expected));
        var context = KT.Repeat(7, 16);
        using var withContext = RecoveryKem.Combine(label, context, ssM, ssX, ctX, pkX, ctM, pkM);
        Assert.True(withContext.ConstantTimeEquals(Sha3Hasher.Hash(label, context, ssM, ssX, ctX, pkX, Sha3Hasher.Of(ctM), Sha3Hasher.Of(pkM))));
        KT.Throws(SiegelErrorCode.Crypto, "kem.combine", () => RecoveryKem.Combine(label, KT.Repeat(7, 15), ssM, ssX, ctX, pkX, ctM, pkM));
        KT.Throws(SiegelErrorCode.Crypto, "kem.combine", () => RecoveryKem.Combine(label, null, ssM.AsSpan(0, 31), ssX, ctX, pkX, ctM, pkM));
    }

    [Fact]
    public void Seed_Laenge_ist_Vorbedingung()
    {
        using var wrong = SecureBuffer.Random(63);
        KT.Throws(SiegelErrorCode.Crypto, "mlkem.seedLength", () => RecoveryKem.MlkemPrivateKey(wrong));
    }

    [Fact]
    public void Master_Tag_und_Wiederverwendung()
    {
        using var dek = SecureBuffer.Random(32);
        using var key = MasterTag.Key(dek);
        using var pw = PasswordNormalizer.SecureBytes("Mein Master Passwort");
        using var tag = MasterTag.Tag(key, pw);
        var entries = new List<VaultEntry>
        {
            TestTresor.Entry("gleich", password: "Mein Master Passwort"),
            TestTresor.Entry("anders", password: "etwas anderes"),
            new() { Title = "Verlauf", Password = "neu", History = [new PasswordHistoryItem("Mein Master Passwort", Clock.Now())] },
        };
        var reuse = MasterTag.Reuse(entries, key, tag);
        Assert.Equal([entries[0].Id, entries[2].Id], reuse.OrderBy(id => entries.FindIndex(e => e.Id == id)));
        Assert.True(MasterTag.IsUsedByEntries(pw, entries));
        using var other = PasswordNormalizer.SecureBytes("nicht drin");
        Assert.False(MasterTag.IsUsedByEntries(other, entries));
    }
}
#endif
