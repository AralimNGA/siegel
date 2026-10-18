#if DEBUG
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Rundlauf und Grundlagen (Gegenstück zu KernRundlaufTests.swift).</summary>
public class RundlaufTests
{
    [Fact]
    public void Anlegen_Eintraege_Sperren_Entsperren()
    {
        using var f = KernVault.Make();
        Assert.Equal(1UL, f.Vault.Generation);
        Assert.Empty(f.Vault.Entries);
        Assert.False(f.Vault.RecoveryConfirmed);
        Assert.Equal(KT.Kdf, f.Vault.Kdf);
        Assert.Equal(f.Pending.Code.KitId, f.Vault.KitId);
        Assert.Equal(11, f.Pending.Code.Groups.Count);
        Assert.All(f.Pending.Code.Groups, g => Assert.Equal(5, g.Length));
        Assert.Equal(2, f.Pending.ConfirmationGroups.Distinct().Count());
        Assert.All(f.Pending.ConfirmationGroups, g => Assert.InRange(g, 0, 10));

        var e = KT.Entry("Bank", "anna.muster", "Kontostand-99", "https://bank.example.ch", "Zeile 1\nZeile 2 äöü «»");
        f.Vault.Upsert(e);
        e.Title = "Bank (privat)";
        f.Vault.Upsert(e);
        f.Vault.Upsert(KT.Entry("Mail", "anna@example.ch", "Post-Fach-7"));
        Assert.Equal(4UL, f.Vault.Generation);
        var expected = f.Vault.AllEntriesForTesting;
        f.Vault.Lock();
        Assert.True(f.Vault.IsLocked);

        var again = KT.Unlocked(f.Store.Unlock(KT.Pw1))!;
        Assert.NotNull(again);
        Assert.Equal(4UL, again.Generation);
        Assert.Equal(f.Vault.VaultId, again.VaultId);
        Assert.Equal(["Bank (privat)", "Mail"], again.Entries.Select(x => x.Title));
        var got = again.AllEntriesForTesting;
        Assert.Equal(expected.Count, got.Count);
        for (var i = 0; i < got.Count; i++)
        {
            Assert.Equal(expected[i].Id, got[i].Id);
            Assert.Equal(expected[i].Password, got[i].Password);
            Assert.Equal(expected[i].Notes, got[i].Notes);
            Assert.Equal(expected[i].Created, got[i].Created);
            Assert.Equal(expected[i].Modified, got[i].Modified);
        }
        again.Lock();
    }

    [Fact]
    public void Falsches_Passwort_ist_WrongPassword()
    {
        using var f = KernVault.Make();
        KT.Throws(SiegelErrorCode.WrongPassword, () => f.Store.Unlock(KT.Pw2));
        KT.Throws(SiegelErrorCode.WrongPassword, () => f.Store.Unlock(""));
        Assert.True(f.Vault.Verify(KT.Pw1));
        Assert.False(f.Vault.Verify(KT.Pw2));
    }

    [Fact]
    public void Kdf_Fehler_ist_KdfFailed_nie_WrongPassword()
    {
        using var f = KernVault.Make();
        using (KT.Hook(() => TestHooks.ForceKdfFailure = true, () => TestHooks.ForceKdfFailure = false))
        {
            KT.Throws(SiegelErrorCode.KdfFailed, () => f.Store.Unlock(KT.Pw1));
            KT.Throws(SiegelErrorCode.KdfFailed, () => f.Store.Unlock(KT.Pw2));
            KT.Throws(SiegelErrorCode.KdfFailed, () => f.Vault.PrepareRecovery(KT.Pw1));
        }
        Assert.NotNull(KT.Unlocked(f.Store.Unlock(KT.Pw1)));
    }

    [Fact]
    public void Tresor_fehlt_oder_existiert_schon()
    {
        using var f = KernVault.Make();
        KT.Throws(SiegelErrorCode.VaultAlreadyExists, () => f.Store.Create(KT.Pw2, KT.Kdf));
        var leer = VaultStore.ForTesting(f.Dir.Sub("Leer"), new InMemoryRollbackGuard());
        Assert.False(leer.VaultExists);
        KT.Throws(SiegelErrorCode.VaultMissing, () => leer.Unlock(KT.Pw1));
        KT.Throws(SiegelErrorCode.VaultMissing, () => leer.CheckRecoveryCode(f.Code));
        KT.Throws(SiegelErrorCode.VaultMissing, () => leer.Recover(f.Code, KT.Pw2, KT.Kdf));
    }

    [Fact]
    public void Normalisierung_geschuetztes_Leerzeichen_und_NFD()
    {
        Assert.True(VaultStore.PasswordsMatch("a b", "a b"));
        Assert.True(VaultStore.PasswordsMatch("é", "é"));
        Assert.False(VaultStore.PasswordsMatch("a b", "a  b"));
        Assert.False(VaultStore.PasswordsMatch(" a", "a"));

        using var f = KernVault.Make("u,F?CfDuMl YWuJASPVQ*6GUG@O");
        Assert.NotNull(KT.Unlocked(f.Store.Unlock("u,F?CfDuMl YWuJASPVQ*6GUG@O")));

        using var g = KernVault.Make("v,:f,uX&%!kQ>NéIti@!3c>w:~");
        Assert.NotNull(KT.Unlocked(g.Store.Unlock("v,:f,uX&%!kQ>NéIti@!3c>w:~")));
        KT.Throws(SiegelErrorCode.WrongPassword, () => g.Store.Unlock("v,:f,uX&%!kQ>NeIti@!3c>w:~"));
    }

    [Fact]
    public void Sperren_verwirft_alles_danach_unbrauchbar()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("A"));
        var gen = f.Vault.Generation;
        f.Vault.Lock();
        Assert.True(f.Vault.IsLocked);
        Assert.Empty(f.Vault.Entries);
        Assert.Empty(f.Vault.DeletedEntries);
        Assert.Empty(f.Vault.MasterPasswordReuse);
        Assert.Null(f.Vault.LastModified);
        Assert.Equal(gen, f.Vault.Generation);
        Assert.False(f.Vault.Verify(KT.Pw1));
        KT.Throws(SiegelErrorCode.Io, "vault.locked", () => f.Vault.Upsert(KT.Entry("B")));
        KT.Throws(SiegelErrorCode.Io, "vault.locked", () => f.Vault.PrepareRecovery(KT.Pw1));
        KT.Throws(SiegelErrorCode.Io, "vault.locked", () => f.Vault.ExportCsv(f.Dir.Path, KT.Pw1));
        KT.Throws(SiegelErrorCode.Io, "vault.locked", () => f.Vault.PurgeBackups());
        Assert.Equal(gen, f.ParsedFile().Generation);
        // Dispose = Lock, mehrfach unschädlich
        f.Vault.Dispose();
        f.Vault.Lock();
    }

    [Fact]
    public void Geschwaerzte_Beschreibungen()
    {
        using var f = KernVault.Make();
        var e = KT.Entry("Titel-Geheim", "benutzer-geheim", "Passwort-Geheim", "https://geheim.example", "Notiz-Geheim");
        f.Vault.Upsert(e);
        string[] secrets = ["Titel-Geheim", "benutzer-geheim", "Passwort-Geheim", "geheim.example", "Notiz-Geheim"];
        void Check(string s)
        {
            foreach (var secret in secrets) { Assert.DoesNotContain(secret, s, StringComparison.Ordinal); }
        }
        Check(e.ToString());
        Check(f.Vault.ToString());
        Check(f.Vault.Entries[0].ToString());
        foreach (var group in f.Pending.Code.Groups)
        {
            Assert.DoesNotContain(group, f.Pending.Code.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain(group, f.Pending.ToString(), StringComparison.Ordinal);
        }
        Assert.DoesNotContain("Verlauf-Geheim", new PasswordHistoryItem("Verlauf-Geheim", DateTimeOffset.UtcNow).ToString(), StringComparison.Ordinal);
        var report = f.Vault.SecurityReport();
        Check(report.ToString());
        Assert.Equal("UnlockOutcome(unlocked)", f.Store.Unlock(KT.Pw1).ToString());
    }

    [Fact]
    public void Polster_verschleiert_kleine_Groessenunterschiede()
    {
        using var a = KernVault.Make();
        using var b = KernVault.Make();
        a.Vault.Upsert(KT.Entry("A", notes: new string('x', 10)));
        b.Vault.Upsert(KT.Entry("Ein viel längerer Titel", notes: new string('y', 3000)));
        Assert.Equal(a.FileBytes().Length, b.FileBytes().Length);
        Assert.Equal(PayloadCodec.BlockSize + Aead.TagBytes, a.ParsedFile().Ciphertext.Length);
        a.Vault.Upsert(KT.Entry("Gross", notes: new string('z', 40_000)));
        Assert.Equal(0, (a.ParsedFile().Ciphertext.Length - Aead.TagBytes) % PayloadCodec.BlockSize);
    }

    [Fact]
    public void Feldgrenzen()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry(new string('t', 2048), new string('u', 2048), new string('p', 4096), new string('w', 2048), new string('n', 256 << 10)));
        var gen = f.Vault.Generation;
        KT.Throws(SiegelErrorCode.Io, "entry.titleTooLong", () => f.Vault.Upsert(KT.Entry(new string('t', 2049))));
        KT.Throws(SiegelErrorCode.Io, "entry.passwordTooLong", () => f.Vault.Upsert(KT.Entry("x", password: new string('p', 4097))));
        KT.Throws(SiegelErrorCode.Io, "entry.notesTooLong", () => f.Vault.Upsert(KT.Entry("x", notes: new string('n', (256 << 10) + 1))));
        KT.Throws(SiegelErrorCode.Io, "entry.titleTooLong", () => f.Vault.ImportEntries([KT.Entry(new string('ä', 1025))]));
        Assert.Equal(gen, f.Vault.Generation);
    }

    [Fact]
    public void Verlauf_hoechstens_10_junge_nie_verdraengt_harte_Grenze_30()
    {
        using var f = KernVault.Make();
        var start = KT.At(1_790_000_000);
        var e = KT.Entry("Wechsel", password: "pw-0");
        using (KT.Now(start)) { f.Vault.Upsert(e); }
        for (var i = 1; i <= 15; i++)
        {
            e.Password = "pw-" + i;
            using (KT.Now(start.AddDays(i * 40))) { f.Vault.Upsert(e); }
        }
        var current = f.Vault.Entries[0];
        Assert.Equal(10, current.History.Count);
        Assert.Equal("pw-14", current.History[0].Password);
        var late = start.AddDays(16 * 40);
        for (var i = 16; i <= 35; i++)
        {
            e.Password = "pw-" + i;
            using (KT.Now(late.AddMinutes(i))) { f.Vault.Upsert(e); }
        }
        Assert.Equal(20, f.Vault.Entries[0].History.Count);
        for (var i = 36; i <= 50; i++)
        {
            e.Password = "pw-" + i;
            using (KT.Now(late.AddMinutes(i))) { f.Vault.Upsert(e); }
        }
        current = f.Vault.Entries[0];
        Assert.Equal(30, current.History.Count);
        Assert.Equal("pw-49", current.History[0].Password);
        Assert.DoesNotContain(current.History, h => h.Password == "pw-50");
        e.Password = "pw-49";
        using (KT.Now(late.AddMinutes(51))) { f.Vault.Upsert(e); }
        current = f.Vault.Entries[0];
        Assert.Equal("pw-50", current.History[0].Password);
        Assert.DoesNotContain(current.History, h => h.Password == "pw-49");
        Assert.Equal(Clock.Canonical(e.Created), current.Created);
        Assert.Equal(Clock.Canonical(late.AddMinutes(51)), current.Modified);
        f.Vault.ClearHistory(current.Id);
        Assert.Empty(f.Vault.Entries[0].History);
    }

    [Fact]
    public void Zuletzt_geloescht_30_Tage()
    {
        using var f = KernVault.Make();
        var t0 = KT.At(1_790_000_000);
        var a = KT.Entry("A");
        var b = KT.Entry("B");
        using (KT.Now(t0))
        {
            f.Vault.Upsert(a);
            f.Vault.Upsert(b);
            f.Vault.Delete(a.Id);
        }
        Assert.Equal(["B"], f.Vault.Entries.Select(x => x.Title));
        Assert.Equal(["A"], f.Vault.DeletedEntries.Select(x => x.Title));
        Assert.Equal(Clock.Canonical(t0), f.Vault.LastModified);
        f.Vault.Restore(a.Id);
        Assert.Empty(f.Vault.DeletedEntries);
        using (KT.Now(t0)) { f.Vault.Delete(a.Id); }
        using (KT.Now(t0.AddDays(29))) { f.Vault.Upsert(b); }
        Assert.Single(f.Vault.DeletedEntries);
        using (KT.Now(t0.AddDays(31))) { f.Vault.Upsert(b); }
        Assert.Empty(f.Vault.DeletedEntries);
        Assert.Single(f.Vault.AllEntriesForTesting);
        KT.Throws(SiegelErrorCode.Io, "entry.notDeleted", () => f.Vault.PurgeDeleted(b.Id));
        f.Vault.Delete(b.Id);
        f.Vault.PurgeDeleted(b.Id);
        Assert.Empty(f.Vault.AllEntriesForTesting);
        KT.Throws(SiegelErrorCode.Io, "entry.notFound", () => f.Vault.Delete(Guid.NewGuid()));
    }

    [Fact]
    public void Inhalts_JSON_sortiert_null_explizit_v2()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("A"));
        var json = f.JsonOnDisk();
        Assert.StartsWith("{\"entries\":[{\"created\":", json, StringComparison.Ordinal);
        Assert.Contains("\"deletedAt\":null", json, StringComparison.Ordinal);
        Assert.Contains("\"recoveryConfirmedAt\":null", json, StringComparison.Ordinal);
        Assert.Contains("\"v\":2", json, StringComparison.Ordinal);
        Assert.Contains("\"level\":1", json, StringComparison.Ordinal);
        Assert.Contains("\"factors\":{\"card\":null,\"secureEnclave\":null,\"securityKey\":null}", json, StringComparison.Ordinal);
        Assert.Contains("\"protection\":1", json, StringComparison.Ordinal);
        Assert.Contains("\"totp\":\"\"", json, StringComparison.Ordinal);
        // Metadaten für alle Einträge (§17) und der Grundschlüssel
        Assert.Contains("\"meta\":{\"changed\":", json, StringComparison.Ordinal);
        Assert.Contains("\"entryKey\":\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("windowsHello", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"hello\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Kein_Argon2_auf_dem_Oberflaechen_Thread()
    {
        using var f = KernVault.Make();
        var old = CoreEnvironment.IsUiThread;
        var thread = Environment.CurrentManagedThreadId;
        CoreEnvironment.IsUiThread = () => Environment.CurrentManagedThreadId == thread;
        try
        {
            KT.Throws(SiegelErrorCode.Crypto, "kdf.uiThread", () => f.Store.Unlock(KT.Pw1));
            KT.Throws(SiegelErrorCode.Crypto, "kdf.uiThread", () => f.Vault.ChangeMasterPassword(KT.Pw1, KT.Pw2));
            // Programmfehler (Swift: dispatchPrecondition) – auch Verify liefert dann nicht still false.
            KT.Throws(SiegelErrorCode.Crypto, "kdf.uiThread", () => f.Vault.Verify(KT.Pw1));
        }
        finally
        {
            CoreEnvironment.IsUiThread = old;
        }
    }
}
#endif
