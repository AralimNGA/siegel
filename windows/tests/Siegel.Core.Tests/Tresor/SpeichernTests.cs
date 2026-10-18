#if DEBUG
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Speichern, Generation, Rollback (Gegenstück zu KernSpeichernTests.swift).</summary>
public class SpeichernTests
{
    [Fact]
    public void Generation_steigt_bei_jedem_Schreibweg_um_genau_1()
    {
        using var f = KernVault.Make();
        ulong expected = 1;
        void Step(string what, UnlockedVault? vault = null)
        {
            expected++;
            var v = vault ?? f.Vault;
            Assert.True(v.Generation == expected, what);
            Assert.True(f.ParsedFile().Generation == expected, what);
            Assert.True(f.Guardian.LastSeenGeneration(v.VaultId) == expected, what);
        }
        Assert.Equal(1UL, f.Vault.Generation);
        var e = KT.Entry("A");
        f.Vault.Upsert(e);
        Step("upsert");
        e.Password = "Neu-1";
        f.Vault.Upsert(e);
        Step("upsert Passwort");
        f.Vault.ClearHistory(e.Id);
        Step("clearHistory");
        f.Vault.Delete(e.Id);
        Step("delete");
        f.Vault.Restore(e.Id);
        Step("restore");
        f.Vault.Delete(e.Id);
        Step("delete 2");
        f.Vault.PurgeDeleted(e.Id);
        Step("purgeDeleted");
        f.Vault.ImportEntries([KT.Entry("Import", url: "import.example")]);
        Step("importEntries");
        f.Vault.ChangeMasterPassword(KT.Pw1, KT.Pw2);
        Step("changeMasterPassword");
        f.Vault.CommitRecovery(f.Pending, KernStufen.Confirmation(f.Pending));
        Step("commitRecovery bestätigen");
        var pending = f.Vault.PrepareRecovery(KT.Pw2);
        f.Vault.CommitRecovery(pending, KernStufen.Confirmation(pending));
        Step("commitRecovery neues Kit");
        f.Vault.Lock();
        var rec = f.Store.Recover(pending.Code.Formatted, KT.Pw3, KT.Kdf);
        Step("recover", rec);
        var oldBackup = f.LocalBackups()[^1];
        rec.Lock();
        var restored = f.Store.RestoreBackup(oldBackup, KT.Pw1);
        Step("restoreBackup", restored);
        // Befund #3: Die alte Sicherung bringt das alte Kit mit; es gilt nicht still als bestätigt.
        Assert.Equal(f.Pending.Code.KitId, restored.KitId);
        Assert.NotEqual(pending.Code.KitId, restored.KitId);
        Assert.False(restored.RecoveryConfirmed);
        var export = Path.Combine(f.Dir.Path, "export.siegel");
        f.Store.ExportBackup(export);
        restored.Lock();
        var imported = f.Store.ImportBackup(export, KT.Pw1);
        Step("importBackup", imported);
        imported.Lock();
        var b = f.FileBytes();
        b[b.Length / 2] ^= 1;
        f.WriteFile(b);
        var (newest, _) = f.Store.RestoreNewestReadableBackup(KT.Pw1);
        Step("restoreNewestReadableBackup", newest);
        newest.Upsert(KT.Entry("Danach"));
        Step("upsert nach Wiederherstellung", newest);
        newest.Lock();
    }

    [Fact]
    public void Rollback_Erkennung()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("A"));
        var gen2 = f.FileBytes();
        f.Vault.Upsert(KT.Entry("B"));
        Assert.Equal(3UL, f.Vault.Generation);
        f.Vault.Lock();
        f.WriteFile(gen2);
        var outcome = f.Store.Unlock(KT.Pw1);
        Assert.True(outcome.IsRollbackSuspected);
        Assert.Equal(3UL, outcome.SeenGeneration);
        Assert.Equal(2UL, outcome.FileGeneration);
        var v = outcome.Vault;
        Assert.Equal(["A"], v.Entries.Select(x => x.Title));
        // „Trotzdem öffnen“: nächstes Speichern schreibt über die gesehene Generation hinaus
        v.Upsert(KT.Entry("C"));
        Assert.Equal(4UL, v.Generation);
        v.Lock();
        Assert.NotNull(KT.Unlocked(f.Store.Unlock(KT.Pw1)));
        var fresh = f.ReopenStore(new InMemoryRollbackGuard());
        Assert.NotNull(KT.Unlocked(fresh.Unlock(KT.Pw1)));
    }

    [Fact]
    public void FileRollbackGuard_merkt_nur_steigende_Generationen()
    {
        using var dir = new KernTempDir();
        var path = Path.Combine(dir.Path, "Stolperdraht", "rollback.txt");
        var g = new FileRollbackGuard(path);
        var id = Guid.NewGuid();
        Assert.Null(g.LastSeenGeneration(id));
        g.Record(id, 5);
        Assert.Equal(5UL, g.LastSeenGeneration(id));
        g.Record(id, 3);
        Assert.Equal(5UL, g.LastSeenGeneration(id));
        g.Record(id, ulong.MaxValue - 1);
        Assert.Equal(ulong.MaxValue - 1, g.LastSeenGeneration(id));
        Assert.Equal(ulong.MaxValue - 1, new FileRollbackGuard(path).LastSeenGeneration(id));
        Assert.Null(g.LastSeenGeneration(Guid.NewGuid()));
        var other = Guid.NewGuid();
        g.Record(other, 7);
        Assert.Equal(7UL, new FileRollbackGuard(path).LastSeenGeneration(other));
        Assert.Equal(ulong.MaxValue - 1, new FileRollbackGuard(path).LastSeenGeneration(id));
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(path)!, "*.tmp"));
    }

    [Fact]
    public void Geaendert_auf_der_Platte_zweite_Sitzung_ueberschreibt_nichts()
    {
        using var f = KernVault.Make();
        var second = KT.Unlocked(f.ReopenStore().Unlock(KT.Pw1))!;
        f.Vault.Upsert(KT.Entry("Von Sitzung 1"));
        var onDisk = f.FileBytes();
        KT.Throws(SiegelErrorCode.VaultChangedOnDisk, () => second.Upsert(KT.Entry("Von Sitzung 2")));
        Assert.Equal(onDisk, f.FileBytes());
        Assert.Empty(second.Entries);
        Assert.Equal(1UL, second.Generation);
        Assert.Empty(f.TempFiles());
        second.Lock();
    }

    [Fact]
    public void Ruecklese_Pruefung_scheitert_alte_Datei_unveraendert()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("A"));
        var before = f.FileBytes();
        var backupsBefore = f.BackupFileNames();
        using (KT.Hook(() => TestHooks.CorruptTempBeforeVerify = true, () => TestHooks.CorruptTempBeforeVerify = false))
        {
            KT.Throws(SiegelErrorCode.Io, "save.verify", () => f.Vault.Upsert(KT.Entry("B")));
        }
        Assert.Equal(before, f.FileBytes());
        Assert.Empty(f.TempFiles());
        Assert.Equal(backupsBefore, f.BackupFileNames());
        Assert.Equal(["A"], f.Vault.Entries.Select(x => x.Title));
        Assert.Equal(2UL, f.Vault.Generation);
        f.Vault.Upsert(KT.Entry("B"));
        Assert.Equal(3UL, f.Vault.Generation);
    }

    [Fact]
    public void Unter_64_MiB_frei_nichts_geschrieben()
    {
        using var f = KernVault.Make();
        var before = f.FileBytes();
        using (KT.Hook(() => TestHooks.FreeSpaceOverride = (64UL << 20) - 1, () => TestHooks.FreeSpaceOverride = null))
        {
            KT.Throws(SiegelErrorCode.NotEnoughDiskSpace, () => f.Vault.Upsert(KT.Entry("A")));
        }
        Assert.Equal(before, f.FileBytes());
        Assert.Empty(f.TempFiles());
        using var dir = new KernTempDir();
        var store = VaultStore.ForTesting(dir.Sub("Siegel"), new InMemoryRollbackGuard());
        using (KT.Hook(() => TestHooks.FreeSpaceOverride = 1UL << 20, () => TestHooks.FreeSpaceOverride = null))
        {
            KT.Throws(SiegelErrorCode.NotEnoughDiskSpace, () => store.Create(KT.Pw1, KT.Kdf));
        }
        Assert.False(store.VaultExists);
        using (KT.Hook(() => TestHooks.FreeSpaceOverride = 64UL << 20, () => TestHooks.FreeSpaceOverride = null))
        {
            f.Vault.Upsert(KT.Entry("A"));
        }
        // ohne Testschalter: der echte freie Platz wird gemessen
        Assert.NotNull(FileIO.FreeSpace(f.Store.DirectoryPath));
    }

    [Fact]
    public void Fehlende_Datei_wird_beim_Speichern_neu_geschrieben()
    {
        using var f = KernVault.Make();
        File.Delete(f.Store.VaultPath);
        f.Vault.Upsert(KT.Entry("A"));
        Assert.True(f.Store.VaultExists);
        f.Vault.Lock();
        Assert.Equal(["A"], KT.Unlocked(f.Store.Unlock(KT.Pw1))!.Entries.Select(x => x.Title));
    }

    [Fact]
    public void Rechte_nur_fuer_den_Benutzer_keine_Temp_Reste()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("A"));
        Assert.Empty(f.TempFiles());
        if (OperatingSystem.IsWindows()) { return; }
        const UnixFileMode Dir700 = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        const UnixFileMode File600 = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        Assert.Equal(Dir700, File.GetUnixFileMode(f.Store.DirectoryPath));
        Assert.Equal(File600, File.GetUnixFileMode(f.Store.VaultPath));
        Assert.Equal(Dir700, File.GetUnixFileMode(f.Store.BackupRoot));
        Assert.Equal(Dir700, File.GetUnixFileMode(f.Store.BackupDirectory(f.Vault.VaultId)));
        foreach (var b in f.LocalBackups()) { Assert.Equal(File600, File.GetUnixFileMode(b.Path)); }
    }
}

/// <summary>Sicherungen (Gegenstück zur Suite „Sicherungen“).</summary>
public class SicherungenTests
{
    [Fact]
    public void Namensschema_und_Sicherung_pro_Speichern()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("A"));
        f.Vault.Upsert(KT.Entry("B"));
        var list = f.LocalBackups();
        Assert.Equal([2UL, 1UL], list.Select(b => b.Generation));
        foreach (var b in list)
        {
            var name = Path.GetFileName(b.Path);
            var parsed = BackupNaming.ParseLocal(name)!;
            Assert.Equal(b.Generation, parsed.Generation);
            Assert.Null(parsed.Reason);
            Assert.Equal(f.Vault.VaultId, b.VaultId);
            Assert.Equal(Bytes.GuidText(f.Vault.VaultId), Path.GetFileName(Path.GetDirectoryName(b.Path)));
            Assert.Equal("20261016-120000-g1-abcd.siegel".Length + b.Generation.ToString(System.Globalization.CultureInfo.InvariantCulture).Length - 1,
                name.Length);
        }
        var fixedTime = KT.At(1_792_000_000);
        var n = BackupNaming.LocalName(fixedTime, 42, "neues-kit");
        var p = BackupNaming.ParseLocal(n)!;
        Assert.Equal(fixedTime, p.Date);
        Assert.Equal(42UL, p.Generation);
        Assert.Equal("neues-kit", p.Reason);
        Assert.StartsWith(BackupNaming.Timestamp(fixedTime) + "-g42-", n, StringComparison.Ordinal);
        Assert.EndsWith("-vor-neues-kit.siegel", n, StringComparison.Ordinal);
        Assert.Null(BackupNaming.ParseLocal("Notizen.txt"));
        Assert.Null(BackupNaming.ParseLocal("20261016-120000-gX-abcd.siegel"));
        Assert.Null(BackupNaming.ParseLocal("20261016-120000-g1-abcd-nach-x.siegel"));
        Assert.Null(BackupNaming.ParseLocal("20261016-120000-g1-abcd-vor.siegel"));
        Assert.Equal("migration-v1", BackupNaming.ParseLocal("20261016-120000-g1-abcd-vor-migration-v1.siegel")!.Reason);
        // Wie Foundations nachsichtiger Kalender: Monat 13 und Tag 0 werden übertragen.
        Assert.Equal(new DateTimeOffset(2027, 1, 31, 0, 0, 0, TimeSpan.Zero), BackupNaming.ParseTimestamp("20261331", "000000"));
        Assert.Equal(new DateTimeOffset(2026, 2, 28, 0, 0, 0, TimeSpan.Zero), BackupNaming.ParseTimestamp("20260300", "000000"));
        Assert.Equal(new DateTimeOffset(2026, 10, 17, 1, 0, 0, TimeSpan.Zero), BackupNaming.ParseTimestamp("20261016", "250000"));
        Assert.Equal("20261016-120000", BackupNaming.Timestamp(new DateTimeOffset(2026, 10, 16, 14, 0, 0, 999, TimeSpan.FromHours(2))));
    }

    [Fact]
    public void Externe_Namen()
    {
        var id = Guid.Parse("D4F9B640-FECB-4BAB-A72D-28DBA1D1636D");
        var t = KT.At(1_792_000_000);
        var n = BackupNaming.ExternalName(id, t);
        Assert.Equal("Siegel-d4f9b640-" + BackupNaming.Timestamp(t) + ".siegel", n);
        Assert.Equal(t, BackupNaming.ParseExternal(n, BackupNaming.ExternalPrefix(id)));
        Assert.Equal(t, BackupNaming.ParseAnyExternal(n));
        Assert.Null(BackupNaming.ParseExternal(n, BackupNaming.ExternalPrefix(Guid.NewGuid())));
        Assert.Null(BackupNaming.ParseAnyExternal("Siegel-xyz.siegel"));
        Assert.Null(BackupNaming.ParseAnyExternal("Siegel-d4f9b640-20261016.siegel"));
    }

    [Fact]
    public void Sicherungsnamen_kollidieren_nie()
    {
        using var f = KernVault.Make();
        var fixedTime = KT.At(1_792_000_000);
        using (KT.Now(fixedTime))
        {
            for (var i = 0; i < 300; i++) { f.Store.BackupNowForTesting(null); }
        }
        var names = f.BackupFileNames();
        Assert.Equal(300, names.Count);
        foreach (var n in names)
        {
            var p = BackupNaming.ParseLocal(n)!;
            Assert.Equal(1UL, p.Generation);
            Assert.Equal(fixedTime, p.Date);
        }
    }

    [Fact]
    public void Ausduennung_rein()
    {
        var now = KT.At(1_792_000_000);
        var items = new List<BackupThinning.Item>();
        var n = 0;
        string Add(double ageSeconds, bool pinned = false)
        {
            n++;
            var u = "/tmp/b" + n + ".siegel";
            items.Add(new BackupThinning.Item(u, now.AddSeconds(-ageSeconds), pinned));
            return u;
        }
        const double H = 3600;
        const double D = 86_400;
        var recent = new List<string>();
        for (var i = 0; i < 60; i++) { recent.Add(Add(i * 0.5 * H + 60)); }
        var daily = new List<string[]>();
        for (var day = 3; day <= 40; day++) { daily.Add([.. Enumerable.Range(0, 3).Select(k => Add(day * D + k * H))]); }
        var pinnedOld = Add(1000 * D, true);
        var pinnedNew = Add(5 * D + 30, true);
        var veryOld = Add(800 * D);
        var oldest = Add(2000 * D);
        var midA = Add(100 * D);
        var midB = Add(100 * D + 600);
        var year = Add(400 * D);

        var delete = BackupThinning.SelectForDeletion(items, now).ToHashSet();
        Assert.DoesNotContain(pinnedOld, delete);
        Assert.DoesNotContain(pinnedNew, delete);
        Assert.DoesNotContain(oldest, delete);
        Assert.Contains(veryOld, delete);
        Assert.DoesNotContain(year, delete);
        Assert.DoesNotContain(midA, delete);
        Assert.Contains(midB, delete);
        Assert.All(recent.Take(50), r => Assert.DoesNotContain(r, delete));
        for (var k = 0; k < daily.Count; k++)
        {
            if (k + 3 > 29) { continue; }
            Assert.DoesNotContain(daily[k][0], delete);
            Assert.Contains(daily[k][2], delete);
        }
        Assert.True(items.Count(i => !delete.Contains(i.Path)) < items.Count);
        Assert.Empty(BackupThinning.SelectForDeletion([], now));
    }

    [Fact]
    public void Ausduennung_im_Ordner_nach_dem_Speichern()
    {
        using var f = KernVault.Make();
        var dir = f.Store.BackupDirectory(f.Vault.VaultId);
        FileIO.EnsureDirectory(dir);
        var bytes = f.FileBytes();
        var now = DateTimeOffset.UtcNow;
        var names = new Dictionary<double, string>();
        foreach (var days in new[] { 1000.0, 900, 800, 3, 3.1, 3.2 })
        {
            var name = BackupNaming.LocalName(now.AddDays(-days), 1, null);
            FileIO.WriteExclusive(Path.Combine(dir, name), bytes);
            names[days] = name;
        }
        var pinned = BackupNaming.LocalName(now.AddDays(-700), 1, "import");
        FileIO.WriteExclusive(Path.Combine(dir, pinned), bytes);
        FileIO.WriteExclusive(Path.Combine(dir, "fremd.txt"), [1, 2, 3]);
        f.Vault.Upsert(KT.Entry("A"));
        var after = f.BackupFileNames();
        Assert.Contains(pinned, after);
        Assert.Contains("fremd.txt", after);
        Assert.Contains(names[1000], after);
        Assert.DoesNotContain(names[900], after);
        Assert.DoesNotContain(names[800], after);
        Assert.Contains(names[3], after);
    }

    [Fact]
    public void Wiederherstellung_einer_alten_Generation_behaelt_neuere()
    {
        using var f = KernVault.Make();
        for (var i = 0; i < 5; i++) { f.Vault.Upsert(KT.Entry("E" + i)); }
        var namesBefore = f.BackupFileNames();
        var gen2 = f.LocalBackups().First(b => b.Generation == 2);
        f.Vault.Lock();
        var restored = f.Store.RestoreBackup(gen2, KT.Pw1);
        Assert.Equal(["E0"], restored.Entries.Select(x => x.Title));
        Assert.Equal(7UL, restored.Generation);
        Assert.True(namesBefore.IsSubsetOf(f.BackupFileNames()));
        var pinned = f.LocalBackups().Where(b => b.Reason == "wiederherstellung").ToList();
        Assert.Single(pinned);
        Assert.Equal(6UL, pinned[0].Generation);
        Assert.NotEqual(VaultFile.Parse(File.ReadAllBytes(gen2.Path)).Header.Salt, f.ParsedFile().Header.Salt);
        restored.Lock();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Beschaedigt_neueste_lesbare_Sicherung(bool corruptHeader)
    {
        using var f = KernVault.Make();
        for (var i = 0; i < 3; i++) { f.Vault.Upsert(KT.Entry("E" + i)); }
        var newest = f.LocalBackups()[0];
        Assert.Equal(3UL, newest.Generation);
        var nb = File.ReadAllBytes(newest.Path);
        nb[nb.Length / 2] ^= 1;
        File.Delete(newest.Path);
        File.WriteAllBytes(newest.Path, nb);
        var vb = f.FileBytes();
        vb[corruptHeader ? 10 : vb.Length / 2] ^= 1;
        f.WriteFile(vb);
        f.Vault.Lock();
        KT.Corrupt("file.checksum", () => f.Store.Unlock(KT.Pw1));
        KT.Throws(SiegelErrorCode.WrongPassword, () => f.Store.RestoreNewestReadableBackup(KT.Pw2));
        var (v, used) = f.Store.RestoreNewestReadableBackup(KT.Pw1);
        Assert.Equal(2UL, used.Generation);
        Assert.Equal(["E0"], v.Entries.Select(x => x.Title));
        Assert.Equal(5UL, v.Generation);
        var quarantined = FileIO.ListFiles(f.Store.BackupRoot).Where(p => Path.GetFileName(p).StartsWith(BackupNaming.QuarantinePrefix, StringComparison.Ordinal)).ToList();
        Assert.Single(quarantined);
        Assert.Equal(vb, File.ReadAllBytes(quarantined[0]));
        Assert.True(File.Exists(newest.Path));
        v.Lock();
        Assert.NotNull(KT.Unlocked(f.Store.Unlock(KT.Pw1)));
    }

    [Fact]
    public void Quarantaene_verschiebt_loescht_nie()
    {
        using var f = KernVault.Make();
        var bytes = f.FileBytes();
        var moved = f.Store.QuarantineCorruptVault();
        Assert.False(f.Store.VaultExists);
        Assert.Equal(Path.GetFullPath(f.Store.BackupRoot), Path.GetDirectoryName(moved));
        Assert.StartsWith("beschaedigt-", Path.GetFileName(moved), StringComparison.Ordinal);
        Assert.Equal(bytes, File.ReadAllBytes(moved));
        KT.Throws(SiegelErrorCode.VaultMissing, () => f.Store.QuarantineCorruptVault());
        f.WriteFile(bytes);
        var second = f.Store.QuarantineCorruptVault();
        Assert.NotEqual(moved, second);
        Assert.Empty(f.Store.Backups());
    }

    [Fact]
    public void Tresor_fehlt_wiederherstellen_aus_der_Liste()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("A"));
        f.Vault.Upsert(KT.Entry("B"));
        f.Vault.Lock();
        File.Delete(f.Store.VaultPath);
        var list = f.Store.Backups();
        Assert.Equal(2, list.Count);
        Assert.All(list, b => Assert.Equal(f.Vault.VaultId, b.VaultId));
        var v = f.Store.RestoreBackup(list[0], KT.Pw1);
        Assert.Equal(["A"], v.Entries.Select(x => x.Title));
        Assert.True(f.Store.VaultExists);
        v.Lock();
    }

    [Fact]
    public void Zweiter_Sicherungsort_hoechstens_einmal_pro_Stunde()
    {
        using var f = KernVault.Make();
        var ext = f.Dir.Sub("USB");
        f.Store.SecondaryBackupDirectory = ext;
        var t0 = KT.At(1_792_000_000);
        using (KT.Now(t0)) { f.Vault.Upsert(KT.Entry("A")); }
        Assert.Equal(SecondaryBackupResult.Written(t0), f.Store.LastSecondaryBackupResult);
        using (KT.Now(t0.AddSeconds(600))) { f.Vault.Upsert(KT.Entry("B")); }
        Assert.Equal(SecondaryBackupResult.NotDue, f.Store.LastSecondaryBackupResult);
        var files = FileIO.ListFiles(ext);
        Assert.Single(files);
        Assert.StartsWith("Siegel-" + KT.Hex(Bytes.OfGuid(f.Vault.VaultId))[..8] + "-", Path.GetFileName(files[0]), StringComparison.Ordinal);
        using (KT.Now(t0.AddHours(2))) { f.Vault.Upsert(KT.Entry("C")); }
        files = FileIO.ListFiles(ext);
        Assert.Equal(2, files.Count);
        Assert.All(files, p => Assert.False(p.EndsWith(".tmp", StringComparison.Ordinal)));
        var external = f.Store.Backups().Where(b => b.IsExternal).ToList();
        Assert.Equal(2, external.Count);
        Assert.All(external, b => Assert.Equal(f.Vault.VaultId, b.VaultId));
        Assert.Equal([4UL, 2UL], external.Select(b => b.Generation));
        f.Vault.Lock();
        var v = f.Store.RestoreBackup(external[^1], KT.Pw1);
        Assert.Equal(["A"], v.Entries.Select(x => x.Title));
        v.Lock();
        f.Store.SecondaryBackupDirectory = null;
        Assert.All(f.Store.Backups(), b => Assert.False(b.IsExternal));
        // nicht erreichbarer Ort
        f.Store.SecondaryBackupDirectory = Path.Combine(f.Dir.Path, "gibtsnicht");
        var again = KT.AnyVault(f.Store.Unlock(KT.Pw1));
        again.Upsert(KT.Entry("D"));
        Assert.Equal(SecondaryBackupResult.Unreachable, f.Store.LastSecondaryBackupResult);
        again.Lock();
    }

    [Fact]
    public void PurgeBackups_entfernt_alle_dieser_vaultID_und_legt_eine_neue_an()
    {
        using var f = KernVault.Make();
        using var other = KernVault.Make();
        other.Vault.Upsert(KT.Entry("Fremd"));
        var ext = f.Dir.Sub("Extern");
        f.Store.SecondaryBackupDirectory = ext;
        f.Vault.Upsert(KT.Entry("A"));
        f.Vault.ChangeMasterPassword(KT.Pw1, KT.Pw2);
        f.Vault.Upsert(KT.Entry("B"));
        Assert.Equal(3, f.LocalBackups().Count);
        Assert.Contains(f.LocalBackups(), b => b.Reason == "passwortwechsel");
        var foreignDir = f.Store.BackupDirectory(other.Vault.VaultId);
        FileIO.EnsureDirectory(foreignDir);
        foreach (var b in other.LocalBackups()) { File.Copy(b.Path, Path.Combine(foreignDir, Path.GetFileName(b.Path))); }
        var foreignCount = FileIO.ListFiles(foreignDir).Count;
        var report = f.Vault.PurgeBackups();
        Assert.True(report.IsComplete);
        Assert.True(report.Removed >= 3);
        var left = f.LocalBackups();
        Assert.Single(left);
        Assert.Equal(f.Vault.Generation, left[0].Generation);
        Assert.Null(left[0].Reason);
        Assert.Single(FileIO.ListFiles(ext));
        Assert.Equal(foreignCount, FileIO.ListFiles(foreignDir).Count);
        f.Vault.Lock();
        var v = f.Store.RestoreBackup(left[0], KT.Pw2);
        Assert.Equal(new HashSet<string> { "A", "B" }, v.Entries.Select(x => x.Title).ToHashSet());
        v.Lock();
    }

    [Fact]
    public void PurgeBackups_meldet_nicht_lesbaren_zweiten_Ort_und_holt_spaeter_nach()
    {
        using var f = KernVault.Make();
        var ext = f.Dir.Sub("Stick");
        f.Store.SecondaryBackupDirectory = ext;
        var t0 = KT.At(1_792_000_000);
        using (KT.Now(t0)) { f.Vault.Upsert(KT.Entry("A")); }
        Assert.Single(FileIO.ListFiles(ext));
        f.Store.SecondaryBackupDirectory = Path.Combine(f.Dir.Path, "ausgesteckt");
        var report = f.Vault.PurgeBackups();
        Assert.True(report.SecondaryUnreachable);
        Assert.False(report.IsComplete);
        // wieder eingesteckt: Entfernen nachholen (vor t0 + 1 s), frische Kopie
        f.Store.SecondaryBackupDirectory = ext;
        var later = f.Store.PurgeSecondaryBackups(f.Vault.VaultId, t0.AddSeconds(1));
        Assert.Equal(1, later.Removed);
        Assert.True(later.IsComplete);
        var files = FileIO.ListFiles(ext);
        Assert.Single(files);
        Assert.NotEqual(t0, BackupNaming.ParseAnyExternal(Path.GetFileName(files[0])));
        f.Store.SecondaryBackupDirectory = null;
        Assert.True(f.Store.PurgeSecondaryBackups(f.Vault.VaultId, t0).SecondaryUnreachable);
    }

    [Fact]
    public void Export_und_Einspielen_rotiert_den_DEK()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("A"));
        var target = Path.Combine(f.Dir.Path, "Kopie.siegel");
        f.Store.ExportBackup(target);
        Assert.Equal(f.FileBytes(), File.ReadAllBytes(target));
        f.Store.ExportBackup(target);
        using var dir = new KernTempDir();
        var other = VaultStore.ForTesting(dir.Sub("Siegel"), new InMemoryRollbackGuard());
        KT.Throws(SiegelErrorCode.WrongPassword, () => other.ImportBackup(target, KT.Pw2));
        Assert.False(other.VaultExists);
        var v = other.ImportBackup(target, KT.Pw1);
        Assert.Equal(["A"], v.Entries.Select(x => x.Title));
        Assert.Equal(f.Vault.VaultId, v.VaultId);
        Assert.Equal(3UL, v.Generation);
        using (var d1 = v.DekForTesting())
        using (var d2 = f.Vault.DekForTesting())
        {
            Assert.False(d1.ConstantTimeEquals(d2));
        }
        Assert.Equal(RecoveryCodeMatch.Exact, other.CheckRecoveryCode(f.Code));
        var b = File.ReadAllBytes(target);
        b[100] ^= 1;
        File.Delete(target);
        File.WriteAllBytes(target, b);
        KT.Corrupt("file.checksum", () => other.ImportBackup(target, KT.Pw1));
        KT.Throws(SiegelErrorCode.Io, "backup.missing", () => other.ImportBackup(Path.Combine(dir.Path, "gibtsnicht.siegel"), KT.Pw1));
        v.Lock();
    }

    [Fact]
    public void Export_ohne_Nachbardatei_wenn_der_Ordner_schreibgeschuetzt_ist()
    {
        if (OperatingSystem.IsWindows()) { return; }
        using var f = KernVault.Make();
        var dir = f.Dir.Sub("NurDatei");
        var target = Path.Combine(dir, "Sicherung.siegel");
        File.WriteAllBytes(target, [0]);
        File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserExecute);
        try
        {
            f.Store.ExportBackup(target);
            Assert.Equal(f.FileBytes(), File.ReadAllBytes(target));
            Assert.Single(Directory.GetFiles(dir));
        }
        finally
        {
            File.SetUnixFileMode(dir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }
        Assert.Equal(f.Vault.VaultId, VaultStore.ReadBackupInfo(target).VaultId);
        KT.Throws(SiegelErrorCode.Io, "backup.missing", () => VaultStore.ReadBackupInfo(Path.Combine(dir, "fehlt.siegel")));
    }

    [Fact]
    public void Threadsicher_parallele_Aenderungen_gehen_nicht_verloren()
    {
        using var f = KernVault.Make();
        var errors = 0;
        var vault = f.Vault;
        Parallel.For(0, 8, t =>
        {
            for (var i = 0; i < 10; i++)
            {
                try
                {
                    vault.Upsert(KT.Entry("T" + t + "-" + i));
                }
                catch (SiegelException)
                {
                    Interlocked.Increment(ref errors);
                }
                _ = vault.Entries.Count;
                _ = vault.MasterPasswordReuse;
            }
        });
        Assert.Equal(0, errors);
        Assert.Equal(80, f.Vault.Entries.Count);
        Assert.Equal(81UL, f.Vault.Generation);
        f.Vault.Lock();
        Assert.Equal(80, KT.Unlocked(f.Store.Unlock(KT.Pw1))!.Entries.Count);
    }

    [Fact]
    public void Temp_Reste_werden_beim_ersten_Speichern_aufgeraeumt()
    {
        using var f = KernVault.Make();
        var old = Path.Combine(f.Store.DirectoryPath, ".Tresor.siegel.deadbeef.tmp");
        var fresh = Path.Combine(f.Store.DirectoryPath, ".Tresor.siegel.cafebabe.tmp");
        File.WriteAllBytes(old, [1]);
        File.SetLastWriteTimeUtc(old, DateTime.UtcNow.AddMinutes(-5));
        File.WriteAllBytes(fresh, [2]);
        var store = f.ReopenStore();
        var v = KT.AnyVault(store.Unlock(KT.Pw1));
        v.Upsert(KT.Entry("A"));
        Assert.False(File.Exists(old));
        Assert.True(File.Exists(fresh));
        v.Lock();
    }
}

/// <summary>KEK-Wiederverwendung (gleiches Salz + Parameter → kein zweites Argon2).</summary>
public class KekWiederverwendungTests
{
    [Fact]
    public void Neueste_lesbare_Sicherung_nur_ein_Argon2_zum_Oeffnen()
    {
        using var f = KernVault.Make();
        for (var i = 0; i < 4; i++) { f.Vault.Upsert(KT.Entry("E" + i)); }
        f.Vault.Lock();
        var backups = f.LocalBackups();
        Assert.Equal(4, backups.Count);
        foreach (var b in backups.Take(3))
        {
            var bytes = File.ReadAllBytes(b.Path);
            bytes[KT.HeaderLength(bytes) + VaultSlots.Size + 60] ^= 1;
            File.Delete(b.Path);
            File.WriteAllBytes(b.Path, KT.WithFixedChecksum(bytes));
        }
        var vb = f.FileBytes();
        vb[vb.Length / 2] ^= 1;
        f.WriteFile(vb);
        var counter = new TestHooks.Counter();
        UnlockedVault v;
        BackupInfo used;
        using (KT.Hook(() => TestHooks.KdfCounter = counter, () => TestHooks.KdfCounter = null))
        {
            (v, used) = f.Store.RestoreNewestReadableBackup(KT.Pw1);
        }
        Assert.Equal(1UL, used.Generation);
        Assert.Empty(v.Entries);
        Assert.Equal(2, counter.Value);
        v.Lock();
    }

    [Fact]
    public void Entsperren_bei_beschaedigtem_Inhalt_einmal_neu_lesen()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("A"));
        var bytes = f.FileBytes();
        bytes[KT.HeaderLength(bytes) + VaultSlots.Size + 60] ^= 1;
        f.WriteFile(KT.WithFixedChecksum(bytes));
        var counter = new TestHooks.Counter();
        using (KT.Hook(() => TestHooks.KdfCounter = counter, () => TestHooks.KdfCounter = null))
        {
            KT.Corrupt("payload.auth", () => f.Store.Unlock(KT.Pw1));
        }
        Assert.Equal(1, counter.Value);
    }
}
#endif
