#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using Siegel.Modell;
using Siegel.Werkzeuge;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Core.Tests.Kern;

/// <summary>
/// Robustheits-Befunde vom 18.10.2026 (Windows, Etappe 1, SPEC-WINDOWS W12 W1.3): robust-1 (fremde Sperren beim
/// Umbenennen/Löschen), robust-2 (HostKey ohne fremde Ausnahme, wie Swift), robust-3 (Totmann-Frist am Jahr-9999-Rand),
/// robust-4 (Ordner-ACL im AppContainer), robust-5 (übergrosse beschädigte Tresordatei beiseitelegen), robust-6 (lange
/// Pfade für MoveFileExW), robust-7 (quadratische IDNA/NFC in der CSV), robust-8 (doppelte Eintrags-Kennungen).
/// Die Windows-Zweige (Sperren, ACL, MAX_PATH) prüfen die mit „Windows_“ beginnenden Tests erst unter Windows; auf dem
/// Mac laufen dort nur die plattformneutralen Teile.
/// </summary>
public class RobustBefundeWindowsTests
{
    private static string U(int scalar) => char.ConvertFromUtf32(scalar);

    // MARK: robust-1

    [Fact]
    public void Wiederholung_bei_fremder_Sperre_mit_wachsender_Pause()
    {
        var antworten = new Queue<int>([FileIO.ErrorSharingViolation, FileIO.ErrorAccessDenied, FileIO.ErrorSharingViolation, 0]);
        var pausen = new List<int>();
        var zeit = TimeSpan.Zero;
        var ergebnis = FileIO.RetryTransient(() => antworten.Dequeue(), ms => { pausen.Add(ms); zeit += TimeSpan.FromMilliseconds(ms); },
            () => zeit);
        Assert.Equal(0, ergebnis);
        Assert.Equal([10, 20, 40], pausen);

        // Andere Fehler (z. B. ERROR_FILE_NOT_FOUND, ERROR_FILE_EXISTS) sofort, ohne Pause
        pausen.Clear();
        Assert.Equal(2, FileIO.RetryTransient(() => 2, pausen.Add, () => TimeSpan.Zero));
        Assert.Equal(80, FileIO.RetryTransient(() => 80, pausen.Add, () => TimeSpan.Zero));
        Assert.Empty(pausen);

        // Dauerhafte Sperre: nach etwa 2 s aufgeben, Pausen höchstens 500 ms, letzter Fehler zurück
        zeit = TimeSpan.Zero;
        var versuche = 0;
        ergebnis = FileIO.RetryTransient(() => { versuche++; return FileIO.ErrorAccessDenied; },
            ms => { pausen.Add(ms); zeit += TimeSpan.FromMilliseconds(ms); }, () => zeit);
        Assert.Equal(FileIO.ErrorAccessDenied, ergebnis);
        Assert.Equal(FileIO.TransientRetryLimit, zeit);
        Assert.All(pausen, p => Assert.InRange(p, 1, 500));
        Assert.Equal(pausen.Count + 1, versuche);
        Assert.Equal([10, 20, 40, 80, 160, 320, 500, 500, 370], pausen);
    }

    [Fact]
    public void Win32_Fehler_aus_Dateiausnahmen()
    {
        Assert.Equal(32, FileIO.Win32ErrorOf(new IOException("x", unchecked((int)0x80070020))));
        Assert.Equal(5, FileIO.Win32ErrorOf(new UnauthorizedAccessException()));
        Assert.Equal(-1, FileIO.Win32ErrorOf(new IOException("x")));
        Assert.True(FileIO.IsTransientSharingError(5) && FileIO.IsTransientSharingError(32));
        Assert.False(FileIO.IsTransientSharingError(33) || FileIO.IsTransientSharingError(80) || FileIO.IsTransientSharingError(0));
    }

    [Fact]
    public void Temp_entfernen_ohne_Fehler()
    {
        using var d = new KernTempDir();
        var tmp = Path.Combine(d.Path, ".x.tmp");
        FileIO.WriteExclusive(tmp, [1, 2, 3]);
        FileIO.RemoveTemp(tmp);
        Assert.False(File.Exists(tmp));
        FileIO.RemoveTemp(tmp); // fehlt schon: kein Fehler
    }

    /// <summary>Wie ein Virenscanner: Ziel bzw. Quelle kurz ohne FILE_SHARE_DELETE offen. Ersetzen, exklusives
    /// Umbenennen und das Entfernen eines Temps warten das ab; eine dauerhafte Sperre ergibt nach etwa 2 s
    /// <c>Io("file.rename")</c>, und beide Dateien bleiben, wie sie waren.</summary>
    [Fact]
    public void Windows_Ersetzen_und_Entfernen_warten_auf_fremde_Sperre()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        using var d = new KernTempDir();
        var src = Path.Combine(d.Path, ".Tresor.siegel.0001.tmp");
        var dst = Path.Combine(d.Path, "Tresor.siegel");
        FileIO.WriteExclusive(src, [1, 2, 3]);
        FileIO.WriteExclusive(dst, [9]);
        HaltenUndFreigeben(dst, 300, () => FileIO.Rename(src, dst));
        Assert.Equal([1, 2, 3], File.ReadAllBytes(dst));
        Assert.False(File.Exists(src));

        var quelle = Path.Combine(d.Path, "q.tmp");
        var ziel = Path.Combine(d.Path, "neu.siegel");
        FileIO.WriteExclusive(quelle, [4]);
        HaltenUndFreigeben(quelle, 300, () => FileIO.RenameExclusive(quelle, ziel));
        Assert.Equal([4], File.ReadAllBytes(ziel));

        var temp = Path.Combine(d.Path, ".zustand.json.0002.tmp");
        FileIO.WriteExclusive(temp, [5]);
        HaltenUndFreigeben(temp, 300, () => FileIO.RemoveTemp(temp));
        Assert.False(File.Exists(temp));

        // dauerhaft gesperrt
        FileIO.WriteExclusive(src, [7]);
        using (new FileStream(dst, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            var uhr = Stopwatch.StartNew();
            KT.Throws(SiegelErrorCode.Io, "file.rename", () => FileIO.Rename(src, dst));
            Assert.True(uhr.Elapsed >= TimeSpan.FromSeconds(1.5));
        }
        Assert.Equal([1, 2, 3], File.ReadAllBytes(dst));
        Assert.Equal([7], File.ReadAllBytes(src));
    }

    private static void HaltenUndFreigeben(string path, int ms, Action body)
    {
        var fremd = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var freigabe = Task.Run(async () =>
        {
            await Task.Delay(ms);
            await fremd.DisposeAsync();
        });
        try
        {
            body();
        }
        finally
        {
            freigabe.Wait();
        }
    }

    // MARK: robust-2

    /// <summary>Hosts, die IDNA ablehnt, ergeben den Wert wie Swift (dort ist <c>URL(string:)</c> nil, also die getrimmte
    /// Adresse klein; gemessen mit Swift auf macOS 26.7) und nie eine fremde Ausnahme.</summary>
    [Fact]
    public void HostKey_wirft_nie_und_rechnet_wie_Swift()
    {
        string[] boese = ["https://bank." + U(0xFFFD) + ".ch", "https://bank." + U(0xE000) + ".ch", "https://" + U(0x0378) + ".ch"];
        foreach (var url in boese) { Assert.Equal(url, UnlockedVault.HostKey(url)); }
        Assert.Equal("https://bank." + U(0xFFFD) + ".ch", UnlockedVault.HostKey("  HTTPS://Bank." + U(0xFFFD) + ".CH \n"));
        // Swift: in "https://" + U+200D + ".ch" gehört U+200D zum zweiten "/", "://" kommt als Character-Folge nicht vor;
        // also "https://" davor, und der Host ist "https".
        Assert.Equal("https", UnlockedVault.HostKey("https://" + U(0x200D) + ".ch"));
        // weitere Werte, mit Swift gemessen
        Assert.Equal("bank..ch", UnlockedVault.HostKey("https://bank..ch/login"));
        Assert.Equal("::1", UnlockedVault.HostKey("https://[::1]:80/"));
        Assert.Equal("example.com", UnlockedVault.HostKey("https://ex%41mple.com/"));
        Assert.Equal("xn--bcher-kva.de", UnlockedVault.HostKey("https://B" + U(0xDC) + "cher.de"));
        Assert.Equal("xn--istanbul-o0e.com", UnlockedVault.HostKey("https://" + U(0x130) + "stanbul.com"));
        Assert.Equal("xn--istanbul-o0e", UnlockedVault.HostKey(U(0x130) + "STANBUL"));
        Assert.Equal("x.ch", UnlockedVault.HostKey("https://x" + U(0xAD) + ".ch"));
    }

    [Fact]
    public void Swift_contains_nur_an_Character_Grenzen()
    {
        Assert.True(SwiftText.EnthaeltFolge("https://x.ch", "://"));
        Assert.True(SwiftText.EnthaeltFolge("a" + U(0x301) + "://x", "://"));    // Kombinationszeichen gehört zum a
        Assert.True(SwiftText.EnthaeltFolge("x\r://y", "://"));
        Assert.True(SwiftText.EnthaeltFolge("x" + U(0x1F1E6) + "://y", "://"));
        Assert.True(SwiftText.EnthaeltFolge("x" + U(0x200D) + "://y://z", "://"));
        Assert.False(SwiftText.EnthaeltFolge("https://" + U(0x200D) + ".ch", "://"));  // ZWJ hängt am "/"
        Assert.False(SwiftText.EnthaeltFolge("https://" + U(0x301) + "x.ch", "://"));  // Extend
        Assert.False(SwiftText.EnthaeltFolge("https://" + U(0x903) + "x.ch", "://"));  // SpacingMark
        Assert.False(SwiftText.EnthaeltFolge(U(0x600) + "://x", "://"));              // Prepend vor ":"
        Assert.False(SwiftText.EnthaeltFolge("https:/" + U(0x200B) + "/x", "://"));
        Assert.False(SwiftText.EnthaeltFolge("", "://"));
    }

    /// <summary>Ein gespeicherter Eintrag mit so einer Adresse blockiert keinen Import, und CSV-Zeilen mit so einem Host
    /// lassen sich importieren (vorher: <c>UriFormatException</c> aus ImportEntries, dauerhaft).</summary>
    [Fact]
    public void Import_mit_IDNA_fremden_Hosts()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("Alt", "u", "a", "https://bank." + U(0xFFFD) + ".ch"));
        f.Vault.Upsert(KT.Entry("Alt2", "z", "z", "https://" + U(0x200D) + ".ch"));
        var r = f.Vault.ImportEntries([KT.Entry("Y", "v", "b", "https://y.ch"), KT.Entry("Z", "w", "c", "")]);
        Assert.Equal((2, 0, 0), (r.Added, r.SkippedDuplicates, r.Conflicts));

        var csv = Encoding.UTF8.GetBytes("name,url,username,password,note\n"
            + "Bank,https://bank." + U(0x0378) + ".ch/login,anna,geheim,\n"
            + "B2,https://" + U(0xE000) + ".ch,bob,pw,\n"
            + "B3,https://bank." + U(0xFFFD) + ".ch,u,a,\n");
        var parsed = CsvImport.Parse(csv);
        Assert.Equal(3, parsed.Entries.Count);
        r = f.Vault.ImportEntries(parsed.Entries);
        // B3 ist eine Dublette des Bestands (gleicher Host-Schlüssel, Benutzer und Passwort)
        Assert.Equal((2, 1, 0), (r.Added, r.SkippedDuplicates, r.Conflicts));
        Assert.Equal(6, f.Vault.Entries.Count);
    }

    // MARK: robust-3

    private static byte[] MitLetzterEntsperrung(byte[] zustand, long sekunden)
    {
        var o = JsonNode.Parse(zustand)!.AsObject();
        o["lastGenuineUnlock"] = sekunden;
        return Encoding.UTF8.GetBytes(o.ToJsonString());
    }

    [Fact]
    public void Totmann_Frist_am_Jahr_9999_gesaettigt()
    {
        var s = new DestructionState(Guid.NewGuid())
        {
            Settings = new DestructionSettings(30, null, false),
            VKeyId = Guid.NewGuid(),
            LastGenuineUnlock = KT.At(1_800_000_000),
        };
        var d = DestructionState.Decode(MitLetzterEntsperrung(s.Encoded(), 253_402_000_000));
        var status = d.Status;
        Assert.Equal(Clock.Canonical(DateTimeOffset.MaxValue), status.Deadline);
        Assert.False(status.DeadlineIsNear(KT.At(1_800_000_000)));
        // normale Werte unverändert
        Assert.Equal(Clock.Canonical(KT.At(1_800_000_000).AddDays(30)), s.Status.Deadline);
        Assert.Equal(Clock.Canonical(DateTimeOffset.MinValue), Clock.AddDaysSaturating(DateTimeOffset.MinValue.AddDays(3), -7));
        Assert.Equal(Clock.Canonical(DateTimeOffset.MaxValue), Clock.AddDaysSaturating(DateTimeOffset.MaxValue, int.MaxValue));
    }

    [Fact]
    public async Task Totmann_Frist_am_Rand_gesperrt_und_entsperrt_ohne_fremde_Ausnahme()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        using (KT.Now(VH.T0)) { await v.Einrichten(new DestructionSettings(DeadmanDays: 30), [a.Id]); }
        v.Vault.Lock();
        File.WriteAllBytes(v.StatePath, MitLetzterEntsperrung(File.ReadAllBytes(v.StatePath), 253_402_000_000));
        Assert.Equal(Clock.Canonical(DateTimeOffset.MaxValue), v.Store.GetDestructionStatus().Deadline);
        Assert.False(v.Store.CheckDeadman(VH.T(1)));
        using (KT.Now(VH.T(VH.Tag))) { v.Reopen(); }
        // RecordGenuineUnlock behält den späteren Wert; Status bleibt ohne Ausnahme
        Assert.Equal(Clock.Canonical(DateTimeOffset.MaxValue), v.Vault.DestructionStatus.Deadline);
        Assert.Equal(Clock.Canonical(DateTimeOffset.MaxValue), v.Store.GetDestructionStatus().Deadline);
        Assert.Contains(Path.GetFileName(v.VPath), v.HardwareNames());
    }

    // MARK: robust-4

    [Fact]
    public void Ordner_ACL_Benutzer_Paket_und_SYSTEM()
    {
        Assert.Equal(["S-1-5-21-1-2-3-1001", "S-1-5-18"], FileIO.DirectoryAclSids("S-1-5-21-1-2-3-1001", null));
        Assert.Equal(["S-1-5-21-1-2-3-1001", "S-1-15-2-1-2-3-4-5-6-7", "S-1-5-18"],
            FileIO.DirectoryAclSids("S-1-5-21-1-2-3-1001", "S-1-15-2-1-2-3-4-5-6-7"));
    }

    /// <summary>Unix: neu angelegte Ordner 0700, ein bestehender Zielordner wird auf 0700 gesetzt (wie Swift), ausser mit
    /// <c>restrictExisting: false</c>; der Rollback-Wächter ändert die Rechte seines Elternordners nie.</summary>
    [Fact]
    public void Unix_Ordnerrechte_nur_wo_gewollt()
    {
        if (OperatingSystem.IsWindows()) { return; }
        using var d = new KernTempDir();
        const UnixFileMode offen = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
            | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute;
        const UnixFileMode privat = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        var neu = Path.Combine(d.Path, "a", "b");
        FileIO.EnsureDirectory(neu);
        Assert.Equal(privat, File.GetUnixFileMode(neu));
        Assert.Equal(privat, File.GetUnixFileMode(Path.Combine(d.Path, "a")));

        var bestehend = d.Sub("bestehend");
        File.SetUnixFileMode(bestehend, offen);
        FileIO.EnsureDirectory(bestehend, restrictExisting: false);
        Assert.Equal(offen, File.GetUnixFileMode(bestehend));
        FileIO.EnsureDirectory(bestehend);
        Assert.Equal(privat, File.GetUnixFileMode(bestehend));

        var eltern = d.Sub("LocalState");
        File.SetUnixFileMode(eltern, offen);
        var guard = new FileRollbackGuard(Path.Combine(eltern, "generationen.txt"));
        var id = Guid.NewGuid();
        guard.Record(id, 7);
        Assert.Equal(7UL, guard.LastSeenGeneration(id));
        Assert.Equal(offen, File.GetUnixFileMode(eltern));
        // fehlt der Elternordner, legt der Wächter ihn privat an
        var guard2 = new FileRollbackGuard(Path.Combine(d.Path, "Waechter", "generationen.txt"));
        guard2.Record(id, 1);
        Assert.Equal(privat, File.GetUnixFileMode(Path.Combine(d.Path, "Waechter")));
    }

    /// <summary>Windows: neu angelegte Ordner bekommen eine geschützte ACL (Benutzer, SYSTEM; im AppContainer zusätzlich
    /// die Paket-SID); die ACL bestehender Ordner (Tresorordner bei jedem Speichern, Elternordner des Wächters) bleibt
    /// unverändert. Der Test unter AppContainer selbst folgt in Etappe 2 (MSIX).</summary>
    [Fact]
    public void Windows_Ordner_ACL_nur_bei_neuen_Ordnern()
    {
        if (!OperatingSystem.IsWindows()) { return; }
        PruefeWindowsAcl();
    }

    [SupportedOSPlatform("windows")]
    private static void PruefeWindowsAcl()
    {
        using var d = new KernTempDir();
        var neu = Path.Combine(d.Path, "Siegel");
        FileIO.EnsureDirectory(neu);
        var acl = new DirectoryInfo(neu).GetAccessControl();
        Assert.True(acl.AreAccessRulesProtected);
        using var me = WindowsIdentity.GetCurrent();
        var sids = acl.GetAccessRules(true, true, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>()
            .Select(r => r.IdentityReference.Value).Order(StringComparer.Ordinal).ToArray();
        Assert.Equal(new[] { me.User!.Value, FileIO.LocalSystemSid }.Order(StringComparer.Ordinal).ToArray(), sids);

        var bestehend = d.Sub("LocalState");
        var vorher = new DirectoryInfo(bestehend).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        FileIO.EnsureDirectory(bestehend);
        new FileRollbackGuard(Path.Combine(bestehend, "generationen.txt")).Record(Guid.NewGuid(), 3);
        Assert.Equal(vorher, new DirectoryInfo(bestehend).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access));
        // Speichern im bestehenden Ordner lässt dessen ACL ebenso stehen
        using var f = KernVault.Make();
        var tresor = new DirectoryInfo(f.Store.DirectoryPath).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        f.Vault.Upsert(KT.Entry("E"));
        Assert.Equal(tresor, new DirectoryInfo(f.Store.DirectoryPath).GetAccessControl().GetSecurityDescriptorSddlForm(AccessControlSections.Access));
    }

    // MARK: robust-5

    private static void Uebergross(KernVault f)
    {
        using var s = new FileStream(f.Store.VaultPath, FileMode.Open, FileAccess.Write);
        s.SetLength(FileFormat.MaxFileBytes + 1L);
    }

    /// <summary>Eine über die Grenze gewachsene, unlesbare Tresordatei: „Neueste lesbare Sicherung öffnen“ gelingt direkt
    /// (wie auf dem Mac per clonefile), die Quarantäne-Kopie hat die volle Grösse.</summary>
    [Fact]
    public void Wiederherstellen_ueber_uebergrosse_beschaedigte_Datei()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("E0"));
        f.Vault.Upsert(KT.Entry("E1"));
        f.Vault.Lock();
        Uebergross(f);
        KT.Throws(SiegelErrorCode.CorruptFile, "file.length", () => f.Store.Unlock(KT.Pw1));
        var (v, _) = f.Store.RestoreNewestReadableBackup(KT.Pw1);
        Assert.Single(v.Entries);
        v.Lock();
        var beschaedigt = FileIO.ListFiles(f.Store.BackupsDirectory).Single(p => Path.GetFileName(p).StartsWith("beschaedigt-", StringComparison.Ordinal));
        Assert.Equal(FileFormat.MaxFileBytes + 1L, new FileInfo(beschaedigt).Length);
        Assert.True(new FileInfo(f.Store.VaultPath).Length < FileFormat.MaxFileBytes);
        Assert.Empty(f.TempFiles());
    }

    /// <summary>Reicht der Platz für die Kopie nicht (mindestens 64 MiB müssen danach frei bleiben), bricht das Ersetzen
    /// vor dem Schreiben ab; die beschädigte Datei bleibt unverändert, keine halbe Kopie.</summary>
    [Fact]
    public void Wiederherstellen_ohne_Platz_fuer_die_Kopie()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("E0"));
        f.Vault.Upsert(KT.Entry("E1"));
        f.Vault.Lock();
        Uebergross(f);
        using (KT.Hook(() => TestHooks.FreeSpaceOverride = VaultStore.MinimumFreeSpace + (1UL << 20), () => TestHooks.FreeSpaceOverride = null))
        {
            KT.Throws(SiegelErrorCode.NotEnoughDiskSpace, () => f.Store.RestoreNewestReadableBackup(KT.Pw1));
        }
        Assert.Equal(FileFormat.MaxFileBytes + 1L, new FileInfo(f.Store.VaultPath).Length);
        Assert.DoesNotContain(FileIO.ListFiles(f.Store.BackupsDirectory), p => Path.GetFileName(p).StartsWith("beschaedigt-", StringComparison.Ordinal));
        Assert.Empty(f.TempFiles());
    }

    [Fact]
    public void Gestreamte_Kopie_exklusiv_und_ohne_Link()
    {
        using var d = new KernTempDir();
        var src = Path.Combine(d.Path, "q.bin");
        var bytes = new byte[(3 << 20) + 17];
        new Random(5).NextBytes(bytes);
        File.WriteAllBytes(src, bytes);
        var dst = Path.Combine(d.Path, "z.bin");
        FileIO.CopyExclusiveStreamed(src, dst, 0);
        Assert.Equal(bytes, File.ReadAllBytes(dst));
        Assert.Throws<FileIO.ExistsException>(() => FileIO.CopyExclusiveStreamed(src, dst, 0));
        KT.Throws(SiegelErrorCode.Io, "backup.clone", () => FileIO.CopyExclusiveStreamed(Path.Combine(d.Path, "fehlt"), Path.Combine(d.Path, "z2"), 0));
        var link = Path.Combine(d.Path, "link.bin");
        File.CreateSymbolicLink(link, src);
        KT.Throws(SiegelErrorCode.Io, "file.read", () => FileIO.CopyExclusiveStreamed(link, Path.Combine(d.Path, "z3"), 0));
        Assert.False(File.Exists(Path.Combine(d.Path, "z3")));
    }

    // MARK: robust-6

    [Fact]
    public void Lange_Pfade_wie_dotnet_mit_Praefix()
    {
        var kurz = @"C:\Users\anna\AppData\Local\Siegel\Tresor.siegel";
        Assert.Equal(kurz, FileIO.ExtendedPathOf(kurz));
        var lang = @"C:\" + string.Join('\\', Enumerable.Repeat(new string('o', 40), 6)) + @"\Tresor.siegel";
        Assert.True(lang.Length >= 260);
        Assert.Equal(@"\\?\" + lang, FileIO.ExtendedPathOf(lang));
        var unc = @"\\nas\freigabe\" + string.Join('\\', Enumerable.Repeat(new string('o', 40), 6)) + @"\.Siegel-1.siegel.abcd.tmp";
        Assert.Equal(@"\\?\UNC\nas\freigabe\" + unc[@"\\nas\freigabe\".Length..], FileIO.ExtendedPathOf(unc));
        Assert.Equal(@"\\?\" + lang, FileIO.ExtendedPathOf(@"\\?\" + lang));
        Assert.Equal(@"\\.\" + lang[3..], FileIO.ExtendedPathOf(@"\\.\" + lang[3..]));
        Assert.Equal(@"\??\" + lang, FileIO.ExtendedPathOf(@"\??\" + lang));
        // Punkt bzw. Leerzeichen am Ende: wie .NET mit Präfix, damit FileStream und MoveFileExW dieselbe Datei meinen
        Assert.Equal(@"\\?\C:\x\export.siegel.", FileIO.ExtendedPathOf(@"C:\x\export.siegel."));
        Assert.Equal(@"\\?\C:\x\export ", FileIO.ExtendedPathOf(@"C:\x\export "));
    }

    /// <summary>Ein Ordnerpfad über 260 Zeichen: Ersetzen, exklusives Umbenennen, der zweite Sicherungsort und der
    /// Export gelingen (unter Windows vorher MAX_PATH-Grenze bei MoveFileExW → zweiter Ort immer Failed).</summary>
    [Fact]
    public void Tiefer_Ordner_ueber_260_Zeichen()
    {
        using var d = new KernTempDir();
        var tief = d.Path;
        while (tief.Length < 280) { tief = Path.Combine(tief, new string('o', 50)); }
        FileIO.EnsureDirectory(tief);
        var a = Path.Combine(tief, ".a.tmp");
        var b = Path.Combine(tief, "b.siegel");
        FileIO.WriteExclusive(a, [1]);
        FileIO.WriteExclusive(b, [2]);
        FileIO.Rename(a, b);
        Assert.Equal([1], File.ReadAllBytes(b));
        var c = Path.Combine(tief, "c.siegel");
        FileIO.RenameExclusive(b, c);
        Assert.Equal([1], File.ReadAllBytes(c));
        FileIO.WriteExclusive(b, [3]);
        Assert.Throws<FileIO.ExistsException>(() => FileIO.RenameExclusive(b, c));

        using var f = KernVault.Make();
        f.Store.SecondaryBackupDirectory = tief;
        f.Vault.Upsert(KT.Entry("E"));
        Assert.Equal(SecondaryBackupKind.Written, f.Store.LastSecondaryBackupResult?.Kind);
        Assert.Contains(FileIO.ListFiles(tief), p => Path.GetFileName(p).StartsWith("Siegel-", StringComparison.Ordinal));
        var export = Path.Combine(tief, "export.siegel");
        f.Store.ExportBackup(export);
        Assert.Equal(File.ReadAllBytes(f.Store.VaultPath), File.ReadAllBytes(export));
        Assert.DoesNotContain(FileIO.ListFiles(tief), p => p.EndsWith(".tmp", StringComparison.Ordinal));
    }

    // MARK: robust-7

    /// <summary>Grenzen von Foundation (gemessen auf macOS 26.7, gleiche Werte in Swift <c>CSVTitelGrenzenTests</c>):
    /// Host mit Nicht-ASCII bis 2048 Byte UTF-8 geht durch IDNA, darüber kein Host; ASCII-Host über 2048 Byte ohne
    /// Prozent-Kodierung kein Host, mit Prozent-Kodierung schon.</summary>
    [Fact]
    public void Titel_aus_URL_Grenzen_wie_Foundation()
    {
        var shy = U(0xAD);
        Assert.Equal("a.ch", CsvText.TitleFromUrl("https://a" + string.Concat(Enumerable.Repeat(shy, 1022)) + ".ch/x"));
        var zuLang = "https://a" + string.Concat(Enumerable.Repeat(shy, 1023)) + ".ch/x";
        Assert.Equal(zuLang, CsvText.TitleFromUrl(zuLang));
        Assert.Equal(new string('a', 2048), CsvText.TitleFromUrl("https://" + new string('a', 2048) + "/x"));
        var asciiZuLang = "https://" + new string('a', 2049) + "/x";
        Assert.Equal(asciiZuLang, CsvText.TitleFromUrl(asciiZuLang));
        Assert.Equal(new string('a', 2049), CsvText.TitleFromUrl("https://" + string.Concat(Enumerable.Repeat("%61", 2049)) + "/x"));
        var e57 = string.Concat(Enumerable.Repeat(U(0xE9), 57));
        Assert.Equal(e57 + ".ch", CsvText.TitleFromUrl("https://" + e57 + ".ch/"));
        var e58 = "https://" + string.Concat(Enumerable.Repeat(U(0xE9), 58)) + ".ch/";
        Assert.Equal(e58, CsvText.TitleFromUrl(e58));
        Assert.True(UrlHost.Zerlegen("https://a" + string.Concat(Enumerable.Repeat(shy, 1023)) + ".ch", out var teile));
        Assert.Null(UrlHost.AceForm(teile));
        Assert.Null(UrlHost.UnicodeForm(teile));
        Assert.True(UrlHost.Zerlegen("https://" + new string('a', 4096), out teile));
        Assert.Equal(new string('a', 4096), UrlHost.AceForm(teile));   // URL.host: ASCII ohne Grenze
        Assert.Null(UrlHost.UnicodeForm(teile));                        // URLComponents.host: nil
    }

    private static string Kombinationsfolge(int paare) => "e" + string.Concat(Enumerable.Repeat(U(0x301) + U(0x316), paare));

    /// <summary>Vorher quadratisch (128 000 Zeichen: 3,9 s für die URL, 7,7 s für die Kopfzeile; an der 16-MiB-Grenze
    /// Stunden). Jetzt linear, mit denselben Fehlercodes wie Swift.</summary>
    [Fact]
    public void CSV_lange_Kombinationsfolgen_linear()
    {
        var url = "https://" + Kombinationsfolge(150_000) + ".ch/";
        var uhr = Stopwatch.StartNew();
        Assert.Equal(url, CsvText.TitleFromUrl(url));
        var e = Assert.Throws<SiegelException>(() => CsvImport.Parse(Encoding.UTF8.GetBytes("name,url,username,password\n," + url + ",anna,pw\n")));
        Assert.Equal((SiegelErrorCode.CsvInvalid, "csv.field.title", 2), (e.Code, e.Detail, e.Line));

        var lang = Kombinationsfolge(150_000);
        var r = CsvImport.Parse(Encoding.UTF8.GetBytes("name,url,username,password," + lang + "," + lang + "\nBank,https://bank.ch,anna,pw,,\n"));
        Assert.True(uhr.Elapsed < TimeSpan.FromSeconds(5), uhr.Elapsed.ToString());
        Assert.Equal(CsvFormat.Chrome, r.Format);
        Assert.Equal("", Assert.Single(r.Entries).Notes);
    }

    /// <summary>Spaltennamen bis 256 Byte wie bisher (klein, NFC, Doppel → Fehler), darüber eine Zusatzspalte ohne Rolle,
    /// nicht verglichen (gleich in Swift <c>CSVKopfzeilenGrenzeTests</c>).</summary>
    [Fact]
    public void CSV_Kopfzeile_Grenze_256_Byte()
    {
        var x256 = new string('x', 256);
        var e = Assert.Throws<SiegelException>(() => CsvImport.Parse(Encoding.UTF8.GetBytes("name,url,username,password," + x256 + "," + x256.ToUpperInvariant() + "\n")));
        Assert.Equal("csv.header.duplicate", e.Detail);
        var x257 = new string('x', 257);
        var r = CsvImport.Parse(Encoding.UTF8.GetBytes("name,url,username,password," + x257 + "," + x257 + "\nA,https://a.ch,u,p,1,2\n"));
        Assert.Equal(x257 + ": 1\n" + x257 + ": 2", Assert.Single(r.Entries).Notes);
        // ein überlanger Name ist nie eine Rolle, auch mit Leerraum am Rand nur gemessen ohne ihn
        var urlLang = "url" + new string(' ', 300);
        r = CsvImport.Parse(Encoding.UTF8.GetBytes("name," + urlLang + ",username,password\nA,https://a.ch,u,p\n"));
        Assert.Equal("https://a.ch", Assert.Single(r.Entries).Url);
        var nameLang = "name" + new string('x', 253);
        e = Assert.Throws<SiegelException>(() => CsvImport.Parse(Encoding.UTF8.GetBytes(nameLang + ",url,username,password\n")));
        Assert.Equal("csv.header.unknown", e.Detail);
        // Grenze in Byte vor der Normalisierung: kanonisch gleiche Namen mit 255 und 256 Byte sind doppelt; mit 257 Byte
        // (ein é mehr zerlegt) zählt der zweite nicht mehr
        var nfc = string.Concat(Enumerable.Repeat(U(0xE9), 127)) + "x";
        var zerlegt1 = "e" + U(0x301) + string.Concat(Enumerable.Repeat(U(0xE9), 126)) + "x";
        var zerlegt2 = "e" + U(0x301) + "e" + U(0x301) + string.Concat(Enumerable.Repeat(U(0xE9), 125)) + "x";
        Assert.Equal((255, 256, 257), (Encoding.UTF8.GetByteCount(nfc), Encoding.UTF8.GetByteCount(zerlegt1), Encoding.UTF8.GetByteCount(zerlegt2)));
        e = Assert.Throws<SiegelException>(() => CsvImport.Parse(Encoding.UTF8.GetBytes("name,url,username,password," + nfc + "," + zerlegt1 + "\n")));
        Assert.Equal("csv.header.duplicate", e.Detail);
        r = CsvImport.Parse(Encoding.UTF8.GetBytes("name,url,username,password," + nfc + "," + zerlegt2 + "\nA,https://a.ch,u,p,1,2\n"));
        Assert.Equal(nfc + ": 1\n" + zerlegt2 + ": 2", Assert.Single(r.Entries).Notes);
    }

    // MARK: robust-8

    private const string Id = "06caf7c7-5bfa-4c75-abec-76e7488cc7a2";

    private static string Eintrag(string meta) =>
        "{\"created\":1,\"history\":[],\"modified\":1,\"notes\":\"\",\"password\":\"p\",\"title\":\"t\",\"url\":\"\",\"username\":\"\",\"id\":\"" + Id + "\"" + meta + "}";

    private static string Json(VaultContent c)
    {
        var (padded, _) = PayloadCodec.Encode(c);
        using (padded) { return PayloadCodec.JsonStringForTesting(padded)!; }
    }

    private static string Inhalt(params string[] eintraege) =>
        "{\"v\":2,\"entries\":[" + string.Join(',', eintraege) + "],\"factors\":{},\"level\":1,\"savedAt\":1}";

    /// <summary>Jede doppelte Eintrags-Kennung ist beschädigt (v4.8), auch ohne Schutzdaten; vorher las C# (und Swift)
    /// den Inhalt, schrieb danach aber Meta für beide und konnte die eigene Datei nie wieder lesen.</summary>
    [Fact]
    public void Doppelte_Kennung_immer_beschaedigt()
    {
        KT.Corrupt("payload.duplicateID", () => InhaltTests.Decode(Inhalt(Eintrag(""), Eintrag(",\"meta\":{}"))));
        KT.Corrupt("payload.duplicateID", () => InhaltTests.Decode(Inhalt(Eintrag(",\"meta\":{}"), Eintrag(""))));
        KT.Corrupt("payload.duplicateID", () => InhaltTests.Decode(Inhalt(Eintrag(""), Eintrag(""))));
        KT.Corrupt("payload.duplicateID", () => InhaltTests.Decode(Inhalt(Eintrag(",\"meta\":null"), Eintrag(",\"meta\":null"))));
        using var eins = InhaltTests.Decode(Inhalt(Eintrag("")));
        Assert.Single(eins.Entries);
    }

    /// <summary>Eigenschaft „gelesen ⇒ wieder lesbar“: Was Decode annimmt, liest Decode nach Encode wieder, auch über
    /// <c>VaultStore.Persist</c> (PrepareEntryData setzt Meta für alle offenen Einträge).</summary>
    [Fact]
    public void Gelesen_heisst_nach_Encode_und_Persist_wieder_lesbar()
    {
        using var reich = InhaltTests.Reich();
        var json = Json(reich);
        using (var back = InhaltTests.Decode(json))
        {
            Assert.Equal(json, Json(back));
        }
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("A", "anna"));
        f.Vault.Upsert(KT.Entry("B", "bert"));
        f.Vault.ImportEntries([.. f.Vault.Entries.Select(e => { var c = e.Copy(); c.Password = "anders"; return c; })]);
        var ids = f.Vault.Entries.Select(e => e.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
        f.Vault.Lock();
        using var v = KT.AnyVault(f.ReopenStore().Unlock(KT.Pw1));
        Assert.Equal(4, v.Entries.Count);
        v.Upsert(KT.Entry("C"));
    }

    /// <summary>Eine Tresordatei mit doppelter Kennung (fremder, fehlerhafter Schreiber mit dem DEK) öffnet als
    /// beschädigt und bleibt unverändert (vorher: öffnete, aber jedes Speichern scheiterte an save.verify).</summary>
    [Fact]
    public void Tresordatei_mit_doppelter_Kennung_ist_beschaedigt()
    {
        using var kv = KernVault.Make();
        kv.Vault.Upsert(KT.Entry("A"));
        var json = kv.JsonOnDisk();
        var entries = JsonNode.Parse(json)!["entries"]!.AsArray();
        var e0 = entries[0]!.ToJsonString();
        var dup = json.Replace("\"entries\":[", "\"entries\":[" + e0 + ",", StringComparison.Ordinal);
        Assert.NotEqual(json, dup);
        var file = kv.ParsedFile();
        var raw = Encoding.UTF8.GetBytes(dup);
        var buf = new byte[(raw.Length / PayloadCodec.BlockSize + 1) * PayloadCodec.BlockSize];
        raw.CopyTo(buf, 0);
        buf[raw.Length] = 0x80;
        byte[] bytes;
        using (var dek = kv.Vault.DekForTesting())
        using (var padded = SecureBuffer.Copy(buf))
        {
            var (nonce, ct) = Aead.Seal(dek, padded, VaultFile.PayloadAdFor(file.Header, file.Slots, file.Generation));
            bytes = new VaultFile(file.Header, file.Slots, file.Generation, nonce, ct).Serialize();
        }
        kv.Vault.Lock();
        kv.WriteFile(bytes);
        KT.Throws(SiegelErrorCode.CorruptFile, () => kv.ReopenStore().Unlock(KT.Pw1));
        Assert.Equal(bytes, kv.FileBytes());
    }
}
#endif
