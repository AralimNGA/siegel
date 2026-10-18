#if DEBUG
using System.Security.Cryptography;
using Siegel.Modell;
using Siegel.Werkzeuge;

namespace Siegel.Core.Tests.Kern;

/// <summary>Offline-Sicherheitsbericht (§17) und Inhalts-JSON des Eintrags-Schutzes (Gegenstück zu KernBerichtTests.swift).</summary>
public class BerichtTests
{
    private static string Stark() => "Zq7!" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8)) + "#Wm";

    [Fact]
    public async Task Schwach_wiederverwendet_alt_gleich_wie_Master_auch_versiegelt()
    {
        using var t = SchutzTresor.Make();
        var vor400Tagen = Clock.Canonical(DateTimeOffset.UtcNow.AddDays(-400));
        var alt = SchutzEntries.Make("Alt", EntryProtection.Normal, Stark());
        using (KT.Now(vor400Tagen))
        {
            var e = alt.Copy();
            e.History = [];
            e.Created = vor400Tagen;
            t.Vault.Upsert(e);
        }
        var schwach = SchutzEntries.Make("Schwach", EntryProtection.Normal, "passwort1");
        var gleich = Stark();
        var a = SchutzEntries.Make("A", EntryProtection.Normal, gleich);
        var b = SchutzEntries.Make("B", EntryProtection.Hoch, gleich);
        var m1 = SchutzEntries.Make("M1", EntryProtection.Normal, KT.Pw1);
        var m2 = SchutzEntries.Make("M2", EntryProtection.Maximal, KT.Pw1);
        var leer = new VaultEntry { Title = "Leer", Username = "x" };
        var weg = SchutzEntries.Make("Weg", EntryProtection.Fingerabdruck, "passwort1");
        foreach (var e in new[] { schwach, a, b, m1, m2, leer, weg }) { t.Vault.Upsert(e); }
        t.Vault.Delete(weg.Id);

        var r = t.Vault.SecurityReport();
        Assert.Equal(6, r.Total);
        // „schwach“ hängt an der Stärke-Schätzung der Werkzeuge (Stufe unter „fair“); „passwort1“ ist es immer.
        Assert.Contains(schwach.Id, r.Weak);
        Assert.Equal([[a.Id, b.Id], [m1.Id, m2.Id]], r.Reused.Select(g => g.ToArray()).ToArray());
        Assert.Equal([alt.Id], r.Old);
        Assert.Equal([m1.Id, m2.Id], r.SameAsMaster);
        Assert.Equal(new HashSet<Guid> { m1.Id, m2.Id }, t.Vault.MasterPasswordReuse.ToHashSet());

        var v = t.Reopen();
        var r1 = v.SecurityReport();
        Assert.Equal(r.Total, r1.Total);
        Assert.Equal(r.Weak, r1.Weak);
        Assert.Equal(r.Old, r1.Old);
        Assert.Equal(r.SameAsMaster, r1.SameAsMaster);
        Assert.Equal(r.Reused.Select(g => g.ToArray()), r1.Reused.Select(g => g.ToArray()));
        Assert.Equal(new HashSet<Guid> { m1.Id, m2.Id }, v.MasterPasswordReuse.ToHashSet());

        var neu = v.Entries.Single(x => x.Id == alt.Id);
        neu.Password = Stark();
        v.Upsert(neu);
        var sb = (await v.RevealSecretsAsync(b.Id, t.P)).ReplacingPassword(Stark());
        v.SetProtection(EntryProtection.Hoch, b.Id, sb);
        var r2 = v.SecurityReport();
        Assert.Empty(r2.Old);
        Assert.Equal([[m1.Id, m2.Id]], r2.Reused.Select(g => g.ToArray()).ToArray());
        v.ChangeMasterPassword(KT.Pw1, KT.Pw2, new FactorSecrets());
        Assert.Empty(v.SecurityReport().SameAsMaster);
        Assert.Empty(v.MasterPasswordReuse);
        DateTimeOffset? changedBefore;
        using (var c = v.ContentForTesting!) { changedBefore = c.Meta[m2.Id].Changed; }
        var umbenannt = v.Entries.Single(x => x.Id == m2.Id);
        umbenannt.Title = "M2 neu";
        v.Upsert(umbenannt);
        using (var c = v.ContentForTesting!) { Assert.Equal(changedBefore, c.Meta[m2.Id].Changed); }
    }

    [Fact]
    public void Metadaten_reuseTag_stabil_ueber_DEK_Rotation_v1_Inhalt_wird_ergaenzt()
    {
        using var t = SchutzTresor.Make();
        var e = SchutzEntries.Make("E", EntryProtection.Fingerabdruck);
        t.Vault.Upsert(e);
        t.Vault.Upsert(SchutzEntries.Make("O", EntryProtection.Normal, e.Password));
        byte[] tag;
        byte[] ebk;
        using (var c1 = t.Vault.ContentForTesting!)
        {
            tag = c1.Meta[e.Id].Tag!;
            Assert.Equal(16, tag.Length);
            Assert.All(c1.Meta.Values, m => Assert.True(Bytes.Same(m.Tag, tag) && m.Strength is not null && m.Changed is not null));
            using var l = c1.EntryKey!.Key.Borrow();
            ebk = l.Span.ToArray();
        }
        t.Vault.ChangeMasterPassword(KT.Pw1, KT.Pw2, new FactorSecrets());
        using (var c2 = t.Vault.ContentForTesting!)
        {
            Assert.True(c2.EntryKey!.Key.ConstantTimeEquals(ebk));
            Assert.Equal(tag, c2.Meta[e.Id].Tag);
        }
        Assert.Single(t.Vault.SecurityReport().Reused);

        using var dir = new KernTempDir();
        var store = VaultStore.ForTesting(dir.Sub("Siegel"), new InMemoryRollbackGuard());
        MigrationTests.WriteV1(store, [KT.Entry("A", password: "x"), KT.Entry("B", password: "x")]);
        var v = KT.Unlocked(store.Unlock(KT.Pw1))!;
        var r = v.SecurityReport();
        Assert.Equal(2, r.Total);
        Assert.Equal(2, r.Weak.Count);
        Assert.Single(r.Reused);
        v.Upsert(KT.Entry("C", password: "Zq7!" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8))));
        using (var c = v.ContentForTesting!)
        {
            Assert.Equal(3, c.Meta.Count);
            Assert.NotNull(c.EntryKey);
        }
        v.Lock();
    }

    [Fact]
    public void Inhalts_JSON_Rundlauf_und_strenge_Regeln()
    {
        using var t = SchutzTresor.Make();
        var offen = SchutzEntries.Make("Offen", EntryProtection.Normal);
        var zu = SchutzEntries.Make("Zu", EntryProtection.Maximal);
        t.Vault.Upsert(offen);
        t.Vault.Upsert(zu);
        var json = t.F.JsonOnDisk();
        Assert.StartsWith("{\"entries\":[{\"created\":", json, StringComparison.Ordinal);
        Assert.Contains("\"entryKey\":\"", json, StringComparison.Ordinal);
        Assert.Contains("\"recoveryGroups\":[{\"anchor\":{\"card\":{\"ctM\":\"", json, StringComparison.Ordinal);
        Assert.Contains("\"sealed\":null", json, StringComparison.Ordinal);
        Assert.Contains("\"sealed\":{\"blob\":{\"card\":{\"ctM\":\"", json, StringComparison.Ordinal);
        Assert.Contains("\"fido\":null", json, StringComparison.Ordinal);
        Assert.Contains("\"meta\":{\"changed\":", json, StringComparison.Ordinal);

        using var content = t.Vault.ContentForTesting!;
        var (padded, _) = PayloadCodec.Encode(content);
        using (padded)
        {
            var (back, _) = PayloadCodec.Decode(padded);
            using (back)
            {
                var (p2, _) = PayloadCodec.Encode(back);
                using (p2) { Assert.Equal(PayloadCodec.JsonStringForTesting(padded), PayloadCodec.JsonStringForTesting(p2)); }
            }
        }
        var io = content.Entries.FindIndex(x => x.Id == offen.Id);
        var iz = content.Entries.FindIndex(x => x.Id == zu.Id);
        var x = content.Sealed[zu.Id];
        bool Rejected(Action<VaultContent> change)
        {
            using var c = content.Clone();
            change(c);
            try
            {
                c.CheckSealing(Fehler.Corrupt);
                return false;
            }
            catch (SiegelException)
            {
                return true;
            }
        }
        Assert.False(Rejected(_ => { }));
        Assert.True(Rejected(c => c.Entries[io].Protection = EntryProtection.Hoch));
        Assert.True(Rejected(c => c.Sealed[offen.Id] = x));
        Assert.True(Rejected(c => c.Entries[iz].Password = "x"));
        Assert.True(Rejected(c => c.Entries[iz].History = [new PasswordHistoryItem("x", DateTimeOffset.UtcNow)]));
        Assert.True(Rejected(c => c.Entries[iz].Protection = EntryProtection.Festung));
        Assert.True(Rejected(c => c.Sealed[zu.Id] = x with { Blob = x.Blob with { Factors = x.Blob.Factors with { Fido = x.Blob.Factors.Card } } }));
        Assert.True(Rejected(c => c.Sealed[zu.Id] = x with { Blob = x.Blob with { Nonce = x.Blob.Nonce[..^1] } }));
        Assert.True(Rejected(c => c.Sealed[zu.Id] = x with { Recovery = x.Recovery with { Wrapped = x.Recovery.Wrapped[..^1] } }));
        Assert.True(Rejected(c => c.Sealed[zu.Id] = x with { Blob = x.Blob with { Factors = x.Blob.Factors with { SeEphemeral = KT.Repeat(4, 64) } } }));
        // Mac-Art und Windows-Hello-Art gleichzeitig bzw. die falsche Art
        Assert.True(Rejected(c => c.Sealed[zu.Id] = x with { Blob = x.Blob with { Factors = x.Blob.Factors with { Hello = new HelloPart(KT.Repeat(1, 32)) } } }));
        Assert.True(Rejected(c => c.Sealed[zu.Id] = x with { Blob = x.Blob with { Factors = x.Blob.Factors with { SeEphemeral = null, Hello = new HelloPart(KT.Repeat(1, 32)) } } }));
        Assert.True(Rejected(c => c.RecoveryGroups = []));
        Assert.True(Rejected(c => c.RecoveryGroups.Add(c.RecoveryGroups[0])));
        Assert.True(Rejected(c => c.RecoveryGroups[0] = c.RecoveryGroups[0] with { Mask = FactorSet.Card }));
        Assert.True(Rejected(c => c.Meta.Remove(zu.Id)));
        Assert.True(Rejected(c => c.Meta[offen.Id] = c.Meta[offen.Id] with { Tag = [1, 2, 3] }));
        Assert.True(Rejected(c =>
        {
            c.EntryKey!.Dispose();
            c.EntryKey = null;
        }));
        Assert.True(Rejected(c => c.EntryFactors = c.EntryFactors with { Card = null }));
        Assert.True(Rejected(c => c.Entries.Add(c.Entries[iz].Copy())));

        using (var bad = content.Clone())
        {
            bad.Entries[io].Protection = EntryProtection.Hoch;
            KT.Throws(SiegelErrorCode.Crypto, "entry.sealedState", () => PayloadCodec.Encode(bad));
        }
        var manipulated = json.Replace("\"protection\":4", "\"protection\":1", StringComparison.Ordinal);
        Assert.NotEqual(json, manipulated);
        using var mp = SchutzTests.Padded(manipulated);
        KT.Corrupt("entry.sealedState", () => PayloadCodec.Decode(mp));
    }
}

/// <summary>Exporte mit Eintrags-Schutz und Import im Kern (Gegenstück zu KernSchutzExportTests und KernImportExportTests).</summary>
public class ExportImportTests
{
    private static bool IsEmptyDir(string p) => Directory.Exists(p) && !Directory.EnumerateFileSystemEntries(p).Any();

    private static (SchutzTresor T, Dictionary<EntryProtection, VaultEntry> List) MitAllenStufen()
    {
        var t = SchutzTresor.Make();
        var list = new Dictionary<EntryProtection, VaultEntry>();
        foreach (var p in Enum.GetValues<EntryProtection>())
        {
            var e = SchutzEntries.Make("E" + (int)p, p);
            t.Vault.Upsert(e);
            list[p] = e;
        }
        return (t, list);
    }

    private static IDisposable CsvAlsText() => KT.Hook(
        () => TestHooks.CsvExporter = items => System.Text.Encoding.UTF8.GetBytes(string.Join("\n",
            items.Select(i => i.Entry.Title + "," + i.Entry.Username + "," + i.Secrets.Password + "," + i.Entry.Password))),
        () => TestHooks.CsvExporter = null);

    [Fact]
    public async Task Csv_Schutz_4_5_fehlen_Schutz_2_3_mit_einer_Freigabe()
    {
        var (t, list) = MitAllenStufen();
        using (t)
        using (CsvAlsText())
        {
            var dir = t.F.Dir.Sub("Export");
            var counter = new TestHooks.Counter();
            using (KT.Hook(() => TestHooks.KdfCounter = counter, () => TestHooks.KdfCounter = null))
            {
                KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => t.Vault.ExportCsv(dir, KT.Pw1, new FactorSecrets()));
            }
            Assert.Equal(0, counter.Value);
            await KT.ThrowsAsync(SiegelErrorCode.FactorMissing, "secureEnclave", () => t.Vault.ExportCsvAsync(dir, KT.Pw1, new FactorSecrets(), null));
            await KT.ThrowsAsync(SiegelErrorCode.WrongPassword, () => t.Vault.ExportCsvAsync(dir, KT.Pw2, new FactorSecrets(), t.P));
            Assert.Equal([0, 0, 0], t.P.Counts);
            Assert.True(IsEmptyDir(dir));
            var url = await t.Vault.ExportCsvAsync(dir, KT.Pw1, new FactorSecrets(), t.P);
            Assert.Equal([1, 0, 0], t.P.Counts);
            var text = File.ReadAllText(url);
            foreach (var (p, e) in list)
            {
                Assert.Equal(p < EntryProtection.Maximal, text.Contains(e.Password, StringComparison.Ordinal));
                Assert.Equal(p < EntryProtection.Maximal, text.Contains(e.Title, StringComparison.Ordinal));
            }
            Assert.EndsWith(".noindex", Path.GetDirectoryName(url), StringComparison.Ordinal);
            if (!OperatingSystem.IsWindows())
            {
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(url));
                Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute, File.GetUnixFileMode(Path.GetDirectoryName(url)!));
            }
        }
        using var t2 = SchutzTresor.Make();
        using (CsvAlsText())
        {
            var offen = SchutzEntries.Make("Offen", EntryProtection.Normal);
            var vier = SchutzEntries.Make("Vier", EntryProtection.Maximal);
            t2.Vault.Upsert(offen);
            t2.Vault.Upsert(vier);
            var text2 = File.ReadAllText(t2.Vault.ExportCsv(t2.F.Dir.Sub("Export"), KT.Pw1));
            Assert.Contains(offen.Password, text2, StringComparison.Ordinal);
            Assert.DoesNotContain(vier.Password, text2, StringComparison.Ordinal);
            Assert.DoesNotContain("Vier", text2, StringComparison.Ordinal);
            Assert.Equal([0, 0, 0], t2.P.Counts);
        }
    }

    [Fact]
    public async Task KeePass_nur_Stufen_1_bis_3_eigenes_Export_Passwort_Schutz_4_5_fehlen()
    {
        var (t, list) = MitAllenStufen();
        using (t)
        {
            var dir = t.F.Dir.Sub("Export");
            var counter = new TestHooks.Counter();
            using (KT.Hook(() => TestHooks.KdfCounter = counter, () => TestHooks.KdfCounter = null))
            {
                KT.Throws(SiegelErrorCode.PasswordTooWeak, () => t.Vault.ExportKeePass(dir, KT.Pw1, new FactorSecrets(), "kurz"));
                KT.Throws(SiegelErrorCode.MasterPasswordReused, () => t.Vault.ExportKeePass(dir, KT.Pw1, new FactorSecrets(), KT.Pw1));
                KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => t.Vault.ExportKeePass(dir, KT.Pw1, new FactorSecrets(), KT.Pw4));
            }
            Assert.Equal(0, counter.Value);
            await KT.ThrowsAsync(SiegelErrorCode.WrongPassword, () => t.Vault.ExportKeePassAsync(dir, KT.Pw2, new FactorSecrets(), KT.Pw4, t.P));
            Assert.Equal([0, 0, 0], t.P.Counts);
            List<(VaultEntry Entry, EntrySecrets Secrets)>? got = null;
            string? gotPassword = null;
            string url;
            TestHooks.KeePassExporter = (items, password) =>
            {
                got = [.. items];
                gotPassword = password;
                return "KDBX-TEST"u8.ToArray();
            };
            try
            {
                url = await t.Vault.ExportKeePassAsync(dir, KT.Pw1, new FactorSecrets(), KT.Pw4, t.P);
            }
            finally
            {
                TestHooks.KeePassExporter = null;
            }
            Assert.Equal([1, 0, 0], t.P.Counts);
            Assert.Equal(KT.Pw4, gotPassword);
            Assert.Equal(new[] { EntryProtection.Normal, EntryProtection.Fingerabdruck, EntryProtection.Hoch }.Select(p => list[p].Id).ToHashSet(),
                got!.Select(i => i.Entry.Id).ToHashSet());
            foreach (var (entry, secrets) in got!)
            {
                var o = list.Values.Single(x => x.Id == entry.Id);
                SchutzTests.Same(SchutzEntries.SecretsOf(o), secrets);
                Assert.Equal((o.Title, o.Url, o.Username, o.Password), (entry.Title, entry.Url, entry.Username, entry.Password));
                Assert.False(entry.SecretsSealed);
            }
            Assert.Equal("Siegel-Export.kdbx", Path.GetFileName(url));
            Assert.Equal("KDBX-TEST"u8.ToArray(), File.ReadAllBytes(url));
            // Echter Exporter (Werkzeuge): Erfolg → Datei da (Inhalt prüft WerkzeugeImKernTests mit dem KDBX-Leser)
            var dir2 = t.F.Dir.Sub("Export2");
            var real = await t.Vault.ExportKeePassAsync(dir2, KT.Pw1, new FactorSecrets(), KT.Pw4, t.P);
            Assert.True(File.Exists(real));
            Assert.NotEqual("KDBX-TEST"u8.ToArray(), File.ReadAllBytes(real));
            // Exporter scheitert → fester Code, nichts liegt herum
            var dir3 = t.F.Dir.Sub("Export3");
            TestHooks.KeePassExporter = (_, _) => throw new SiegelException(SiegelErrorCode.Io, "export.kdbx");
            try
            {
                await KT.ThrowsAsync(SiegelErrorCode.Io, "export.kdbx",
                    () => t.Vault.ExportKeePassAsync(dir3, KT.Pw1, new FactorSecrets(), KT.Pw4, t.P));
            }
            finally
            {
                TestHooks.KeePassExporter = null;
            }
            Assert.True(IsEmptyDir(dir3));
        }
        using var t4 = SchutzTresor.Make(SecurityLevel.Maximal);
        var c4 = new TestHooks.Counter();
        using (KT.Hook(() => TestHooks.KdfCounter = c4, () => TestHooks.KdfCounter = null))
        {
            KT.Throws(SiegelErrorCode.NotAllowedAtLevel, () => t4.Vault.ExportKeePass(t4.F.Dir.Path, KT.Pw1,
                t4.K.Secrets(FactorSet.SecureEnclave | FactorSet.Card), KT.Pw4));
            await KT.ThrowsAsync(SiegelErrorCode.NotAllowedAtLevel, () => t4.Vault.ExportCsvAsync(t4.F.Dir.Path, KT.Pw1,
                t4.K.Secrets(FactorSet.SecureEnclave | FactorSet.Card), t4.P));
        }
        Assert.Equal(0, c4.Value);
    }

    [Fact]
    public void Host_Schluessel_und_Import_Titel()
    {
        Assert.Equal("example.com", UnlockedVault.HostKey("HTTPS://Example.COM:8080/a"));
        Assert.Equal("example.com", UnlockedVault.HostKey("example.com/login"));
        Assert.Equal("xn--bcher-kva.de", UnlockedVault.HostKey("https://bücher.de"));
        Assert.Equal("xn--bcher-kva.de", UnlockedVault.HostKey("xn--bcher-kva.de"));
        Assert.Equal("example.com", UnlockedVault.HostKey("  example.com.  "));
        Assert.Equal("", UnlockedVault.HostKey(""));
        Assert.Equal("(Import)", UnlockedVault.ImportTitle(""));
        Assert.Equal("Bank (Import)", UnlockedVault.ImportTitle("Bank"));
        Assert.Equal(2048, System.Text.Encoding.UTF8.GetByteCount(UnlockedVault.ImportTitle(new string('x', 2048))));
    }

    [Fact]
    public void Importieren_nur_anhaengen_Dubletten_Konflikte_Sicherung_vor_import()
    {
        using var f = KernVault.Make();
        var existing = KT.Entry("Beispiel", "alice", "Alt-Passwort-1", "https://example.com/login");
        f.Vault.Upsert(existing);
        var stored = f.Vault.Entries[0];
        VaultEntry[] items =
        [
            KT.Entry("Dublette", "alice", "Alt-Passwort-1", "EXAMPLE.com"),
            KT.Entry("Konflikt", "alice", "Anders-2", "https://example.com/other"),
            KT.Entry("Neu", "bob", "x", "https://bücher.de"),
            KT.Entry("IDN-Dublette", "bob", "x", "https://xn--bcher-kva.de/"),
            KT.Entry("Leer", "", "", ""),
            KT.Entry("", "carol", "y", "example.com"),
            KT.Entry("", "alice", "Anders-3", "example.com"),
        ];
        var report = f.Vault.ImportEntries(items);
        Assert.Equal(5, report.Added);
        Assert.Equal(2, report.SkippedDuplicates);
        Assert.Equal(2, report.Conflicts);
        Assert.Equal(3UL, f.Vault.Generation);
        var same = f.Vault.Entries.Single(x => x.Id == existing.Id);
        Assert.Equal((stored.Title, stored.Password, stored.Modified), (same.Title, same.Password, same.Modified));
        Assert.Equal(["Beispiel", "Konflikt (Import)", "Neu", "Leer", "", "(Import)"], f.Vault.Entries.Select(x => x.Title));
        var pinned = f.LocalBackups().Where(b => b.Reason == "import").ToList();
        Assert.Single(pinned);
        Assert.Equal(2UL, pinned[0].Generation);
        var again = f.Vault.ImportEntries([items[0], items[2]]);
        Assert.Equal(0, again.Added);
        Assert.Equal(2, again.SkippedDuplicates);
        Assert.Equal(3UL, f.Vault.Generation);
        var sameId = KT.Entry("Andere Seite", "zoe", "z", "zoe.example");
        sameId.Id = existing.Id;
        f.Vault.ImportEntries([sameId]);
        Assert.Equal(stored.Title, f.Vault.Entries.Single(x => x.Id == existing.Id).Title);
        Assert.Contains(f.Vault.Entries, x => x.Title == "Andere Seite" && x.Id != existing.Id);
        f.Vault.Delete(existing.Id);
        var r3 = f.Vault.ImportEntries([KT.Entry("Wieder da", "alice", "Alt-Passwort-1", "example.com")]);
        Assert.Equal(1, r3.Added);
        Assert.Equal(0, r3.SkippedDuplicates);
        Assert.Equal(1, r3.Conflicts);
    }

    [Fact]
    public void Csv_Export_Ordner_Rechte_Cloud_abgelehnt()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("A", "anna", "=SUMME(1;2)", "https://a.example", "Zeile\n\"zitiert\""));
        var b = KT.Entry("B");
        f.Vault.Upsert(b);
        f.Vault.Delete(b.Id);
        var parent = f.Dir.Sub("Export");
        KT.Throws(SiegelErrorCode.WrongPassword, () => f.Vault.ExportCsv(parent, KT.Pw2));
        Assert.True(IsEmptyDir(parent));
        var url = f.Vault.ExportCsv(parent, KT.Pw1);
        var folder = Path.GetDirectoryName(url)!;
        var day = DateTime.Now.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
        Assert.Equal("Siegel-Export-" + day + ".noindex", Path.GetFileName(folder));
        Assert.Equal("Siegel-Export.csv", Path.GetFileName(url));
        // Inhalt = CsvExport der nicht gelöschten Einträge mit ihren Geheimteilen
        Assert.Equal(CsvExport.Export(f.Vault.Entries.Select(e => (e, SchutzEntries.SecretsOf(e))).ToList()), File.ReadAllBytes(url));
        var second = f.Vault.ExportCsv(parent, KT.Pw1);
        Assert.Equal("Siegel-Export-" + day + "-2.noindex", Path.GetFileName(Path.GetDirectoryName(second)));
        var icloud = Path.Combine(f.Dir.Path, "Library", "Mobile Documents", "com~apple~CloudDocs");
        Directory.CreateDirectory(icloud);
        KT.Throws(SiegelErrorCode.ExportLocationRejected, "icloud", () => f.Vault.ExportCsv(icloud, KT.Pw1));
        Assert.True(IsEmptyDir(icloud));
        KT.Throws(SiegelErrorCode.Io, "export.directory", () => f.Vault.ExportCsv(Path.Combine(f.Dir.Path, "gibtsnicht"), KT.Pw1));
    }

    [Fact]
    public void OneDrive_wird_abgelehnt()
    {
        using var f = KernVault.Make();
        var root = f.Dir.Sub("OneDrive-Test");
        var inside = Path.Combine(root, "Dokumente");
        Directory.CreateDirectory(inside);
        var old = Environment.GetEnvironmentVariable("OneDriveCommercial");
        Environment.SetEnvironmentVariable("OneDriveCommercial", root);
        try
        {
            KT.Throws(SiegelErrorCode.ExportLocationRejected, "onedrive", () => ExportLocation.Check(inside));
            KT.Throws(SiegelErrorCode.ExportLocationRejected, "onedrive", () => ExportLocation.Check(root));
            ExportLocation.Check(f.Dir.Sub("Daneben"));
        }
        finally
        {
            Environment.SetEnvironmentVariable("OneDriveCommercial", old);
        }
    }
}
#endif
