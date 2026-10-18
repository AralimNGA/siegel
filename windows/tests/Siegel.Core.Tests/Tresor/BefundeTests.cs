#if DEBUG
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Hilfen der Befund-Tests (Gegenstück zu den Hilfen in KernDateiBefundeTests.swift, KernKryptoBefundeTests.swift,
/// KernVernichtungFuzzBefundeTests.swift).</summary>
internal static partial class BH
{
    internal const string Nbsp = "Zebra Kanu Fichte Lampe 7319 Q!";
    internal const string Space = "Zebra Kanu Fichte Lampe 7319 Q!";

    internal static FactorSecret Zufall() => FactorSecret.Copy(RandomNumberGenerator.GetBytes(32));

    /// <summary>Eintrag mit Schutz 1 in Stufe 4/5 (dort bekommen neue Einträge mindestens Schutz 2).</summary>
    internal static VaultEntry Offen(VTresor v, string title, string password)
    {
        var e = SchutzEntries.Make(title, EntryProtection.Normal, password);
        v.Vault.Upsert(e);
        v.Vault.SetProtection(EntryProtection.Normal, e.Id, SchutzEntries.SecretsOf(e));
        return e;
    }

    /// <summary>Platzhalter-Datei für einen SE-Schlüssel, dessen Blob im Test nicht als Datei liegt.</summary>
    internal static string Platzhalter(VTresor v, Guid id)
    {
        var path = Path.Combine(v.Hardware, Bytes.GuidText(id) + ".siegelhw");
        File.WriteAllBytes(path, KT.Repeat(0x41, 32));
        return path;
    }

    internal static void ZustandAendern(VTresor v, Action<DestructionState> change)
    {
        var st = v.State()!;
        change(st);
        DestructionState.Write(st, v.Hardware);
    }

    internal static Guid SeKeyId(VTresor v) => v.Vault.HeaderForTesting!.FactorFields.SeKeyId!.Value;

    internal static void FlipPayloadByte(KernVault f)
    {
        var b = f.FileBytes();
        b[^100] ^= 0x01;
        f.WriteFile(b);
    }

    internal static IReadOnlyList<string> Quarantined(KernVault f) =>
        [.. FileIO.ListFiles(f.Store.BackupRoot).Where(p => Path.GetFileName(p).StartsWith(BackupNaming.QuarantinePrefix, StringComparison.Ordinal))];

    internal static PendingRecovery NewKit(UnlockedVault vault, string password = KT.Pw1)
    {
        var pending = vault.PrepareRecovery(password);
        vault.CommitRecovery(pending, KernStufen.Confirmation(pending));
        return pending;
    }

    /// <summary>Lauf 2 eines Vorgangs sperrt den Tresor (Testschalter <c>KdfObserverHook</c>).</summary>
    internal static IDisposable SperreBeiLauf(UnlockedVault vault, int run, out TestHooks.KdfObserver observer)
    {
        var o = new TestHooks.KdfObserver(n =>
        {
            if (n == run) { vault.Lock(); }
        });
        observer = o;
        return KT.Hook(() => TestHooks.KdfObserverHook = o, () => TestHooks.KdfObserverHook = null);
    }

    internal const uint UfImmutable = 0x00000002;

    [LibraryImport("libc", EntryPoint = "chflags", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int Chflags(string path, uint flags);
}

/// <summary>Datei-Befunde der zweiten Prüfung (SPEC v4.4): Sperre während des Einrichtens, Notfallweg ohne Tresordatei
/// und für eine gewählte Sicherung, Fehlversuche auf den Sicherungswegen (KernDateiBefundeTests.swift).</summary>
public class DateiBefundeTests
{
    [Fact]
    public async Task Datei_1_Sperre_waehrend_des_Argon2_fuers_Vernichtungs_Passwort_Datei_unveraendert_V_unbenutzt()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        var vault = v.Vault;
        var vaultId = vault.VaultId;
        var generation = vault.Generation;
        var vorher = v.T.F.FileBytes();
        var sicherungen = v.Store.Backups().Select(b => b.Path).ToHashSet();
        // Lauf 1: Passwortprüfung der async-Variante, Lauf 2: Argon2 des neuen Vernichtungs-Passworts (im Kern).
        TestHooks.KdfObserver observer;
        using (BH.SperreBeiLauf(vault, 2, out observer))
        {
            await KT.ThrowsAsync(SiegelErrorCode.Io, "vault.locked",
                () => v.Einrichten(new DestructionSettings(DuressEnabled: true), [a.Id], VTresor.DuressPw));
        }
        Assert.Equal(2, observer.Runs);
        Assert.Equal(vorher, v.T.F.FileBytes());
        Assert.Equal(sicherungen, v.Store.Backups().Select(b => b.Path).ToHashSet());
        Assert.Null(v.State());
        Assert.True(v.Store.DestructionKeyIsUnused(v.VKeyId, vaultId, generation));

        // Die Oberfläche darf V jetzt vernichten; der Eintrag hängt nicht daran.
        new FileDestructionKeyEraser().Destroy(v.VKeyId, v.Hardware);
        v.Reopen();
        Assert.Empty(v.Vault.DestructibleEntries);
        Assert.Null(v.Vault.DestructionKeyId);
        await VH.Same(a, v.Reveal(a.Id));
    }

    [Fact]
    public async Task Nach_erfolgreichem_Einrichten_nennt_der_Zustand_V_nie_unbenutzt()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        var vaultId = v.Vault.VaultId;
        var generation = v.Vault.Generation;
        var report = await v.Einrichten(new DestructionSettings(DuressEnabled: true), [a.Id], VTresor.DuressPw);
        Assert.True(report?.IsComplete);
        Assert.False(v.Store.DestructionKeyIsUnused(v.VKeyId, vaultId, generation));
        Assert.False(v.Store.DestructionKeyIsUnused(v.VKeyId, vaultId, v.Vault.Generation));
        // Fehlt zustand.json (Schreiben gescheitert), schützt die neuere Generation auf der Platte.
        DestructionState.Remove(v.Hardware);
        Assert.False(v.Store.DestructionKeyIsUnused(v.VKeyId, vaultId, generation));
        // Unbekannte Kennung, gleicher Stand: unbenutzt.
        Assert.True(v.Store.DestructionKeyIsUnused(Guid.NewGuid(), vaultId, v.Vault.Generation));
    }

    [Fact]
    public async Task PurgeBackups_scheitert_nach_dem_Schreiben_kein_Fehler_Bericht_unvollstaendig()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        var vaultId = v.Vault.VaultId;
        var generation = v.Vault.Generation;
        PurgeReport? report;
        using (KT.Hook(() => TestHooks.FailPurgeBackups = true, () => TestHooks.FailPurgeBackups = false))
        {
            report = await v.Einrichten(new DestructionSettings(DeadmanDays: 30), [a.Id]);
        }
        Assert.True(report?.Interrupted);
        Assert.False(report?.IsComplete);
        Assert.True(v.Vault.Generation > generation);
        VH.SameSet([a.Id], v.Vault.DestructibleEntries);
        Assert.Equal(v.VKeyId, v.Vault.DestructionKeyId);
        Assert.Equal(v.VKeyId, v.State()?.VKeyId);
        Assert.False(v.Store.DestructionKeyIsUnused(v.VKeyId, vaultId, generation));
        await VH.Same(a, v.Reveal(a.Id));
        v.Reopen();
        VH.SameSet([a.Id], v.Vault.DestructibleEntries);
    }

    [Fact]
    public void Nach_dem_Sperren_schreibt_kein_laufender_Passwortwechsel()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("A"));
        var vorher = f.FileBytes();
        TestHooks.KdfObserver observer;
        using (BH.SperreBeiLauf(f.Vault, 2, out observer))
        {
            KT.Throws(SiegelErrorCode.Io, "vault.locked", () => f.Vault.ChangeMasterPassword(KT.Pw1, KT.Pw2));
        }
        Assert.Equal(2, observer.Runs);
        Assert.Equal(vorher, f.FileBytes());
        using var again = KT.Unlocked(f.Store.Unlock(KT.Pw1));
        Assert.NotNull(again);
    }

    [Fact]
    public void Datei_2_Tresordatei_fehlt_Code_passt_zu_den_Sicherungen_und_stellt_die_neueste_her()
    {
        using var f = KernVault.Make();
        f.Vault.Upsert(KT.Entry("A"));
        f.Vault.Upsert(KT.Entry("B"));
        f.Vault.Lock();
        FileIO.Remove(f.Store.VaultPath);
        Assert.False(f.Store.VaultExists);
        KT.Throws(SiegelErrorCode.VaultMissing, () => f.Store.CheckRecoveryCode(f.Code));
        Assert.Equal(RecoveryCodeMatch.Exact, f.Store.CheckRecoveryCodeAgainstBackups(f.Code));
        var (wieder, info) = f.Store.RecoverFromNewestReadableBackup(f.Code, KT.Pw2, KT.Kdf);
        using (wieder)
        {
            Assert.True(f.Store.VaultExists);
            Assert.Equal(f.Vault.VaultId, info.VaultId);
            Assert.Equal(["A"], wieder.Entries.Select(e => e.Title));
            // Kopf ohne Datei: aus der neuesten lesbaren Sicherung (für die Wahl Code/Teile).
            Assert.Equal(RecoveryScheme.SingleCode, VaultStore.Inspect(info.Path).RecoveryScheme);
        }
    }

    [Fact]
    public void Datei_3_neues_Geraet_Stufe_4_zwei_Teile_oeffnen_genau_die_gewaehlte_Sicherung()
    {
        var (a, _, kit) = KernStufen.Make(SecurityLevel.Maximal);
        using (a)
        {
            var teile = kit!.Shares.Select(s => s.Formatted).ToArray();
            a.Vault.Upsert(KT.Entry("Alt"));
            a.Vault.Lock();
            var kopie = Path.Combine(a.Dir.Sub("Stick"), "Siegel-Sicherung.siegel");
            File.Copy(a.Store.VaultPath, kopie);

            using var neu = new KernTempDir();
            var storeB = VaultStore.ForTesting(Path.Combine(neu.Path, "Siegel"), new InMemoryRollbackGuard());
            // Ohne Tresor (Einrichtung): direkt aus der Sicherung.
            Assert.Equal(RecoveryScheme.Shamir2Of3, VaultStore.Inspect(kopie).RecoveryScheme);
            Assert.Equal([RecoveryCodeMatch.Exact, RecoveryCodeMatch.Exact], storeB.CheckRecoveryShares([teile[2], teile[0]], kopie));
            using var wieder = storeB.RecoverBackup(kopie, [teile[2], teile[0]], KT.Pw4, KT.Kdf);
            Assert.Equal(SecurityLevel.Standard, wieder.Level);
            Assert.Equal(["Alt"], wieder.Entries.Select(e => e.Title));
            Assert.True(storeB.VaultExists);
        }
    }

    [Fact]
    public void Abstufen_2_auf_1_die_angeheftete_Stufe_2_Sicherung_oeffnet_sich_mit_dem_Notfallcode()
    {
        var (a, faktoren, _) = KernStufen.Make(SecurityLevel.Erhoeht);
        using (a)
        {
            a.Vault.Upsert(KT.Entry("Vorher"));
            KernStufen.Change(a.Vault, SecurityLevel.Standard, faktoren, FactorSet.SecureEnclave);
            var alt = a.Store.Backups().Where(b => b.Reason == BackupNaming.Reason.LevelChange).MaxBy(b => b.Generation)!;
            KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => a.Store.RestoreBackup(alt, KT.Pw1));
            a.Vault.Lock();
            using var wieder = a.Store.RecoverBackup(alt.Path, a.Code, KT.Pw2, KT.Kdf);
            Assert.Equal(["Vorher"], wieder.Entries.Select(e => e.Title));
            Assert.Equal(SecurityLevel.Standard, wieder.Level);
        }
    }

    [Fact]
    public async Task Datei_5_Tresor_fehlt_Zaehler_an_Sicherungswege_zaehlen_ab_N_halbe_Warnung()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(MaxFailedAttempts: 10), [a.Id]);
        v.Vault.Upsert(KT.Entry("Später"));
        var level = v.Vault.Level;
        v.Vault.Lock();
        FileIO.Remove(v.Store.VaultPath);
        var sicherung = v.Store.Backups().First(b => b.VaultId is not null);
        Assert.False(v.Store.GetDestructionStatus().ShouldWarnAboutAttempts);
        for (var i = 0; i < 5; i++)
        {
            KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.RestoreBackup(sicherung, KT.Pw3, v.T.K.Secrets(level.Factors())));
        }
        var status = v.Store.GetDestructionStatus();
        Assert.Equal(5, status.FailedAttempts);
        Assert.Equal(5, status.RemainingAttempts);
        Assert.True(status.ShouldWarnAboutAttempts);
        Assert.Empty(v.Eraser.Destroyed);
    }
}

/// <summary>Regressionstests zu den Prüfbefunden vom 16.10.2026, soweit nicht schon in den übrigen Tresor-Tests
/// (KernBefundeTests.swift: #3 Kit-Bestätigung nach Wiederherstellen, #4 Notfallweg, #2 Export).</summary>
public class Befunde1610Tests
{
    private static void ConfirmSetupKit(KernVault f) => f.Vault.CommitRecovery(f.Pending, KernStufen.Confirmation(f.Pending));

    [Fact]
    public void Nr3_importBackup_einer_alten_Kopie_nach_Kitwechsel_ist_unbestaetigt()
    {
        using var f = KernVault.Make();
        ConfirmSetupKit(f);
        var kopie = Path.Combine(f.Dir.Path, "alt.siegel");
        f.Store.ExportBackup(kopie);
        BH.NewKit(f.Vault);
        f.Vault.Lock();
        using var v = f.Store.ImportBackup(kopie, KT.Pw1);
        Assert.False(v.RecoveryConfirmed);
    }

    [Fact]
    public void Nr3_neueste_lesbare_Sicherung_nach_Kitwechsel_und_Beschaedigung_ist_unbestaetigt()
    {
        using var f = KernVault.Make();
        ConfirmSetupKit(f);
        BH.NewKit(f.Vault);
        f.Vault.Lock();
        BH.FlipPayloadByte(f);
        var (v, info) = f.Store.RestoreNewestReadableBackup(KT.Pw1);
        using (v)
        {
            Assert.Equal(BackupNaming.Reason.NewKit, info.Reason);
            Assert.False(v.RecoveryConfirmed);
        }
    }

    [Fact]
    public void Nr3_Wiederherstellung_mit_gleichem_Kit_laesst_die_Bestaetigung_stehen()
    {
        using var f = KernVault.Make();
        ConfirmSetupKit(f);
        f.Vault.Upsert(KT.Entry("A"));
        f.Vault.Upsert(KT.Entry("B"));
        var alt = f.LocalBackups()[0];
        f.Vault.Lock();
        using var v = f.Store.RestoreBackup(alt, KT.Pw1);
        Assert.True(v.RecoveryConfirmed);
        Assert.Equal(f.Pending.Code.KitId, v.KitId);
    }

    [Fact]
    public void Nr4_Inhalt_gekippt_recover_wirft_Corrupt_der_Sicherungsweg_oeffnet_die_neueste()
    {
        using var f = KernVault.Make();
        ConfirmSetupKit(f);
        f.Vault.Upsert(KT.Entry("A"));
        f.Vault.Upsert(KT.Entry("B"));
        f.Vault.Lock();
        BH.FlipPayloadByte(f);
        Assert.Equal(RecoveryCodeMatch.Exact, f.Store.CheckRecoveryCode(f.Code));
        KT.Corrupt("file.checksum", () => f.Store.Recover(f.Code, KT.Pw3, KT.Kdf));
        var (v, info) = f.Store.RecoverFromNewestReadableBackup(f.Code, KT.Pw3, KT.Kdf);
        using (v)
        {
            Assert.Equal(3UL, info.Generation);
            Assert.Equal(["A"], v.Entries.Select(e => e.Title));
            Assert.True(v.RecoveryConfirmed);
            Assert.Single(BH.Quarantined(f));
            v.Lock();
        }
        using var again = KT.Unlocked(f.Store.Unlock(KT.Pw3));
        Assert.NotNull(again);
    }

    [Fact]
    public void Nr4_Gegenprobe_fremder_Tresor_und_aelteres_Kit_werden_nie_angenommen()
    {
        using var f = KernVault.Make();
        ConfirmSetupKit(f);
        f.Vault.Upsert(KT.Entry("A"));
        var neu = BH.NewKit(f.Vault);
        f.Vault.Upsert(KT.Entry("B"));
        f.Vault.Lock();
        BH.FlipPayloadByte(f);
        // Altes, bewusst ersetztes Kit.
        KT.Corrupt("backup.noneReadable", () => f.Store.RecoverFromNewestReadableBackup(f.Code, KT.Pw3, KT.Kdf));
        Assert.ThrowsAny<SiegelException>(() => f.Store.CheckRecoveryCodeAgainstBackups(f.Code));
        // Fremder Tresor.
        using var fremd = KernVault.Make();
        KT.Corrupt("backup.noneReadable", () => f.Store.RecoverFromNewestReadableBackup(fremd.Code, KT.Pw3, KT.Kdf));
        Assert.True(f.Store.VaultExists);
        Assert.Empty(BH.Quarantined(f));
        // Das aktuelle Kit öffnet die neueste Sicherung mit diesem Kit.
        var (v, _) = f.Store.RecoverFromNewestReadableBackup(neu.Code.Formatted, KT.Pw3, KT.Kdf);
        using (v)
        {
            Assert.Equal(neu.Code.KitId, v.KitId);
            Assert.Equal(["A"], v.Entries.Select(e => e.Title));
        }
    }

    [Fact]
    public void Nr4_Regel_und_KDF_Grenzen_gelten_auch_auf_dem_Sicherungsweg()
    {
        using var f = KernVault.Make();
        f.Vault.Lock();
        BH.FlipPayloadByte(f);
        KT.Throws(SiegelErrorCode.PasswordTooWeak, () => f.Store.RecoverFromNewestReadableBackup(f.Code, KT.Weak, KT.Kdf));
        KT.Throws(SiegelErrorCode.KdfParametersOutOfRange, () => f.Store.RecoverFromNewestReadableBackup(f.Code, KT.Pw3, KdfParameters.Standard));
        Assert.Empty(BH.Quarantined(f));
    }

    [Fact]
    public void Nr2_exportBackup_ersetzt_und_prueft_zurueck_ohne_Temp_Reste()
    {
        using var f = KernVault.Make();
        var datei = Path.Combine(f.Dir.Path, "Kopie.siegel");
        f.Store.ExportBackup(datei);
        f.Vault.Upsert(KT.Entry("B"));
        f.Store.ExportBackup(datei);
        Assert.Equal(f.FileBytes(), File.ReadAllBytes(datei));
        Assert.DoesNotContain(FileIO.ListFiles(f.Dir.Path), p => p.EndsWith(".tmp", StringComparison.Ordinal));
    }
}

/// <summary>Krypto-Befunde der zweiten Prüfung (KernKryptoBefundeTests.swift): Umschlag des Vernichtungs-Passworts an die
/// Faktoren gebunden (krypto-1), DEK-Rotation nach einer Vernichtungs-Sitzung (krypto-2), reuseTag wie das
/// Master-Passwort normalisiert (krypto-3).</summary>
public class KryptoBefundeTests
{
    [Fact]
    public async Task Krypto_1_Stufe_5_Ablage_und_Vernichtungs_Passwort_ohne_Faktoren_nur_erkannt_kein_DEK()
    {
        using var v = new VTresor(SecurityLevel.Festung);
        var geheim = "Schutz1-" + KT.Hex(RandomNumberGenerator.GetBytes(6));
        var offen = BH.Offen(v, "Offen", geheim);
        var zwei = v.Add("Zwei", EntryProtection.Fingerabdruck);
        var bank = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DuressEnabled: true), [bank.Id], VTresor.DuressPw);
        var fileId = v.State()!.DuressFileId!.Value;
        v.Vault.Lock();
        var ablage = File.ReadAllBytes(v.Store.HardwareKeyPath(fileId));
        var datei = v.T.F.FileBytes();
        Assert.Equal(FactorSet.All, VaultFile.Parse(datei).Header.Factors);

        // Angreifer mit Container-Kopie und Vernichtungs-Passwort, ohne Finger, Karte und Schlüssel.
        Assert.Equal((true, false), v.OfflineDuress(ablage, fileId, datei, null));
        // Karte gesehen (q bekannt), Secure Enclave und Sicherheitsschlüssel geraten.
        var geraten = new FactorSecrets { SecureEnclave = BH.Zufall(), Card = FactorSecret.Copy(v.T.K.Q), SecurityKey = BH.Zufall() };
        Assert.Equal((true, false), v.OfflineDuress(ablage, fileId, datei, geraten));
        // Nur der Sicherheitsschlüssel falsch: auch nichts.
        var echt = v.Factors();
        Assert.Equal((true, false), v.OfflineDuress(ablage, fileId, datei,
            new FactorSecrets { SecureEnclave = echt.SecureEnclave, Card = echt.Card, SecurityKey = BH.Zufall() }));
        // Gegenprobe: mit allen Faktoren öffnet der Umschlag – genau das, was die Vernichtungs-Sitzung sieht.
        Assert.Equal((true, true), v.OfflineDuress(ablage, fileId, datei, v.Factors()));
        using (var c = OpenWithDuress(v, ablage, fileId, datei))
        {
            Assert.Equal(geheim, c.Entries.Single(e => e.Id == offen.Id).Password);
            Assert.True(c.Entries.Single(e => e.Id == zwei.Id).SecretsSealed);
        }
        // Ein anderes Passwort wird gar nicht erkannt.
        Assert.False(v.OfflineDuress(ablage, fileId, datei, v.Factors(), KT.Pw3).Recognized);
        // Das Offline-Raten vernichtet nichts.
        Assert.True(File.Exists(v.VPath));
    }

    private static VaultContent OpenWithDuress(VTresor v, byte[] ablage, Guid fileId, byte[] vaultFile)
    {
        var f = DuressFile.Decode(ablage, fileId);
        var file = VaultFile.Parse(vaultFile);
        using var pw = PasswordNormalizer.SecureBytes(VTresor.DuressPw);
        using var d = DuressCrypto.Derive(pw, f.Salt, file.Header.Kdf, v.Store.Limits);
        using var binding = DuressCrypto.Binding(file.Header, v.Factors());
        var (_, dek) = DuressCrypto.Open(f, d, binding, file.Header.VaultId);
        using (dek) { return VaultCrypto.DecryptPayload(file, dek!).Content; }
    }

    [Fact]
    public async Task Krypto_1_Vernichtungs_Passwort_mit_falschem_Faktor_vernichtet_oeffnet_aber_nicht()
    {
        using var v = new VTresor(SecurityLevel.Festung);
        var bank = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DuressEnabled: true), [bank.Id], VTresor.DuressPw);
        v.Vault.Lock();
        var richtig = v.Factors();
        var falsch = new FactorSecrets { SecureEnclave = richtig.SecureEnclave, Card = richtig.Card, SecurityKey = BH.Zufall() };
        KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.Unlock(VTresor.DuressPw, falsch));
        Assert.Equal([v.VKeyId], v.Eraser.Destroyed);
        Assert.Equal(0, v.Store.GetDestructionStatus().FailedAttempts);
        // Mit den richtigen Faktoren: Vernichtungs-Sitzung wie gewohnt.
        using var dv = v.TryUnlock(VTresor.DuressPw);
        Assert.True(dv.IsDuressSession);
        Assert.DoesNotContain(dv.Entries, e => e.Id == bank.Id);
    }

    [Fact]
    public async Task Krypto_1_ungebundene_Ablage_aus_v4_3_nur_erkannt_das_naechste_echte_Entsperren_schreibt_sie_neu()
    {
        using var v = new VTresor();
        var bank = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DuressEnabled: true), [bank.Id], VTresor.DuressPw);
        DestructionConfig.DuressInfo d;
        using (var c = v.Vault.ContentForTesting!) { d = c.Destruction!.Duress!; }
        var header = v.Vault.HeaderForTesting!;
        var path = v.Store.HardwareKeyPath(d.FileId);
        byte[] alt;
        using (var dek = v.Vault.DekForTesting())
        using (var enc = RecoveryKem.Encapsulate(d.Pk, DuressCrypto.Label, Bytes.OfGuid(d.FileId)))
        {
            // Formel bis v4.3: KEK direkt aus der Kapselung, ohne F.
            var wrapped = Aead.Wrap(enc.Kek, dek, DuressCrypto.WrapAd(header.VaultId, d.FileId, d.Salt));
            alt = new DuressFile(d.FileId, d.Salt, d.Check, new HybridCapsule(enc.CtM, enc.CtX), wrapped).Encoded();
        }
        File.WriteAllBytes(path, alt);
        Assert.False(v.DuressEnvelopeOpens());
        v.Vault.Lock();

        // Unter Zwang vor dem ersten echten Entsperren: vernichtet, aber keine Sitzung (wie ein veralteter Umschlag).
        KT.Throws(SiegelErrorCode.WrongPassword, () => v.TryUnlock(VTresor.DuressPw));
        Assert.Equal([v.VKeyId], v.Eraser.Destroyed);

        v.Reopen();
        Assert.NotEqual(alt, File.ReadAllBytes(path));
        Assert.True(v.DuressEnvelopeOpens());
        v.Vault.Lock();
        using var dv = v.TryUnlock(VTresor.DuressPw);
        Assert.True(dv.IsDuressSession);
    }

    [Fact]
    public async Task Krypto_1_ohne_F_wird_ein_Inhalt_mit_Vernichtungs_Passwort_nie_geschrieben()
    {
        using var v = new VTresor();
        var bank = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DuressEnabled: true), [bank.Id], VTresor.DuressPw);
        v.Vault.Lock();
        var vorher = v.T.F.FileBytes();
        var file = VaultFile.Parse(vorher);
        using var pw = PasswordNormalizer.SecureBytes(KT.Pw1);
        UnlockedVault ohneF;
        using (var opened = VaultCrypto.OpenWithPassword(file, pw, v.Factors(), v.Store.Limits))
        {
            // Sitzung ohne Faktoren (damit ohne F); übernimmt Kopien von DEK und Inhalt.
            ohneF = new UnlockedVault(v.Store, file.Header, file.Slots, opened.Dek.Slice(0, opened.Dek.Length), opened.Content.Clone(),
                file.Generation, pw);
        }
        using (ohneF)
        {
            KT.Throws(SiegelErrorCode.Crypto, "duress.binding", () => ohneF.Upsert(SchutzEntries.Make("Neu", EntryProtection.Maximal)));
        }
        Assert.Equal(vorher, v.T.F.FileBytes());
    }

    [Fact]
    public async Task Krypto_2_nach_einer_Vernichtungs_Sitzung_erneuert_das_erste_echte_Entsperren_den_DEK()
    {
        using var v = new VTresor();
        var bank = v.Add("Bank", EntryProtection.Maximal);
        var mail = BH.Offen(v, "Mail", "Mail-" + KT.Hex(RandomNumberGenerator.GetBytes(6)));
        await v.Einrichten(new DestructionSettings(DuressEnabled: true), [bank.Id], VTresor.DuressPw);
        var fileId = v.State()!.DuressFileId!.Value;
        using var dek0 = v.Vault.DekForTesting();
        v.Vault.Lock();
        var ablage = File.ReadAllBytes(v.Store.HardwareKeyPath(fileId));

        // Zwang: die Sitzung arbeitet mit dem echten DEK.
        using (var dv = v.TryUnlock(VTresor.DuressPw))
        {
            Assert.True(dv.IsDuressSession);
            using (var d = dv.DekForTesting()) { Assert.True(d.ConstantTimeEquals(dek0)); }
            Assert.True(v.State()!.RekeyPending);
            Assert.Contains("\"rekeyPending\":true", File.ReadAllText(v.StatePath), StringComparison.Ordinal);
            dv.Lock();
        }
        var generation0 = VaultFile.Parse(v.T.F.FileBytes()).Generation;

        // Besitzer: echtes Entsperren → neuer DEK und neues Salz, sofort geschrieben, Vermerk erledigt.
        v.Reopen();
        using var dek1 = v.Vault.DekForTesting();
        Assert.False(dek1.ConstantTimeEquals(dek0));
        Assert.True(v.Vault.Generation > generation0);
        Assert.False(v.State()!.RekeyPending);
        Assert.DoesNotContain("rekeyPending", File.ReadAllText(v.StatePath), StringComparison.Ordinal);
        Assert.Equal([bank.Id], v.Vault.DestroyedEntries);
        Assert.Equal(DestructionTrigger.DuressPassword, v.Vault.DestructionStatus.DestroyedTrigger);
        Assert.Equal(mail.Password, v.Vault.Entries.Single(e => e.Id == mail.Id).Password);
        Assert.True(v.DuressEnvelopeOpens());

        // Später kommt der Angreifer an eine neuere Tresordatei.
        BH.Offen(v, "Neu", "Neu-" + KT.Hex(RandomNumberGenerator.GetBytes(6)));
        v.Vault.Lock();
        var spaeter = v.T.F.FileBytes();
        Assert.ThrowsAny<SiegelException>(() => VaultCrypto.DecryptPayload(VaultFile.Parse(spaeter), dek0).Content.Dispose());
        // Alte Ablage + Vernichtungs-Passwort, sogar mit allen Faktoren: nur der alte DEK.
        Assert.Equal((true, false), v.OfflineDuress(ablage, fileId, spaeter, v.Factors()));

        // Ein weiteres echtes Entsperren rotiert nicht erneut.
        v.Reopen();
        using (var d = v.Vault.DekForTesting()) { Assert.True(d.ConstantTimeEquals(dek1)); }
        // Das Vernichtungs-Passwort wirkt weiter wie zuvor.
        v.Vault.Lock();
        using var dv2 = v.TryUnlock(VTresor.DuressPw);
        Assert.True(dv2.IsDuressSession);
    }

    [Fact]
    public async Task Krypto_2_bei_Rollback_Verdacht_wird_nicht_rotiert_der_Vermerk_bleibt()
    {
        using var v = new VTresor();
        var bank = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DuressEnabled: true), [bank.Id], VTresor.DuressPw);
        v.Vault.Lock();
        SecureBuffer dek0;
        using (var dv = v.TryUnlock(VTresor.DuressPw)) { dek0 = dv.DekForTesting(); }
        using (dek0)
        {
            var file = VaultFile.Parse(v.T.F.FileBytes());
            v.Store.RollbackGuard.Record(file.Header.Uuid, file.Generation + 5);
            var outcome = v.Store.Unlock(KT.Pw1, v.Factors());
            using var r = outcome.Vault;
            Assert.True(outcome.IsRollbackSuspected);
            using (var d = r.DekForTesting()) { Assert.True(d.ConstantTimeEquals(dek0)); }
            Assert.True(v.State()!.RekeyPending);
        }
    }

    [Fact]
    public void Krypto_3_versiegelter_Eintrag_mit_U00A0_Passwortwechsel_auf_dasselbe_ist_MasterPasswordReused()
    {
        foreach (var neu in new[] { BH.Nbsp, BH.Space })
        {
            using var t = SchutzTresor.Make(SecurityLevel.Erhoeht);
            var se = t.K.Secrets(FactorSet.SecureEnclave);
            var e = SchutzEntries.Make("Bank", EntryProtection.Hoch, BH.Nbsp);
            t.Vault.Upsert(e);
            Assert.True(t.Vault.Entries.Single(x => x.Id == e.Id).SecretsSealed);
            KT.Throws(SiegelErrorCode.MasterPasswordReused, () => t.Vault.ChangeMasterPassword(KT.Pw1, neu, se));
        }
    }

    [Fact]
    public void Krypto_3_gleich_wie_Master_Passwort_auch_bei_versiegelten_Eintraegen_mit_U00A0()
    {
        using var t = SchutzTresor.Make(SecurityLevel.Erhoeht);
        t.Vault.ChangeMasterPassword(KT.Pw1, BH.Nbsp, t.K.Secrets(FactorSet.SecureEnclave));
        var e = SchutzEntries.Make("Bank", EntryProtection.Fingerabdruck, BH.Nbsp);
        t.Vault.Upsert(e);
        Assert.Contains(e.Id, t.Vault.MasterPasswordReuse);
        foreach (var typed in new[] { BH.Nbsp, BH.Space })
        {
            var v = t.Reopen(typed);
            Assert.Contains(e.Id, v.SecurityReport().SameAsMaster);
            Assert.Contains(e.Id, v.MasterPasswordReuse);
        }
    }

    [Fact]
    public void Krypto_3_alte_Tags_bis_v4_3_erkannt_wenn_genau_so_getippt_kein_neues_Aenderungsdatum()
    {
        using var t = SchutzTresor.Make(SecurityLevel.Erhoeht);
        var se = t.K.Secrets(FactorSet.SecureEnclave);
        var versiegelt = SchutzEntries.Make("Bank", EntryProtection.Hoch, BH.Nbsp);
        var offen = SchutzEntries.Make("Mail", EntryProtection.Normal, BH.Nbsp);
        t.Vault.Upsert(versiegelt);
        t.Vault.Upsert(offen);
        var damals = KT.At(1_780_000_000);
        byte[]? altTag = null;
        // Tags auf die alte Formel zurücksetzen (so lagen sie vor v4.4 im Inhalt).
        t.Vault.Mutate(null, null, (c, _) =>
        {
            using var rk = c.ReuseKey();
            altTag = EntrySealing.LegacyReuseTag(rk, BH.Nbsp);
            foreach (var id in new[] { versiegelt.Id, offen.Id }) { c.Meta[id] = c.Meta[id] with { Tag = altTag, Changed = damals }; }
            return true;
        });
        Assert.NotNull(altTag);
        // Versiegelt: der Passwortwechsel auf genau diese Eingabe wird abgelehnt.
        KT.Throws(SiegelErrorCode.MasterPasswordReused, () => t.Vault.ChangeMasterPassword(KT.Pw1, BH.Nbsp, se));
        // Offen: beim nächsten Speichern neuer Tag, aber kein neues Änderungsdatum.
        t.Vault.Upsert(SchutzEntries.Make("Anderes", EntryProtection.Normal));
        using var content = t.Vault.ContentForTesting!;
        var meta = content.Meta[offen.Id];
        Assert.False(Bytes.Same(altTag, meta.Tag));
        Assert.Equal(damals, meta.Changed);
        using var rk2 = content.ReuseKey();
        Assert.True(Bytes.Same(EntrySealing.ReuseTag(rk2, BH.Nbsp), meta.Tag));
    }

    [Fact]
    public void Krypto_3_alter_Tag_eines_versiegelten_Eintrags_gleich_wie_Master_nach_Entsperren_mit_genau_dieser_Eingabe()
    {
        using var t = SchutzTresor.Make(SecurityLevel.Erhoeht);
        t.Vault.ChangeMasterPassword(KT.Pw1, BH.Nbsp, t.K.Secrets(FactorSet.SecureEnclave));
        var e = SchutzEntries.Make("Bank", EntryProtection.Hoch, BH.Nbsp);
        t.Vault.Upsert(e);
        t.Vault.Mutate(null, null, (c, _) =>
        {
            using var rk = c.ReuseKey();
            c.Meta[e.Id] = c.Meta[e.Id] with { Tag = EntrySealing.LegacyReuseTag(rk, BH.Nbsp) };
            return true;
        });
        var v = t.Reopen(BH.Nbsp);
        Assert.Contains(e.Id, v.SecurityReport().SameAsMaster);
        // Ehrliche Grenze: mit U+0020 getippt passt der alte Tag nicht (bis der Eintrag neu versiegelt wird).
        var w = t.Reopen(BH.Space);
        Assert.DoesNotContain(e.Id, w.SecurityReport().SameAsMaster);
    }
}

/// <summary>Funde des Fuzz-Ziels „vernichtung“ (KernVernichtungFuzzBefundeTests.swift): <c>zustand.json</c> ist nicht
/// authentisiert; der Kern nimmt ihn gesperrt so, wie er ist, darf aber nie selbst aussperren und nie eine Datei löschen, die
/// der Tresor nachweislich noch braucht.</summary>
public class VernichtungFuzzBefundeTests
{
    [Fact]
    public async Task Vernichtung_1_ein_Zustand_der_den_Entsperr_SE_Schluessel_nennt_gilt_nicht()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DeadmanDays: 7, MaxFailedAttempts: 10), [a.Id]);
        var se = BH.SeKeyId(v);
        var seDatei = BH.Platzhalter(v, se);
        v.Vault.Lock();

        // Zähler kurz vor der Schwelle, V = Entsperr-Schlüssel: ein falsches Passwort darf ihn nicht löschen.
        BH.ZustandAendern(v, st =>
        {
            st.VKeyId = se;
            st.FailedAttempts = 9;
        });
        Assert.Equal(DestructionStatus.Off, v.Store.GetDestructionStatus());
        KT.Throws(SiegelErrorCode.WrongPassword, () => v.TryUnlock(KT.Pw2));
        Assert.True(File.Exists(seDatei));
        Assert.DoesNotContain(se, v.Eraser.Destroyed);

        // Abgelaufene Frist bzw. ein Vermerk, der ihn als vernichtet nennt: ebenso nichts.
        BH.ZustandAendern(v, st =>
        {
            st.VKeyId = se;
            st.LastGenuineUnlock = KT.At(1_700_000_000);
        });
        Assert.False(v.Store.CheckDeadman(KT.At(1_800_000_000)));
        BH.ZustandAendern(v, st =>
        {
            st.VKeyId = v.VKeyId;
            st.DestroyedInfo = new DestructionState.Destroyed(se, DestructionTrigger.Deadman, KT.At(1_700_000_000));
        });
        Assert.False(v.Store.CheckDeadman(KT.At(1_800_000_000)));
        Assert.True(File.Exists(seDatei));
        Assert.True(File.Exists(v.VPath));
        Assert.Empty(v.Eraser.Destroyed);

        // Das echte Entsperren stellt den Zustand aus dem Inhalt wieder her; der Eintrag ist lesbar.
        v.Reopen();
        Assert.Equal(v.VKeyId, v.State()?.VKeyId);
        Assert.Null(v.State()?.DestroyedInfo);
        await VH.Same(a, v.Reveal(a.Id));
    }

    [Fact]
    public async Task Vernichtung_2_echtes_Entsperren_loescht_als_alte_Ablage_nie_einen_gebrauchten_Schluessel()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        var b = v.Add("Mail", EntryProtection.Maximal);
        var o = v.Add("Notiz", EntryProtection.Fingerabdruck);
        await v.Einrichten(new DestructionSettings(DeadmanDays: 30, DuressEnabled: true), [a.Id], VTresor.DuressPw);
        var se = BH.SeKeyId(v);
        var eintrag = v.T.P.EntryKeyId;
        var seDatei = BH.Platzhalter(v, se);
        var eintragDatei = BH.Platzhalter(v, eintrag);
        Guid ablage;
        using (var c = v.Vault.ContentForTesting!) { ablage = c.Destruction!.Duress!.FileId; }

        foreach (var genannt in new[] { eintrag, v.VKeyId, se })
        {
            BH.ZustandAendern(v, st =>
            {
                st.Settings = new DestructionSettings(DuressEnabled: true);
                st.DuressFileId = genannt;
            });
            v.Reopen();
            Assert.True(File.Exists(eintragDatei));
            Assert.True(File.Exists(seDatei));
            Assert.True(File.Exists(v.VPath));
            Assert.Equal(ablage, v.State()?.DuressFileId);
            Assert.Empty(v.Vault.DestroyedEntries);
            await VH.Same(a, v.Reveal(a.Id));
            await VH.Same(b, v.Reveal(b.Id));
            await VH.Same(o, v.Reveal(o.Id));
        }
        // Auch nach einem Speichern und aus einem fremden Zustand (andere vaultID).
        var fremd = v.State()! with { VaultId = Guid.NewGuid() };
        fremd.DuressFileId = v.VKeyId;
        DestructionState.Write(fremd, v.Hardware);
        v.Vault.Upsert(SchutzEntries.Make("Neu", EntryProtection.Maximal));
        Assert.True(File.Exists(v.VPath));
        Assert.Equal(v.Vault.VaultId, v.State()?.VaultId);
        await VH.Same(a, v.Reveal(a.Id));

        // Eine wirklich veraltete Ablage (nicht in Gebrauch) wird weiter entfernt – nur, wenn die Datei eine Ablage mit
        // dieser Kennung ist (vernichtung-7); eine andere Datei unter diesem Namen bleibt.
        var alt = Guid.NewGuid();
        var altDatei = BH.Platzhalter(v, alt);
        BH.ZustandAendern(v, st => st.DuressFileId = alt);
        v.Reopen();
        Assert.True(File.Exists(altDatei));
        var f = v.Store.ReadDuressFile(ablage)!;
        File.WriteAllBytes(altDatei, (f with { FileId = alt }).Encoded());
        BH.ZustandAendern(v, st => st.DuressFileId = alt);
        v.Reopen();
        Assert.False(File.Exists(altDatei));
    }

    [Fact]
    public async Task Vernichtung_3_checkDeadman_an_den_Grenzen_der_Uhr()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        using (KT.Now(VH.T0)) { await v.Einrichten(new DestructionSettings(DeadmanDays: 7), [a.Id]); }
        v.Vault.Lock();
        var vorher = File.ReadAllBytes(v.StatePath);
        // Unbrauchbar alte Uhr (Gegenstück zu −∞/NaN in Swift; DateTimeOffset kennt kein Unendlich).
        Assert.False(v.Store.CheckDeadman(DateTimeOffset.MinValue));
        Assert.False(v.Store.CheckDeadman(KT.At(0)));
        Assert.True(File.Exists(v.VPath));
        Assert.Empty(v.Eraser.Destroyed);
        Assert.Equal(vorher, File.ReadAllBytes(v.StatePath));
        // Endliche Zeit weit in der Zukunft vernichtet wie immer; der Vermerk bleibt lesbar.
        Assert.True(v.Store.CheckDeadman(DateTimeOffset.MaxValue));
        Assert.False(File.Exists(v.VPath));
        Assert.Equal(DestructionTrigger.Deadman, v.Store.GetDestructionStatus().DestroyedTrigger);
        // Der Vermerk liegt am Rand des darstellbaren Bereichs und ist ein Fixpunkt des JSON-Rundlaufs.
        var am = Clock.Canonical(DateTimeOffset.MaxValue);
        Assert.Equal(am, v.Store.GetDestructionStatus().DestroyedAt);
        Assert.Equal(am, Clock.Canonical(am));
        Assert.Equal(am, Clock.FromSeconds(Clock.ToSeconds(am)));
        Assert.True(DateTimeOffset.MaxValue - am < TimeSpan.FromSeconds(1));
        Assert.Equal(am, DestructionState.Read(v.Hardware)?.DestroyedInfo?.At);
    }

    [Fact]
    public async Task Vernichtung_4_zustand_json_zwischen_Probe_und_Vermerk_getauscht_nennt_er_den_SE_Schluessel_wird_nichts_geloescht()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DuressEnabled: true), [a.Id], VTresor.DuressPw);
        var se = BH.SeKeyId(v);
        var seDatei = BH.Platzhalter(v, se);
        v.Vault.Lock();
        // Der Haken läuft nach beiden Argon2 (Vernichtungs-Passwort erkannt) und vor dem Vermerk.
        var hw = v.Hardware;
        void Haken()
        {
            if (DestructionState.Read(hw) is not { } st) { return; }
            st.VKeyId = se;
            DestructionState.Write(st, hw);
        }
        using (KT.Hook(() => TestHooks.AfterDuressArgon = Haken, () => TestHooks.AfterDuressArgon = null))
        {
            using var dv = v.TryUnlock(VTresor.DuressPw);
        }
        Assert.True(File.Exists(seDatei));
        Assert.Empty(v.Eraser.Destroyed);
        // Der getauschte Zustand gilt nicht; das echte Entsperren stellt ihn aus dem Inhalt wieder her.
        Assert.Equal(DestructionStatus.Off, v.Store.GetDestructionStatus());
        v.Reopen();
        Assert.Equal(v.VKeyId, v.State()?.VKeyId);
        Assert.True(File.Exists(seDatei));
        await VH.Same(a, v.Reveal(a.Id));
    }

    [Fact]
    public async Task Vernichtung_5_Hardware_Ordner_nicht_beschreibbar_checkDeadman_meldet_Io_die_naechste_Pruefung_holt_es_nach()
    {
        // Nur auf dem Mac nachstellbar (chflags uchg); unter Windows entspräche das einer Verweigern-ACL.
        if (!OperatingSystem.IsMacOS()) { return; }
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        using (KT.Now(VH.T0)) { await v.Einrichten(new DestructionSettings(DeadmanDays: 7), [a.Id]); }
        v.Vault.Lock();
        var vorher = File.ReadAllBytes(v.VPath);
        var zustand = File.ReadAllBytes(v.StatePath);
        Assert.Equal(0, BH.Chflags(v.Hardware, BH.UfImmutable));
        try
        {
            KT.Throws(SiegelErrorCode.Io, "destruction.write", () => v.Store.CheckDeadman(VH.T(8 * VH.Tag)));
            // V ist überschrieben (unbrauchbar), aber noch da; ohne Vermerk wiederholt die nächste Prüfung das Vernichten.
            Assert.NotEqual(vorher, File.ReadAllBytes(v.VPath));
            Assert.Equal(zustand, File.ReadAllBytes(v.StatePath));
        }
        finally
        {
            BH.Chflags(v.Hardware, 0);
        }
        Assert.True(v.Store.CheckDeadman(VH.T(9 * VH.Tag)));
        Assert.False(File.Exists(v.VPath));
        Assert.Equal(DestructionTrigger.Deadman, v.Store.GetDestructionStatus().DestroyedTrigger);
    }

    [Fact]
    public async Task Tiefenverteidigung_Ablage_Kennung_und_V_heissen_nie_wie_ein_anderer_SE_Schluessel()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DuressEnabled: true), [a.Id], VTresor.DuressPw);
        using var c = v.Vault.ContentForTesting!;
        var se = BH.SeKeyId(v);
        var eintrag = c.EntryFactors.SecureEnclave!.KeyId;
        var ablage = c.Destruction!.Duress!.FileId;
        // Lesen: Ablage-Kennung = V bzw. Eintrags-SE-Schlüssel → verworfen (sonst überschriebe das Kapseln sie).
        string text;
        var (p, _) = PayloadCodec.Encode(c);
        using (p) { text = PayloadCodec.JsonStringForTesting(p)!; }
        foreach (var id in new[] { v.VKeyId, eintrag })
        {
            using var boese = SchutzTests.Padded(text.Replace(Bytes.GuidText(ablage), Bytes.GuidText(id), StringComparison.Ordinal));
            KT.Corrupt("payload.destruction", () => PayloadCodec.Decode(boese).Content.Dispose());
        }
        // Schreiben: dasselbe ist ein Programmfehler.
        using (var x = c.Clone())
        {
            x.Destruction = c.Destruction with { Duress = c.Destruction.Duress with { FileId = v.VKeyId } };
            KT.Throws(SiegelErrorCode.Crypto, "payload.destruction", () => PayloadCodec.Encode(x).Padded.Dispose());
        }
        // V bzw. Ablage = Entsperr-SE-Schlüssel des Kopfes: Lesen (DecryptPayload) und Schreiben (Persist) lehnen ab.
        using (var scope = v.Vault.Enter())
        {
            var s = scope.State;
            foreach (var setze in new Action<VaultContent>[]
                     {
                         y => y.Destruction = y.Destruction! with { VKey = y.Destruction.VKey! with { KeyId = se } },
                         y => y.Destruction = y.Destruction! with { Duress = y.Destruction.Duress! with { FileId = se } },
                     })
            {
                using var y = c.Clone();
                setze(y);
                var (gebaut, _) = VaultCrypto.BuildFile(s.Header, s.Slots, s.Generation + 1, s.Dek, y);
                KT.Corrupt("payload.destruction", () => VaultCrypto.DecryptPayload(VaultFile.Parse(gebaut), s.Dek).Content.Dispose());
                KT.Throws(SiegelErrorCode.Crypto, "payload.destruction", () => v.Store.Persist(s.Header, s.Slots, s.Dek, y, s.Generation,
                    new VaultStore.DiskExpectation.Generation(s.Header.Uuid, s.Generation), null, s.DuressBinding).Content.Dispose());
            }
        }
        // Nichts davon wurde geschrieben: der Tresor öffnet wie zuvor, der Eintrag ist lesbar.
        v.Reopen();
        await VH.Same(a, v.Reveal(a.Id));
    }

    [Fact]
    public async Task Vernichtung_6_ohne_lesbare_Tresordatei_gilt_kein_Zustand_der_den_SE_Schluessel_einer_Sicherung_nennt()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        using (KT.Now(VH.T0)) { await v.Einrichten(new DestructionSettings(DeadmanDays: 7, MaxFailedAttempts: 10), [a.Id]); }
        var se = BH.SeKeyId(v);
        var seDatei = BH.Platzhalter(v, se);
        var level = v.Vault.Level;
        v.Vault.Lock();
        Assert.NotEmpty(v.Store.Backups());
        // Die Tresordatei fehlt (z. B. beschädigt beiseitegelegt); der Zustand nennt den Entsperr-SE-Schlüssel als V.
        var tresor = File.ReadAllBytes(v.Store.VaultPath);
        File.Delete(v.Store.VaultPath);
        BH.ZustandAendern(v, st =>
        {
            st.VKeyId = se;
            st.FailedAttempts = 9;
        });
        Assert.False(v.Store.CheckDeadman(VH.T(8 * VH.Tag)));
        KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.RestoreNewestReadableBackup(KT.Pw2, v.T.K.Secrets(level.Factors())));
        Assert.True(File.Exists(seDatei));
        Assert.Empty(v.Eraser.Destroyed);
        Assert.Equal(DestructionStatus.Off, v.Store.GetDestructionStatus());
        // Nennt er V, gilt er ohne Tresordatei weiter (Totmann-Schalter wie bisher).
        BH.ZustandAendern(v, st => st.VKeyId = v.VKeyId);
        Assert.True(v.Store.CheckDeadman(VH.T(8 * VH.Tag)));
        Assert.False(File.Exists(v.VPath));
        Assert.True(File.Exists(seDatei));
        File.WriteAllBytes(v.Store.VaultPath, tresor);
        v.Reopen();
        Assert.Equal([a.Id], v.Vault.DestroyedEntries);
    }

    [Fact]
    public async Task Vernichtung_7_der_Notfallweg_loescht_als_alte_Ablage_nur_eine_Ablage_nie_einen_SE_Schluessel()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        var b = v.Add("Mail", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DuressEnabled: true), [a.Id], VTresor.DuressPw);
        var se = BH.SeKeyId(v);
        var seDatei = BH.Platzhalter(v, se);
        var eintragDatei = BH.Platzhalter(v, v.T.P.EntryKeyId);
        var vaultId = v.Vault.VaultId;
        v.Vault.Lock();
        var kit = v.T.Kit!;
        foreach (var genannt in new[] { se, v.T.P.EntryKeyId, v.VKeyId })
        {
            // Der Zustand nennt den Schlüssel als Ablage; danach der Notfallweg (neuer Kopf ohne Faktoren).
            BH.ZustandAendern(v, st =>
            {
                st.Settings = new DestructionSettings(DuressEnabled: true);
                st.DuressFileId = genannt;
            });
            using (var r = v.Store.Recover([kit.Shares[0].Formatted, kit.Shares[2].Formatted], KT.Pw2, KT.Kdf))
            {
                Assert.Contains(r.Entries, e => e.Id == b.Id);
            }
            Assert.True(File.Exists(seDatei));
            Assert.True(File.Exists(eintragDatei));
            Assert.True(File.Exists(v.VPath));
            // Ältere Sicherungen (Stufe 4) öffnen weiter mit Passwort und Faktoren, auch die Einträge.
            var alt = v.Store.Backups().First(x => VaultStore.ReadHeader(x.Path)?.FactorFields.SeKeyId == se);
            using (var c = v.T.F.OpenFile(alt.Path, factors: v.T.K.Secrets(SecurityLevel.Maximal.Factors())))
            {
                Assert.Contains(c.Entries, e => e.Id == b.Id);
            }
            // Für die nächste Runde: Zustand wie vor dem Notfallweg (gültig).
            DestructionState.Write(new DestructionState(vaultId), v.Hardware);
        }
    }

    [Fact]
    public async Task Vernichtung_8_das_Kapseln_der_Ablage_ersetzt_nur_eine_Ablage_nie_einen_Schluessel_unter_diesem_Namen()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DuressEnabled: true), [a.Id], VTresor.DuressPw);
        DestructionConfig.DuressInfo ablage;
        using (var c = v.Vault.ContentForTesting!) { ablage = c.Destruction!.Duress!; }
        var vorher = File.ReadAllBytes(v.VPath);
        using (var scope = v.Vault.Enter())
        {
            var s = scope.State;
            // Kennung, unter der ein Schlüssel liegt (hier V, 32 B roh; ebenso ein SE-Schlüssel mit anderer Bloblänge).
            KT.Throws(SiegelErrorCode.Io, "destruction.write",
                () => v.Store.WriteDuressFile(ablage with { FileId = v.VKeyId }, s.Dek, s.DuressBinding!, s.Header.VaultId));
        }
        Assert.Equal(vorher, File.ReadAllBytes(v.VPath));
        await VH.Same(a, v.Reveal(a.Id));
        // Eine beschädigte Ablage (Form intakt) heilt beim nächsten echten Entsperren.
        var path = v.Store.HardwareKeyPath(ablage.FileId);
        var b = File.ReadAllBytes(path);
        b[100] ^= 0x01;
        File.WriteAllBytes(path, b);
        Assert.Null(v.Store.ReadDuressFile(ablage.FileId));
        v.Reopen();
        Assert.NotNull(v.Store.ReadDuressFile(ablage.FileId));
        Assert.True(v.DuressEnvelopeOpens());
    }
}
#endif
