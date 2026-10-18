#if DEBUG
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Gemeinsames der Selbstvernichtungs-Tests (Gegenstück zu KernVernichtungTests.swift).</summary>
internal static class VH
{
    internal const double Tag = 86_400;

    internal static readonly DateTimeOffset T0 = KT.At(1_800_000_000);

    internal static DateTimeOffset T(double seconds) => T0.AddSeconds(seconds);

    internal static void SameSet(IEnumerable<Guid> expected, IEnumerable<Guid> got) =>
        Assert.Equal(expected.Order().ToArray(), got.Order().ToArray());

    internal static async Task Same(VaultEntry expected, Task<EntrySecrets> got) => SchutzEntries.SameSecrets(expected, await got);

    internal static EntryKeyEnrollment RandomV() => new(Guid.NewGuid(), P256.RandomPoint());

    /// <summary>Unter Windows tragen Ablage, Zustand und V das Attribut <c>NotContentIndexed</c> (Gegenstück zu
    /// <c>isExcludedFromBackup</c>); anderswo gibt es nichts zu prüfen.</summary>
    internal static void ExcludedFromIndexing(string path)
    {
        if (!OperatingSystem.IsWindows()) { return; }
        Assert.True(File.GetAttributes(path).HasFlag(FileAttributes.NotContentIndexed));
    }
}

/// <summary>Selbstvernichtung: Einrichten (§23.3).</summary>
public class VernichtungEinrichtenTests
{
    [Fact]
    public async Task Markieren_nur_Schutz_4_5_vernichtbar_an_V_ohne_Notfall_Umschlag()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        var b = v.Add("Mail", EntryProtection.Fingerabdruck);
        var c = v.Add("Krypto", EntryProtection.Festung);
        await KT.ThrowsAsync(SiegelErrorCode.NotAllowedAtLevel, () => v.Einrichten(DestructionSettings.Off, [b.Id]));

        var report = await v.Einrichten(DestructionSettings.Off, [a.Id, c.Id]);
        Assert.True(report?.IsComplete);
        VH.SameSet([a.Id, c.Id], v.Vault.DestructibleEntries);
        Assert.Equal(v.VKeyId, v.Vault.DestructionKeyId);
        using (var content = v.Vault.ContentForTesting!)
        {
            VH.SameSet([a.Id, c.Id], content.Destructible.Keys);
            Assert.False(content.Sealed.ContainsKey(a.Id));
            Assert.False(content.Sealed.ContainsKey(c.Id));
            Assert.True(content.Sealed.ContainsKey(b.Id));
            // Kein Notfall-Umschlag, keine Gruppe für die vernichtbaren Masken.
            Assert.Equal([FactorSet.SecureEnclave], content.RecoveryGroups.Select(g => g.Mask).Distinct());
        }
        var json = v.T.F.JsonOnDisk();
        Assert.Contains("\"recovery\":null", json, StringComparison.Ordinal);
        Assert.Contains("\"destruction\":{\"duress\":null,\"settings\":{\"deadmanDays\":null", json, StringComparison.Ordinal);
        Assert.Contains("\"vKey\":{\"keyID\":\"" + Bytes.GuidText(v.VKeyId), json, StringComparison.Ordinal);

        // Aufdecken über V (+ Karte, + Sicherheitsschlüssel); der Eintrags-SE-Schlüssel wird nicht gefragt.
        var before = v.T.P.Count(FactorKind.SecureEnclave);
        await VH.Same(a, v.Reveal(a.Id));
        await VH.Same(c, v.Reveal(c.Id));
        Assert.Equal(2, v.Provider.VCount);
        Assert.Equal(before, v.T.P.Count(FactorKind.SecureEnclave));
        await VH.Same(b, v.Reveal(b.Id));
        // Liste und offene Felder bleiben normal.
        Assert.Equal(3, v.Vault.Entries.Count);
        Assert.True(v.Vault.Entries.Single(e => e.Id == a.Id).SecretsSealed);
        Assert.Equal(a.Title, v.Vault.Entries.Single(e => e.Id == a.Id).Title);
        // Nach dem Neu-Öffnen genauso.
        v.Reopen();
        VH.SameSet([a.Id, c.Id], v.Vault.DestructibleEntries);
        await VH.Same(a, v.Reveal(a.Id));
    }

    [Fact]
    public async Task Stufe_1_bis_3_einschalten_und_markieren_abgelehnt_alles_aus_geht()
    {
        using var v = new VTresor(SecurityLevel.Hoch);
        var a = v.Add("Bank", EntryProtection.Maximal);
        await KT.ThrowsAsync(SiegelErrorCode.NotAllowedAtLevel, () => v.Einrichten(new DestructionSettings(DeadmanDays: 30), []));
        await KT.ThrowsAsync(SiegelErrorCode.NotAllowedAtLevel, () => v.Einrichten(DestructionSettings.Off, [a.Id]));
        await KT.ThrowsAsync(SiegelErrorCode.NotAllowedAtLevel,
            () => v.Einrichten(new DestructionSettings(DuressEnabled: true), [], VTresor.DuressPw));
        Assert.Null(await v.Einrichten(DestructionSettings.Off, [], vKey: false));
        using (var c = v.Vault.ContentForTesting!) { Assert.Null(c.Destruction); }
        Assert.False(File.Exists(v.StatePath));
    }

    [Fact]
    public async Task Falsche_Konfigurationen_werden_abgelehnt_ohne_etwas_zu_schreiben()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        var generation = v.Vault.Generation;
        const string pw = VTresor.DuressPw;
        await KT.ThrowsAsync(SiegelErrorCode.Io, "destruction.deadmanDays", () => v.Einrichten(new DestructionSettings(DeadmanDays: 6), []));
        await KT.ThrowsAsync(SiegelErrorCode.Io, "destruction.deadmanDays", () => v.Einrichten(new DestructionSettings(DeadmanDays: 366), []));
        await KT.ThrowsAsync(SiegelErrorCode.Io, "destruction.maxFailedAttempts",
            () => v.Einrichten(new DestructionSettings(MaxFailedAttempts: 9), []));
        await KT.ThrowsAsync(SiegelErrorCode.Io, "destruction.maxFailedAttempts",
            () => v.Einrichten(new DestructionSettings(MaxFailedAttempts: 101), []));
        // Vernichtungs-Passwort: fehlt beim Einschalten, ist mitgegeben ohne Einschalten, zu schwach, = Master.
        await KT.ThrowsAsync(SiegelErrorCode.Io, "destruction.duressPassword", () => v.Einrichten(new DestructionSettings(DuressEnabled: true), []));
        await KT.ThrowsAsync(SiegelErrorCode.Io, "destruction.duressPassword", () => v.Einrichten(new DestructionSettings(DeadmanDays: 30), [], pw));
        await KT.ThrowsAsync(SiegelErrorCode.PasswordTooWeak, () => v.Einrichten(new DestructionSettings(DuressEnabled: true), [], KT.Weak));
        await KT.ThrowsAsync(SiegelErrorCode.MasterPasswordReused, () => v.Einrichten(new DestructionSettings(DuressEnabled: true), [], KT.Pw1));
        // Ohne V, falsches Passwort, unbekannter Eintrag, V = Eintrags-SE-Schlüssel, ungültiger Punkt.
        await KT.ThrowsAsync(SiegelErrorCode.FactorMissing, "secureEnclave",
            () => v.Einrichten(new DestructionSettings(DeadmanDays: 30), [], vKey: false));
        await KT.ThrowsAsync(SiegelErrorCode.WrongPassword, () => v.Einrichten(new DestructionSettings(DeadmanDays: 30), [], password: KT.Pw2));
        await KT.ThrowsAsync(SiegelErrorCode.Io, "entry.notFound", () => v.Einrichten(DestructionSettings.Off, [Guid.NewGuid()]));
        var gleich = new EntryKeyEnrollment(v.T.P.EntryKeyId, P256.Encode(v.VKey));
        await KT.ThrowsAsync(SiegelErrorCode.Crypto, "factor.keyID", () => v.Vault.ConfigureDestructionAsync(new DestructionSettings(DeadmanDays: 30),
            null, new HashSet<Guid>(), KT.Pw1, v.Factors(), gleich, v.Provider));
        var kaputt = new EntryKeyEnrollment(Guid.NewGuid(), KT.Repeat(4, 65));
        await KT.ThrowsAsync(SiegelErrorCode.Crypto, "factor.publicKey", () => v.Vault.ConfigureDestructionAsync(new DestructionSettings(DeadmanDays: 30),
            null, new HashSet<Guid>(), KT.Pw1, v.Factors(), kaputt, v.Provider));
        // Markieren braucht die Geheimteile: synchron → FactorMissing; async ohne Anbieter ebenso.
        KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => v.Vault.ConfigureDestruction(DestructionSettings.Off, null,
            new HashSet<Guid> { a.Id }, KT.Pw1, v.Factors(), v.VEnrollment));
        await KT.ThrowsAsync(SiegelErrorCode.FactorMissing, "secureEnclave", () => v.Vault.ConfigureDestructionAsync(DestructionSettings.Off, null,
            new HashSet<Guid> { a.Id }, KT.Pw1, v.Factors(), v.VEnrollment, null));
        Assert.Equal(generation, v.Vault.Generation);
        Assert.False(File.Exists(v.StatePath));
        Assert.Equal(0, v.T.P.Count(FactorKind.SecureEnclave));

        // Gültig einrichten; danach ein anderes V, solange Einträge daran hängen → abgelehnt.
        await v.Einrichten(new DestructionSettings(DeadmanDays: 30), [a.Id]);
        await KT.ThrowsAsync(SiegelErrorCode.NotAllowedAtLevel, () => v.Vault.ConfigureDestructionAsync(new DestructionSettings(DeadmanDays: 30),
            null, new HashSet<Guid> { a.Id }, KT.Pw1, v.Factors(), VH.RandomV(), v.Provider));
        // Nur Einstellungen ändern geht auch synchron (nichts neu zu versiegeln).
        v.Vault.ConfigureDestruction(new DestructionSettings(60, 20), null, new HashSet<Guid> { a.Id }, KT.Pw1, v.Factors(), null);
        Assert.Equal(new DestructionSettings(60, 20), v.Vault.DestructionSettings);
        Assert.Equal(new DestructionSettings(60, 20), v.Store.GetDestructionStatus().Settings);
    }

    [Fact]
    public async Task Markieren_entfernt_aeltere_Sicherungen()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        v.Add("Mail", EntryProtection.Fingerabdruck);
        v.Add("Shop", EntryProtection.Maximal);
        Assert.True(v.T.F.LocalBackups().Count >= 3);
        var report = await v.Einrichten(DestructionSettings.Off, [a.Id]);
        Assert.NotNull(report);
        Assert.True(report.IsComplete);
        var backups = v.T.F.LocalBackups();
        Assert.NotEmpty(backups);
        foreach (var b in backups)
        {
            using var c = v.T.F.OpenFile(b.Path, factors: v.Factors());
            Assert.False(c.Sealed.ContainsKey(a.Id));
            Assert.True(c.Destructible.ContainsKey(a.Id));
        }
        // Nur Einstellungen ändern bereinigt nichts.
        v.Add("Neu", EntryProtection.Maximal);
        var count = v.T.F.LocalBackups().Count;
        Assert.Null(await v.Einrichten(new DestructionSettings(DeadmanDays: 30), [a.Id]));
        Assert.True(v.T.F.LocalBackups().Count >= count);
    }

    [Fact]
    public async Task Waehrend_der_Freigabe_geaendert_gilt_das_Geoeffnete_nicht_mehr()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        var vault = v.Vault;
        v.T.P.OnAnswer(() =>
        {
            try
            {
                vault.SetProtection(EntryProtection.Maximal, a.Id, new EntrySecrets { Password = "Inzwischen-geaendert-1" });
            }
            catch (SiegelException)
            {
                // wie try? im Original
            }
        });
        await KT.ThrowsAsync(SiegelErrorCode.Io, "entry.stale", () => v.Einrichten(DestructionSettings.Off, [a.Id]));
        v.T.P.OnAnswer(null);
        Assert.Empty(v.Vault.DestructibleEntries);
        Assert.Equal("Inzwischen-geaendert-1", (await v.Reveal(a.Id)).Password);
    }

    [Fact]
    public async Task Befund_ablaeufe_5_markiert_ohne_Ausloeser_nennt_V_offen_und_gesperrt()
    {
        using var v = new VTresor();
        var a = v.Add("Krypto", EntryProtection.Maximal);
        Assert.False(v.Vault.DestructionStatus.KeyConfigured);
        Assert.False(v.Store.GetDestructionStatus().KeyConfigured);
        await v.Einrichten(DestructionSettings.Off, [a.Id]);
        var offen = v.Vault.DestructionStatus;
        Assert.False(offen.Settings.AnyTriggerEnabled);
        Assert.True(offen.KeyConfigured);
        v.Vault.Lock();
        var gesperrt = v.Store.GetDestructionStatus();
        Assert.False(gesperrt.Settings.AnyTriggerEnabled);
        Assert.True(gesperrt.KeyConfigured);
        Assert.NotEqual(DestructionStatus.Off, gesperrt);
        v.Reopen();
        // Alles aus: V weg, Stand wieder wie nie eingerichtet.
        await v.Einrichten(DestructionSettings.Off, [], vKey: false);
        Assert.False(v.Vault.DestructionStatus.KeyConfigured);
        Assert.Equal(DestructionStatus.Off, v.Store.GetDestructionStatus());
    }

    [Fact]
    public async Task Entmarkieren_versiegelt_normal_alles_aus_entfernt_V()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        var c = v.Add("Krypto", EntryProtection.Festung);
        await v.Einrichten(new DestructionSettings(DeadmanDays: 30), [a.Id, c.Id]);
        var vCalls = v.Provider.VCount;
        await v.Einrichten(new DestructionSettings(DeadmanDays: 30), [c.Id]);
        Assert.Equal(vCalls + 1, v.Provider.VCount);
        VH.SameSet([c.Id], v.Vault.DestructibleEntries);
        using (var content = v.Vault.ContentForTesting!)
        {
            Assert.True(content.Sealed.ContainsKey(a.Id));
            Assert.False(content.Destructible.ContainsKey(a.Id));
        }
        await VH.Same(a, v.Reveal(a.Id));

        // Alles aus: c wieder normal, V vernichtet (nicht mehr gebraucht), Zustand weg.
        await v.Einrichten(DestructionSettings.Off, [], vKey: false);
        using (var content = v.Vault.ContentForTesting!) { Assert.Null(content.Destruction); }
        Assert.Empty(v.Vault.DestructibleEntries);
        Assert.Equal([v.VKeyId], v.Eraser.Destroyed);
        Assert.False(File.Exists(v.VPath));
        Assert.False(File.Exists(v.StatePath));
        await VH.Same(c, v.Reveal(c.Id));
        // Beide wieder über den Notfallcode lesbar.
        var kit = v.T.Kit!;
        v.Vault.Lock();
        using var r = v.Store.Recover([kit.Shares[0].Formatted, kit.Shares[2].Formatted], KT.Pw2, KT.Kdf);
        Assert.Equal(a.Password, r.Entries.Single(e => e.Id == a.Id).Password);
        Assert.Equal(c.Notes, r.Entries.Single(e => e.Id == c.Id).Notes);
    }

    [Fact]
    public async Task Stufe_KDF_Master_Passwort_und_Schutz_respektieren_die_Selbstvernichtung()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DuressEnabled: true), [a.Id], VTresor.DuressPw);
        var f = v.Factors();
        KT.Throws(SiegelErrorCode.NotAllowedAtLevel, () => v.Vault.ChangeSecurityLevel(SecurityLevel.Hoch, KT.Pw1, f, new NewFactorMaterial(), null, []));
        KT.Throws(SiegelErrorCode.NotAllowedAtLevel, () => v.Vault.ChangeMasterPassword(KT.Pw1, KT.Pw1, f, new KdfParameters(3, 64UL << 10)));
        KT.Throws(SiegelErrorCode.MasterPasswordReused, () => v.Vault.ChangeMasterPassword(KT.Pw1, VTresor.DuressPw, f));
        // Schutz: unter 4 nicht (erst entmarkieren), 4 → 5 bleibt vernichtbar.
        var s = await v.Reveal(a.Id);
        KT.Throws(SiegelErrorCode.NotAllowedAtLevel, () => v.Vault.SetProtection(EntryProtection.Hoch, a.Id, s));
        v.Vault.SetProtection(EntryProtection.Festung, a.Id, s.ReplacingPassword("Neu-123!"));
        VH.SameSet([a.Id], v.Vault.DestructibleEntries);
        Assert.Equal("Neu-123!", (await v.Reveal(a.Id)).Password);
        // Eine andere Karte geht nicht (Stufe 4 öffnet mit ihr); den Eintrags-SE-Schlüssel ersetzen geht, denn der
        // vernichtbare Eintrag hängt an V, nicht an ihm.
        KT.Throws(SiegelErrorCode.WrongCard, () => v.Vault.EnrollFactors(new NewFactorMaterial(Card: new CardEnrollment(CardCode.Generate())), KT.Pw1, f));
        v.Vault.EnrollFactors(new NewFactorMaterial(EntryKey: VH.RandomV()), KT.Pw1, v.Factors());
        Assert.Equal("Neu-123!", (await v.Reveal(a.Id)).Password);
        // Stufe 4 → 5 geht (gleiches KDF-Profil), der Eintrag bleibt vernichtbar.
        v.Vault.ChangeSecurityLevel(SecurityLevel.Festung, KT.Pw1, v.T.K.Secrets(FactorSet.All), new NewFactorMaterial(), null, []);
        Assert.Equal(SecurityLevel.Festung, v.Vault.Level);
        VH.SameSet([a.Id], v.Vault.DestructibleEntries);
        Assert.True(v.DuressEnvelopeOpens());
    }
}

/// <summary>Selbstvernichtung: Auslöser (§23.2).</summary>
public class VernichtungAusloeserTests
{
    [Fact]
    public async Task Totmann_vernichtet_nach_Ablauf_auch_gesperrt_danach_nur_noch_entfernen()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        var b = v.Add("Mail", EntryProtection.Maximal);
        var o = v.Add("Notiz", EntryProtection.Fingerabdruck);
        using (KT.Now(VH.T0)) { await v.Einrichten(new DestructionSettings(DeadmanDays: 7), [a.Id]); }
        var status = v.Store.GetDestructionStatus();
        Assert.Equal(VH.T0, status.LastGenuineUnlock);
        Assert.Equal(VH.T(7 * VH.Tag), status.Deadline);
        Assert.False(status.DeadlineIsNear(VH.T(5 * VH.Tag)));
        Assert.True(status.DeadlineIsNear(VH.T(5.5 * VH.Tag)));
        v.Vault.Lock();

        Assert.False(v.Store.CheckDeadman(VH.T(7 * VH.Tag - 1)));
        Assert.True(File.Exists(v.VPath));
        Assert.True(v.Store.CheckDeadman(VH.T(7 * VH.Tag)));
        Assert.Equal([v.VKeyId], v.Eraser.Destroyed);
        Assert.False(File.Exists(v.VPath));
        var after = v.Store.GetDestructionStatus();
        Assert.Equal(DestructionTrigger.Deadman, after.DestroyedTrigger);
        Assert.Equal(VH.T(7 * VH.Tag), after.DestroyedAt);
        Assert.False(v.Store.CheckDeadman(VH.T(30 * VH.Tag)));
        Assert.Equal([v.VKeyId], v.Eraser.Destroyed);

        // Echtes Entsperren: Meldung, Eintrag unlesbar (ohne Anfrage an V), die anderen unberührt.
        v.Reopen();
        Assert.False(v.Vault.IsDuressSession);
        Assert.Equal([a.Id], v.Vault.DestroyedEntries);
        Assert.Equal(DestructionTrigger.Deadman, v.Vault.DestructionStatus.DestroyedTrigger);
        Assert.Null(v.Vault.DestructionKeyId);
        var calls = v.Provider.VCount;
        await KT.ThrowsAsync(SiegelErrorCode.FactorUnavailable, "secureEnclave", () => v.Reveal(a.Id));
        Assert.Equal(calls, v.Provider.VCount);
        await VH.Same(b, v.Reveal(b.Id));
        await VH.Same(o, v.Reveal(o.Id));
        KT.Throws(SiegelErrorCode.Io, "entry.destroyed", () => v.Vault.SetProtection(EntryProtection.Festung, a.Id, new EntrySecrets()));
        await KT.ThrowsAsync(SiegelErrorCode.Io, "destruction.destroyed", () => v.Einrichten(new DestructionSettings(DeadmanDays: 7), []));

        // Entfernen: Eintrag weg, Selbstvernichtung aus, Zustand weg.
        v.Vault.RemoveDestroyedEntries();
        Assert.DoesNotContain(v.Vault.Entries, e => e.Id == a.Id);
        Assert.Empty(v.Vault.DestroyedEntries);
        Assert.Equal(DestructionSettings.Off, v.Vault.DestructionSettings);
        Assert.False(File.Exists(v.StatePath));
        Assert.Equal(DestructionStatus.Off, v.Store.GetDestructionStatus());
        await VH.Same(b, v.Reveal(b.Id));
        // Neu einrichten mit neuem V geht wieder (Software-V des Anbieters ersetzen).
        using var neu = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var nId = Guid.NewGuid();
        await v.Vault.ConfigureDestructionAsync(new DestructionSettings(DeadmanDays: 7), null, new HashSet<Guid> { b.Id }, KT.Pw1, v.Factors(),
            new EntryKeyEnrollment(nId, P256.Encode(neu)), v.Provider);
        VH.SameSet([b.Id], v.Vault.DestructibleEntries);
    }

    [Fact]
    public async Task Totmann_greift_auch_beim_Entsperren_bevor_etwas_geoeffnet_wird()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        using (KT.Now(VH.T0)) { await v.Einrichten(new DestructionSettings(DeadmanDays: 10), [a.Id]); }
        using (KT.Now(VH.T(11 * VH.Tag))) { v.Reopen(); }
        Assert.Equal([a.Id], v.Vault.DestroyedEntries);
        Assert.Equal(DestructionTrigger.Deadman, v.Store.GetDestructionStatus().DestroyedTrigger);
        Assert.False(File.Exists(v.VPath));
    }

    [Fact]
    public async Task Uhr_rueckwaerts_nicht_vernichten_Frist_nicht_verlaengern()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        using (KT.Now(VH.T0)) { await v.Einrichten(new DestructionSettings(DeadmanDays: 7), [a.Id]); }
        v.Vault.Lock();
        var bytes = File.ReadAllBytes(v.StatePath);
        Assert.False(v.Store.CheckDeadman(VH.T(-2 * VH.Tag)));
        Assert.False(v.Store.CheckDeadman(VH.T(-0.5 * VH.Tag)));
        Assert.Equal(bytes, File.ReadAllBytes(v.StatePath));
        // Echtes Entsperren mit zurückgestellter Uhr: letzte echte Entsperrung bleibt t0.
        using (KT.Now(VH.T(-10 * VH.Tag))) { v.Reopen(); }
        Assert.Equal(VH.T0, v.Store.GetDestructionStatus().LastGenuineUnlock);
        Assert.Equal(VH.T(7 * VH.Tag), v.Store.GetDestructionStatus().Deadline);
        // Uhr wieder richtig, Entsperren am Tag 3: Frist ab da.
        using (KT.Now(VH.T(3 * VH.Tag))) { v.Reopen(); }
        Assert.Equal(VH.T(3 * VH.Tag), v.Store.GetDestructionStatus().LastGenuineUnlock);
        v.Vault.Lock();
        // Uhr wieder rückwärts nach Ablauf → nichts; vorwärts über die Frist → vernichtet.
        Assert.False(v.Store.CheckDeadman(VH.T(-20 * VH.Tag)));
        Assert.False(v.Store.CheckDeadman(VH.T(10 * VH.Tag - 1)));
        Assert.Empty(v.Eraser.Destroyed);
        Assert.True(v.Store.CheckDeadman(VH.T(10 * VH.Tag)));
        Assert.Equal([v.VKeyId], v.Eraser.Destroyed);
    }

    [Fact]
    public async Task Fehlversuch_Zaehler_nur_WrongPassword_zaehlt_echtes_Entsperren_setzt_zurueck_bei_N_vernichtet()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        var b = v.Add("Mail", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(MaxFailedAttempts: 10), [a.Id]);
        v.Vault.Lock();
        var level = v.Vault.Level;
        FactorSecrets F() => v.T.K.Secrets(level.Factors());
        for (var i = 1; i <= 4; i++)
        {
            KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.Unlock(KT.Pw2, F()));
            Assert.Equal(i, v.Store.GetDestructionStatus().FailedAttempts);
        }
        Assert.False(v.Store.GetDestructionStatus().ShouldWarnAboutAttempts);
        KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.Unlock(KT.Pw2, F()));
        Assert.True(v.Store.GetDestructionStatus().ShouldWarnAboutAttempts);
        Assert.Equal(5, v.Store.GetDestructionStatus().RemainingAttempts);
        // Zählen nicht: fehlender Faktor, falsche Karte, Argon2-Fehler.
        KT.Throws(SiegelErrorCode.FactorMissing, "card", () => v.Store.Unlock(KT.Pw2, v.T.K.Secrets(FactorSet.SecureEnclave)));
        var falscheKarte = F();
        falscheKarte.Card = CardCode.Generate();
        KT.Throws(SiegelErrorCode.WrongCard, () => v.Store.Unlock(KT.Pw2, falscheKarte));
        using (KT.Hook(() => TestHooks.ForceKdfFailure = true, () => TestHooks.ForceKdfFailure = false))
        {
            KT.Throws(SiegelErrorCode.KdfFailed, () => v.Store.Unlock(KT.Pw2, F()));
        }
        Assert.Equal(5, v.Store.GetDestructionStatus().FailedAttempts);
        // Echtes Entsperren setzt zurück.
        v.Reopen();
        Assert.Equal(0, v.Store.GetDestructionStatus().FailedAttempts);
        v.Vault.Lock();
        // Auch die Sicherungswege zählen.
        var backup = v.T.F.LocalBackups()[0];
        KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.RestoreBackup(backup, KT.Pw2, F()));
        Assert.Equal(1, v.Store.GetDestructionStatus().FailedAttempts);
        for (var i = 2; i <= 9; i++)
        {
            KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.Unlock(KT.Pw3, F()));
        }
        Assert.Empty(v.Eraser.Destroyed);
        KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.Unlock(KT.Pw3, F()));
        Assert.Equal([v.VKeyId], v.Eraser.Destroyed);
        Assert.Equal(DestructionTrigger.FailedAttempts, v.Store.GetDestructionStatus().DestroyedTrigger);
        Assert.False(File.Exists(v.VPath));
        // Weitere Fehlversuche ändern nichts mehr.
        KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.Unlock(KT.Pw3, F()));
        Assert.Equal([v.VKeyId], v.Eraser.Destroyed);
        // Echt entsperrt: a vernichtet, b unberührt.
        v.Reopen();
        Assert.Equal([a.Id], v.Vault.DestroyedEntries);
        await KT.ThrowsAsync(SiegelErrorCode.FactorUnavailable, "secureEnclave", () => v.Reveal(a.Id));
        await VH.Same(b, v.Reveal(b.Id));
    }

    [Fact]
    public async Task Alle_Sicherungswege_zaehlen_Argon2_Fehler_bei_beiden_Laeufen_zaehlt_nicht()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(MaxFailedAttempts: 10, DuressEnabled: true), [a.Id], VTresor.DuressPw);
        v.Vault.Lock();
        var f = v.Factors;
        Assert.False(v.Store.CheckDeadman(DateTimeOffset.UtcNow));
        KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.RestoreNewestReadableBackup(KT.Pw2, f()));
        Assert.Equal(1, v.Store.GetDestructionStatus().FailedAttempts);
        KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.ImportBackup(v.Store.VaultPath, KT.Pw2, f()));
        Assert.Equal(2, v.Store.GetDestructionStatus().FailedAttempts);
        // Mit Vernichtungs-Passwort: beide Argon2 scheitern (2 gleichzeitig), dann nacheinander – der erste scheitert
        // wieder (3) → KdfFailed, kein Fehlversuch.
        var counter = new TestHooks.Counter();
        using (KT.Hook(() =>
               {
                   TestHooks.ForceKdfFailure = true;
                   TestHooks.KdfCounter = counter;
               }, () =>
               {
                   TestHooks.ForceKdfFailure = false;
                   TestHooks.KdfCounter = null;
               }))
        {
            KT.Throws(SiegelErrorCode.KdfFailed, () => v.TryUnlock(KT.Pw2));
        }
        Assert.Equal(3, counter.Value);
        Assert.Equal(2, v.Store.GetDestructionStatus().FailedAttempts);
        Assert.Empty(v.Eraser.Destroyed);
        // Eine Sicherung mit dem Master-Passwort einsetzen gilt als echtes Entsperren (Zähler 0).
        var backup = v.T.F.LocalBackups()[0];
        v.T.F.Vault = v.Store.RestoreBackup(backup, KT.Pw1, f());
        Assert.Equal(0, v.Store.GetDestructionStatus().FailedAttempts);
        Assert.True(v.DuressEnvelopeOpens());
    }

    [Fact]
    public async Task Zaehler_aus_falsche_Passwoerter_hinterlassen_keine_Spur()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DeadmanDays: 30), [a.Id]);
        v.Vault.Lock();
        var bytes = File.ReadAllBytes(v.StatePath);
        for (var i = 0; i < 12; i++)
        {
            KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.Unlock(KT.Pw2, v.Factors()));
        }
        Assert.Equal(bytes, File.ReadAllBytes(v.StatePath));
        Assert.Equal(0, v.Store.GetDestructionStatus().FailedAttempts);
        Assert.Empty(v.Eraser.Destroyed);
    }

    [Fact]
    public async Task Schicht_kaputt_der_Kern_ueberschreibt_und_loescht_V_selbst()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(MaxFailedAttempts: 10), [a.Id]);
        var kaputt = new ZaehlEraser(untaetig: true);
        v.Store.DestructionKeyEraser = kaputt;
        v.Vault.Lock();
        for (var i = 0; i < 10; i++)
        {
            KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.Unlock(KT.Pw2, v.Factors()));
        }
        Assert.Equal([v.VKeyId], kaputt.Destroyed);
        Assert.False(File.Exists(v.VPath));
        Assert.Equal(DestructionTrigger.FailedAttempts, v.Store.GetDestructionStatus().DestroyedTrigger);
    }
}

/// <summary>Selbstvernichtung: Vernichtungs-Passwort (§23.2 Nr. 3).</summary>
public class VernichtungsPasswortTests
{
    [Fact]
    public async Task Vernichtungs_Passwort_oeffnet_scheinbar_normal_vernichtet_still_verlaengert_die_Frist_nicht()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        var b = v.Add("Mail", EntryProtection.Maximal);
        var o = v.Add("Notiz", EntryProtection.Fingerabdruck);
        using (KT.Now(VH.T0))
        {
            await v.Einrichten(new DestructionSettings(30, 10, true), [a.Id], VTresor.DuressPw);
        }
        v.Vault.Lock();
        KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.Unlock(KT.Pw2, v.Factors()));
        Assert.Equal(1, v.Store.GetDestructionStatus().FailedAttempts);
        var vaultBytes = v.T.F.FileBytes();
        var backups = v.T.F.BackupFileNames();
        var hw = v.HardwareNames();

        UnlockedVault dv;
        using (KT.Now(VH.T(2 * VH.Tag))) { dv = v.TryUnlock(VTresor.DuressPw); }
        using (dv)
        {
            Assert.True(dv.IsDuressSession);
            Assert.Equal([v.VKeyId], v.Eraser.Destroyed);
            Assert.False(File.Exists(v.VPath));
            // Was die Sitzung geschrieben hat: nur V weg und der Zustand; Tresordatei und Sicherungen unverändert.
            Assert.Equal(vaultBytes, v.T.F.FileBytes());
            Assert.Equal(backups, v.T.F.BackupFileNames());
            hw.Remove(Bytes.GuidText(v.VKeyId) + ".siegelhw");
            Assert.Equal(hw, v.HardwareNames());
            var st = v.State()!;
            Assert.Equal(VH.T0, st.LastGenuineUnlock);
            Assert.Equal(0, st.FailedAttempts);
            Assert.Equal(DestructionTrigger.DuressPassword, st.DestroyedInfo?.Trigger);
            Assert.Equal(VH.T(2 * VH.Tag), st.DestroyedInfo?.At);

            // Nach aussen normal: ohne den vernichteten Eintrag, nichts deutet auf die Vernichtung hin.
            VH.SameSet([b.Id, o.Id], dv.Entries.Select(e => e.Id));
            Assert.Empty(dv.DestroyedEntries);
            Assert.Empty(dv.DestructibleEntries);
            Assert.Equal(v.VKeyId, dv.DestructionKeyId);
            Assert.True(dv.DestructionSettings.DuressEnabled);
            Assert.Null(dv.DestructionStatus.DestroyedTrigger);
            Assert.Null(dv.DestructionStatus.DestroyedAt);
            Assert.Equal(2, dv.SecurityReport().Total);
            Assert.DoesNotContain(a.Id, dv.MasterPasswordReuse);
            await KT.ThrowsAsync(SiegelErrorCode.Io, "entry.notFound", () => v.Reveal(a.Id, dv));
            KT.Throws(SiegelErrorCode.Io, "entry.notFound", () => dv.Delete(a.Id));
            KT.Throws(SiegelErrorCode.Io, "entry.stale", () => dv.Upsert(a));
            await VH.Same(b, v.Reveal(b.Id, dv));
            await VH.Same(o, v.Reveal(o.Id, dv));
            // Passwort-Bestätigungen gelten als falsch (das Vernichtungs-Passwort ist kein Master-Passwort).
            Assert.False(dv.Verify(VTresor.DuressPw, v.Factors()));
            await KT.ThrowsAsync(SiegelErrorCode.WrongPassword, () => dv.ConfigureDestructionAsync(DestructionSettings.Off, null,
                new HashSet<Guid>(), VTresor.DuressPw, v.Factors(), null, v.Provider));
            dv.RemoveDestroyedEntries();
            // Bearbeiten geht und schreibt normal; der vernichtete Eintrag bleibt im Inhalt.
            var n = SchutzEntries.Make("Neu", EntryProtection.Maximal);
            dv.Upsert(n);
            Assert.Contains(dv.Entries, e => e.Id == n.Id);
            Assert.Equal(DestructionTrigger.DuressPassword, v.State()?.DestroyedInfo?.Trigger);
            dv.Lock();

            // Der Besitzer sieht beim nächsten echten Entsperren die Meldung.
            using (KT.Now(VH.T(5 * VH.Tag))) { v.Reopen(); }
            Assert.False(v.Vault.IsDuressSession);
            Assert.Equal([a.Id], v.Vault.DestroyedEntries);
            Assert.Equal(DestructionTrigger.DuressPassword, v.Vault.DestructionStatus.DestroyedTrigger);
            VH.SameSet([a.Id, b.Id, o.Id, n.Id], v.Vault.Entries.Select(e => e.Id));
            await VH.Same(n, v.Reveal(n.Id));
            Assert.Equal(VH.T(5 * VH.Tag), v.Store.GetDestructionStatus().LastGenuineUnlock);
        }
    }

    private static (int Runs, int Arrivals, int Missed, SiegelException? Error) Messen(VTresor v, string pw)
    {
        var counter = new TestHooks.Counter();
        var rv = new TestHooks.Rendezvous();
        SiegelException? error = null;
        using (KT.Hook(() =>
               {
                   TestHooks.KdfCounter = counter;
                   TestHooks.KdfRendezvous = rv;
               }, () =>
               {
                   TestHooks.KdfCounter = null;
                   TestHooks.KdfRendezvous = null;
               }))
        {
            try
            {
                KT.AnyVault(v.Store.Unlock(pw, v.T.K.Secrets(SecurityLevel.Maximal.Factors()))).Lock();
            }
            catch (SiegelException e)
            {
                error = e;
            }
        }
        return (counter.Value, rv.Arrivals, rv.Missed, error);
    }

    [Fact]
    public async Task Zeitgleichheit_mit_Vernichtungs_Passwort_laufen_immer_beide_Argon2_gleichzeitig()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DuressEnabled: true), [a.Id], VTresor.DuressPw);
        v.Vault.Lock();
        var echt = Messen(v, KT.Pw1);
        Assert.Equal((2, 2, 0), (echt.Runs, echt.Arrivals, echt.Missed));
        Assert.Null(echt.Error);
        var falsch = Messen(v, KT.Pw3);
        Assert.Equal((2, 2, 0), (falsch.Runs, falsch.Arrivals, falsch.Missed));
        Assert.Equal(SiegelErrorCode.WrongPassword, falsch.Error?.Code);
        Assert.Empty(v.Eraser.Destroyed);
        var zwang = Messen(v, VTresor.DuressPw);
        Assert.Equal((2, 2, 0), (zwang.Runs, zwang.Arrivals, zwang.Missed));
        Assert.Null(zwang.Error);
        Assert.Equal([v.VKeyId], v.Eraser.Destroyed);

        // Ohne Vernichtungs-Passwort bleibt es bei einem Argon2.
        using var w = new VTresor();
        var wa = w.Add("Bank", EntryProtection.Maximal);
        await w.Einrichten(new DestructionSettings(DeadmanDays: 30), [wa.Id]);
        w.Vault.Lock();
        var counter = new TestHooks.Counter();
        using (KT.Hook(() => TestHooks.KdfCounter = counter, () => TestHooks.KdfCounter = null))
        {
            KT.AnyVault(w.Store.Unlock(KT.Pw1, w.T.K.Secrets(SecurityLevel.Maximal.Factors()))).Lock();
        }
        Assert.Equal(1, counter.Value);
        w.Reopen();
    }

    [Fact]
    public async Task Fehlt_die_Ablage_gleiche_Dauer_nichts_erkannt_echtes_Entsperren_repariert_sie()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DuressEnabled: true), [a.Id], VTresor.DuressPw);
        Guid fileId;
        using (var c = v.Vault.ContentForTesting!) { fileId = c.Destruction!.Duress!.FileId; }
        var path = v.Store.HardwareKeyPath(fileId);
        var level = v.Vault.Level;
        v.Vault.Lock();
        File.Delete(path);
        var counter = new TestHooks.Counter();
        using (KT.Hook(() => TestHooks.KdfCounter = counter, () => TestHooks.KdfCounter = null))
        {
            KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.Unlock(VTresor.DuressPw, v.T.K.Secrets(level.Factors())));
        }
        Assert.Equal(2, counter.Value);
        Assert.Empty(v.Eraser.Destroyed);
        v.T.F.Vault = KT.AnyVault(v.Store.Unlock(KT.Pw1, v.T.K.Secrets(level.Factors())));
        Assert.True(File.Exists(path));
        Assert.True(v.DuressEnvelopeOpens());
        v.Vault.Lock();
        using var dv = v.TryUnlock(VTresor.DuressPw);
        Assert.True(dv.IsDuressSession);
    }

    [Fact]
    public async Task Der_Umschlag_folgt_jeder_DEK_Rotation_und_wird_bei_jedem_Speichern_neu_gekapselt()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DuressEnabled: true), [a.Id], VTresor.DuressPw);
        Assert.True(v.DuressEnvelopeOpens());
        Assert.False(v.DuressEnvelopeOpens(VTresor.DuressPw2));
        Guid fileId;
        using (var c = v.Vault.ContentForTesting!) { fileId = c.Destruction!.Duress!.FileId; }
        var path = v.Store.HardwareKeyPath(fileId);

        bool SameDek(SecureBuffer old)
        {
            using var now = v.Vault.DekForTesting();
            return now.ConstantTimeEquals(old);
        }

        // Speichern (gleicher DEK): frische Kapselung.
        var f0 = File.ReadAllBytes(path);
        v.Add("Mail", EntryProtection.Maximal);
        Assert.NotEqual(f0, File.ReadAllBytes(path));
        Assert.True(v.DuressEnvelopeOpens());

        // Passwortwechsel (neuer DEK).
        using (var dek = v.Vault.DekForTesting())
        {
            v.Vault.ChangeMasterPassword(KT.Pw1, KT.Pw2, v.Factors());
            Assert.False(SameDek(dek));
        }
        Assert.True(v.DuressEnvelopeOpens());

        // Neues Kit (neuer DEK, versiegelte Einträge über ihre Gruppen).
        using (var dek = v.Vault.DekForTesting())
        {
            var kit = v.Vault.PrepareRecovery(KT.Pw2, v.Factors(), RecoveryScheme.Shamir2Of3);
            await v.Vault.CommitRecoveryAsync(kit, KernStufen.Confirmation(kit), v.Provider);
            Assert.False(SameDek(dek));
        }
        Assert.True(v.DuressEnvelopeOpens());

        // Stufenwechsel 4 → 5 (neuer DEK).
        using (var dek = v.Vault.DekForTesting())
        {
            v.Vault.ChangeSecurityLevel(SecurityLevel.Festung, KT.Pw2, v.T.K.Secrets(FactorSet.All), new NewFactorMaterial(), null, []);
            Assert.False(SameDek(dek));
        }
        Assert.True(v.DuressEnvelopeOpens());

        // Sicherung einsetzen (neuer DEK, Stand der Sicherung: Stufe 4).
        var backup = v.T.F.LocalBackups()[0];
        var level4 = v.T.K.Secrets(FactorSet.SecureEnclave | FactorSet.Card);
        v.Vault.Lock();
        v.T.F.Vault = v.Store.RestoreBackup(backup, KT.Pw2, level4);
        Assert.True(v.DuressEnvelopeOpens());

        // Am Ende das echte Vernichtungs-Passwort.
        v.Vault.Lock();
        using var dv = v.TryUnlock(VTresor.DuressPw);
        Assert.True(dv.IsDuressSession);
        Assert.DoesNotContain(dv.Entries, e => e.Id == a.Id);
    }

    [Fact]
    public async Task Vernichtungs_Passwort_aendern_und_entfernen()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DuressEnabled: true), [a.Id], VTresor.DuressPw);
        Guid DuressId()
        {
            using var c = v.Vault.ContentForTesting!;
            return c.Destruction?.Duress?.FileId ?? Guid.Empty;
        }
        bool SameDek(SecureBuffer old)
        {
            using var now = v.Vault.DekForTesting();
            return now.ConstantTimeEquals(old);
        }
        var alt = DuressId();
        var kopieAlt = File.ReadAllBytes(v.Store.HardwareKeyPath(alt));
        using (var dek = v.Vault.DekForTesting())
        {
            await v.Einrichten(new DestructionSettings(DuressEnabled: true), [a.Id], VTresor.DuressPw2);
            // Ersetzen ist ein Zugangswechsel (v4.4): neuer DEK.
            Assert.False(SameDek(dek));
        }
        var neu = DuressId();
        Assert.NotEqual(alt, neu);
        Assert.False(File.Exists(v.Store.HardwareKeyPath(alt)));
        Assert.True(v.DuressEnvelopeOpens(VTresor.DuressPw2));
        Assert.False(v.DuressEnvelopeOpens(VTresor.DuressPw));
        // Gegenprobe: alte Ablage + altes Vernichtungs-Passwort (sogar mit allen Faktoren) öffnen die neue Datei nicht.
        var nachErsetzen = v.OfflineDuress(kopieAlt, alt, v.T.F.FileBytes(), v.Factors());
        Assert.True(nachErsetzen.Recognized);
        Assert.False(nachErsetzen.Opens);
        // Nur Einstellungen ändern behält das Passwort (und den DEK).
        using (var dek = v.Vault.DekForTesting())
        {
            await v.Einrichten(new DestructionSettings(DeadmanDays: 30, DuressEnabled: true), [a.Id]);
            Assert.Equal(neu, DuressId());
            Assert.True(SameDek(dek));
            // Entfernen: Ablage weg, neuer DEK, das alte Vernichtungs-Passwort ist nur noch ein falsches Passwort.
            var kopieNeu = File.ReadAllBytes(v.Store.HardwareKeyPath(neu));
            await v.Einrichten(new DestructionSettings(DeadmanDays: 30), [a.Id]);
            Assert.False(File.Exists(v.Store.HardwareKeyPath(neu)));
            Assert.False(SameDek(dek));
            var nachEntfernen = v.OfflineDuress(kopieNeu, neu, v.T.F.FileBytes(), v.Factors(), VTresor.DuressPw2);
            Assert.True(nachEntfernen.Recognized);
            Assert.False(nachEntfernen.Opens);
        }
        v.Vault.Lock();
        KT.Throws(SiegelErrorCode.WrongPassword, () => v.TryUnlock(VTresor.DuressPw2));
        Assert.Empty(v.Eraser.Destroyed);
    }
}

/// <summary>Selbstvernichtung: unlesbar nach der Vernichtung (§23.1).</summary>
public class VernichtungUnlesbarTests
{
    /// <summary>Tresor mit einem vernichtbaren (a) und einem nicht vernichtbaren Eintrag (b), mehreren Sicherungen; danach
    /// über den Fehlversuch-Zähler vernichtet.</summary>
    private static async Task<(VTresor V, VaultEntry A, VaultEntry B)> Vernichtet()
    {
        var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        var b = v.Add("Mail", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(MaxFailedAttempts: 10), [a.Id]);
        v.Add("Shop", EntryProtection.Fingerabdruck);
        v.Add("Velo", EntryProtection.Maximal);
        v.Vault.Lock();
        for (var i = 0; i < 10; i++)
        {
            KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.Unlock(KT.Pw2, v.Factors()));
        }
        Assert.Equal([v.VKeyId], v.Eraser.Destroyed);
        return (v, a, b);
    }

    [Fact]
    public async Task Aus_jeder_Sicherung_unlesbar_auch_kryptografisch()
    {
        var (v, a, b) = await Vernichtet();
        using (v)
        {
            var backups = v.T.F.LocalBackups();
            Assert.True(backups.Count >= 2);
            var vaultId = Bytes.OfGuid(v.Vault.VaultId);
            var mask = EntryProtection.Maximal.Factors();
            foreach (var backup in backups)
            {
                using var c = v.T.F.OpenFile(backup.Path, factors: v.Factors());
                Assert.False(c.Sealed.ContainsKey(a.Id));
                var blob = c.Destructible[a.Id];
                // Ohne V: mit einem anderen P-256-Schlüssel (alles andere echt) entsteht ein falsches K.
                using (var fremdKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
                {
                    File.WriteAllBytes(v.VPath, fremdKey.ExportParameters(true).D!);
                }
                try
                {
                    var keys = c.SealingKeys(vaultId);
                    var v0 = c.Destruction!.VKey!;
                    var released = await EntrySealing.ReleaseAsync(blob.Factors, a.Id, mask, keys.Factors, keys.VaultId, v.Provider,
                        EntrySealing.SePart.ForDestruction(v0), CancellationToken.None);
                    try
                    {
                        using var opened = EntrySealing.Open(blob, a.Id, (byte)EntryProtection.Maximal, mask, EntrySealing.DestructibleAd,
                            keys.Base, keys.VaultId, released, EntrySealing.DestructibleKeyInfo);
                        Assert.Null(opened);
                    }
                    finally
                    {
                        foreach (var r in released) { r.Dispose(); }
                    }
                }
                finally
                {
                    File.Delete(v.VPath);
                }
            }
            // Eine ältere Sicherung einsetzen: a bleibt vernichtet, b lesbar.
            var oldest = backups[^1];
            v.T.F.Vault = v.Store.RestoreBackup(oldest, KT.Pw1, v.T.K.Secrets(SecurityLevel.Maximal.Factors()));
            Assert.Equal([a.Id], v.Vault.DestroyedEntries);
            await KT.ThrowsAsync(SiegelErrorCode.FactorUnavailable, "secureEnclave", () => v.Reveal(a.Id));
            await VH.Same(b, v.Reveal(b.Id));
        }
    }

    [Fact]
    public async Task Ueber_den_Notfallcode_vernichtbare_Eintraege_fallen_weg_die_uebrigen_kommen_zurueck()
    {
        var (v, a, b) = await Vernichtet();
        using (v)
        {
            var kit = v.T.Kit!;
            string[] shares = [kit.Shares[1].Formatted, kit.Shares[2].Formatted];
            using (var r = v.Store.Recover(shares, KT.Pw3, KT.Kdf))
            {
                Assert.DoesNotContain(r.Entries, e => e.Id == a.Id);
                Assert.Equal(b.Password, r.Entries.Single(e => e.Id == b.Id).Password);
                Assert.Equal(SecurityLevel.Standard, r.Level);
                Assert.Equal(DestructionSettings.Off, r.DestructionSettings);
                Assert.Empty(r.DestroyedEntries);
                Assert.False(File.Exists(v.StatePath));
                r.Lock();
            }
            // Auch der Notfallweg über die Sicherungen (beschädigte Tresordatei) bringt a nicht zurück.
            var bytes = v.T.F.FileBytes();
            bytes[bytes.Length / 2] ^= 0x01;
            v.T.F.WriteFile(bytes);
            var (r2, _) = v.Store.RecoverFromNewestReadableBackup(shares, KT.Pw4, KT.Kdf);
            using (r2)
            {
                Assert.DoesNotContain(r2.Entries, e => e.Id == a.Id);
                Assert.Contains(r2.Entries, e => e.Id == b.Id);
            }
        }
    }

    [Fact]
    public async Task Kein_Notfallweg_schon_vor_der_Vernichtung()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        var b = v.Add("Mail", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DeadmanDays: 30), [a.Id]);
        v.Vault.Lock();
        var kit = v.T.Kit!;
        using var r = v.Store.Recover([kit.Shares[0].Formatted, kit.Shares[1].Formatted], KT.Pw2, KT.Kdf);
        Assert.DoesNotContain(r.Entries, e => e.Id == a.Id);
        Assert.Equal(b.Notes, r.Entries.Single(e => e.Id == b.Id).Notes);
        Assert.Empty(v.Eraser.Destroyed);
    }
}

/// <summary>Selbstvernichtung: Zustand, Ablage und Konsistenz.</summary>
public class VernichtungFormatTests
{
    [Fact]
    public void Ohne_Selbstvernichtung_entsteht_keine_Datei_der_Inhalt_bleibt_ohne_destruction()
    {
        using var v = new VTresor();
        v.Add("Bank", EntryProtection.Maximal);
        v.Reopen();
        Assert.False(File.Exists(v.StatePath));
        Assert.Equal([Bytes.GuidText(v.VKeyId) + ".siegelhw"], v.HardwareNames());
        Assert.DoesNotContain("destruction", v.T.F.JsonOnDisk(), StringComparison.Ordinal);
        Assert.Equal(DestructionStatus.Off, v.Store.GetDestructionStatus());
        Assert.Equal(DestructionStatus.Off, v.Vault.DestructionStatus);
    }

    [Fact]
    public async Task Ablage_feste_Form_und_Groesse_strenger_Leser()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DeadmanDays: 30, DuressEnabled: true), [a.Id], VTresor.DuressPw);
        Guid fileId;
        using (var c = v.Vault.ContentForTesting!) { fileId = c.Destruction!.Duress!.FileId; }
        var path = v.Store.HardwareKeyPath(fileId);
        var bytes = File.ReadAllBytes(path);
        Assert.Equal(2048, bytes.Length);
        Assert.Equal("SIEGELHW"u8.ToArray(), bytes[..8]);
        Assert.Equal((1, 0, 2), (bytes[8], bytes[9], bytes[10]));
        Assert.Equal(Bytes.OfGuid(fileId), bytes[11..27]);
        Assert.Equal(DuressFile.BlobLength, bytes[27] | bytes[28] << 8);
        Assert.Equal(DuressFile.Checksum(bytes.AsSpan(0, 2016)), bytes[2016..]);
        Assert.True(P256.IsValidPublicKey(bytes.AsSpan(2016 - 65, 65)));
        // Strenger Leser: falsche Kennung, Bitfehler, Länge.
        KT.Corrupt("duress.id", () => DuressFile.Decode(bytes, Guid.NewGuid()));
        var kaputt = (byte[])bytes.Clone();
        kaputt[100] ^= 1;
        KT.Corrupt("duress.checksum", () => DuressFile.Decode(kaputt, fileId));
        KT.Corrupt("duress.length", () => DuressFile.Decode(bytes[..^1], fileId));
        // Neu kodiert: gleicher Inhalt, frische Zufallsfüllung und frischer Punkt.
        var again = DuressFile.Decode(bytes, fileId).Encoded();
        var payloadEnd = DuressFile.FixedLength + DuressFile.PayloadLength;
        Assert.Equal(bytes[..payloadEnd], again[..payloadEnd]);
        Assert.NotEqual(bytes[payloadEnd..], again[payloadEnd..]);
        Assert.Equal(DuressFile.Decode(bytes, fileId), DuressFile.Decode(again, fileId));
        foreach (var p in new[] { path, v.StatePath, v.VPath }) { VH.ExcludedFromIndexing(p); }
        var st = v.State()!;
        Assert.Equal(fileId, st.DuressFileId);
        Assert.Equal(v.VKeyId, st.VKeyId);
        Assert.Equal(v.Vault.VaultId, st.VaultId);
        var json = File.ReadAllText(v.StatePath);
        Assert.Contains("\"settings\":{\"deadmanDays\":30,\"duressEnabled\":true,\"maxFailedAttempts\":null}", json, StringComparison.Ordinal);
        Assert.Contains("\"destroyed\":null", json, StringComparison.Ordinal);
        Assert.Contains("\"v\":1", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Zustand_json_wird_streng_gelesen()
    {
        var s = new DestructionState(Guid.NewGuid())
        {
            Settings = new DestructionSettings(30, 10, true),
            VKeyId = Guid.NewGuid(),
            DuressFileId = Guid.NewGuid(),
            FailedAttempts = 3,
            LastGenuineUnlock = KT.At(1_800_000_000),
            DestroyedInfo = new DestructionState.Destroyed(Guid.NewGuid(), DestructionTrigger.DuressPassword, KT.At(1_800_000_100)),
        };
        Assert.Equal(s, DestructionState.Decode(s.Encoded()));
        Assert.Equal(s.Encoded(), DestructionState.Decode(s.Encoded()).Encoded());
        byte[] Variante(Action<JsonObject> change)
        {
            var obj = JsonNode.Parse(s.Encoded())!.AsObject();
            change(obj);
            return System.Text.Encoding.UTF8.GetBytes(obj.ToJsonString());
        }
        foreach (var bad in new[]
                 {
                     Variante(o => o["v"] = 2),
                     Variante(o => o["failedAttempts"] = -1),
                     Variante(o => o["duressFileID"] = null),
                     Variante(o => o["settings"] = new JsonObject { ["deadmanDays"] = 3, ["duressEnabled"] = false }),
                     Variante(o => o["vaultID"] = "keine-uuid"),
                     Variante(o => ((JsonObject)o["destroyed"]!)["trigger"] = "unbekannt"),
                     [0x7b],
                 })
        {
            KT.Corrupt("destruction.state", () => DestructionState.Decode(bad));
        }
    }

    [Fact]
    public async Task Fremder_Zustand_andere_vaultID_gilt_nicht()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(MaxFailedAttempts: 10), [a.Id]);
        var st = v.State()! with { VaultId = Guid.NewGuid() };
        DestructionState.Write(st, v.Hardware);
        Assert.Equal(DestructionStatus.Off, v.Store.GetDestructionStatus());
        v.Vault.Lock();
        for (var i = 0; i < 12; i++)
        {
            KT.Throws(SiegelErrorCode.WrongPassword, () => v.Store.Unlock(KT.Pw2, v.Factors()));
        }
        Assert.Empty(v.Eraser.Destroyed);
        // Das echte Entsperren stellt den Zustand aus dem Inhalt wieder her.
        v.Reopen();
        Assert.Equal(v.Vault.VaultId, v.State()?.VaultId);
        Assert.Equal(10, v.Store.GetDestructionStatus().Settings.MaxFailedAttempts);
    }

    [Fact]
    public async Task Konsistenzregeln_im_Inhalt_und_JSON_Rundlauf()
    {
        using var v = new VTresor();
        var a = v.Add("Bank", EntryProtection.Maximal);
        v.Add("Mail", EntryProtection.Maximal);
        await v.Einrichten(new DestructionSettings(DeadmanDays: 30, DuressEnabled: true), [a.Id], VTresor.DuressPw);
        using var c = v.Vault.ContentForTesting!;
        var wrap = c.Sealed.Values.First().Recovery;
        c.CheckSealing(Fehler.Corrupt);
        var (padded, _) = PayloadCodec.Encode(c);
        using (padded)
        {
            using var back = PayloadCodec.Decode(padded).Content;
            Assert.Equal(c.Destructible.OrderBy(x => x.Key), back.Destructible.OrderBy(x => x.Key));
            Assert.Equal(c.Sealed.OrderBy(x => x.Key), back.Sealed.OrderBy(x => x.Key));
            Assert.Equal(c.Destruction, back.Destruction);
        }

        bool Abgelehnt(Action<VaultContent> change)
        {
            using var x = c.Clone();
            change(x);
            try
            {
                x.CheckSealing(Fehler.Corrupt);
                return false;
            }
            catch (SiegelException e)
            {
                return e.Code == SiegelErrorCode.CorruptFile;
            }
        }
        var d = c.Destruction!;
        Assert.True(Abgelehnt(x => x.Level = SecurityLevel.Hoch));
        Assert.True(Abgelehnt(x => x.Destruction = d with { VKey = null }));
        Assert.True(Abgelehnt(x => x.Destruction = null));
        Assert.True(Abgelehnt(x => x.Destruction = d with { Duress = null }));
        Assert.True(Abgelehnt(x => x.Destruction = d with { Settings = d.Settings with { DeadmanDays = 400 } }));
        Assert.True(Abgelehnt(x => x.Entries.Single(e => e.Id == a.Id).Protection = EntryProtection.Fingerabdruck));
        Assert.True(Abgelehnt(x => x.Sealed[a.Id] = new SealedSecrets(x.Destructible[a.Id], wrap)));
        Assert.True(Abgelehnt(x => x.Destruction = d with { VKey = d.VKey! with { KeyId = v.T.P.EntryKeyId } }));
        Assert.True(Abgelehnt(x => x.Destructible[a.Id] = x.Destructible[a.Id] with
        {
            Factors = x.Destructible[a.Id].Factors with { SeEphemeral = null },
        }));
        // Windows-Hello-V mit Mac-Art-Blob: Art passt nicht.
        Assert.True(Abgelehnt(x => x.Destruction = d with { VKey = new DestructionConfig.VKeyInfo(d.VKey!.KeyId, [], 1) }));
        // Unverändert bleibt gültig.
        Assert.False(Abgelehnt(_ => { }));
        // Schreiben eines kaputten Inhalts ist ein Programmfehler.
        using var kaputt = c.Clone();
        kaputt.Level = SecurityLevel.Hoch;
        KT.Throws(SiegelErrorCode.Crypto, "payload.destruction", () => PayloadCodec.Encode(kaputt).Padded.Dispose());
    }
}
#endif
