#if DEBUG
using System.Security.Cryptography;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Software-Ersatz für ein Windows-Hello-V (nur Tests): eigener HMAC-Schlüssel; „vernichtet“ = Schlüssel weg.</summary>
internal sealed class HelloVProvider(SchutzProvider inner, Guid vKeyId) : IEntryFactorProvider
{
    private int vCalls;
    private volatile bool destroyed;

    internal Guid VKeyId { get; } = vKeyId;
    internal byte[] VSecret { get; } = RandomNumberGenerator.GetBytes(32);
    internal int VCount => Volatile.Read(ref vCalls);
    internal List<Guid> Erased { get; } = [];

    internal EntryKeyEnrollment Enrollment => EntryKeyEnrollment.WindowsHello(VKeyId);

    internal IDestructionKeyEraser Eraser => new ClosureDestructionKeyEraser((id, _) =>
    {
        lock (Erased) { Erased.Add(id); }
        if (id == VKeyId) { destroyed = true; }
    });

    public Task<FactorSecret> WindowsHelloSecretAsync(Guid keyId, ReadOnlyMemory<byte> challenge, CancellationToken cancellationToken)
    {
        if (keyId != VKeyId) { return inner.WindowsHelloSecretAsync(keyId, challenge, cancellationToken); }
        Interlocked.Increment(ref vCalls);
        if (destroyed) { throw new SiegelException(SiegelErrorCode.FactorUnavailable, "secureEnclave"); }
        return Task.FromResult(FactorSecret.Copy(SchutzProvider.HelloRaw(VSecret, keyId, challenge.Span)));
    }

    public Task<FactorSecret> SecureEnclaveSharedSecretAsync(Guid keyId, ReadOnlyMemory<byte> ephemeralPublicKey, CancellationToken cancellationToken) =>
        inner.SecureEnclaveSharedSecretAsync(keyId, ephemeralPublicKey, cancellationToken);

    public Task<FactorSecret> CardSecretAsync(CancellationToken cancellationToken) => inner.CardSecretAsync(cancellationToken);

    public Task<FactorSecret> SecurityKeyOutputAsync(ReadOnlyMemory<byte> credentialId, ReadOnlyMemory<byte> salt, CancellationToken cancellationToken) =>
        inner.SecurityKeyOutputAsync(credentialId, salt, cancellationToken);
}

/// <summary>Windows-Hello-Art des Eintrags-Gerätefaktors (SPEC-WINDOWS W4.1, Format in KERN-NOTIZEN-CS.md): Einrichten,
/// Versiegeln nur mit Signatur (Sammel-/Liefer-Runden), Aufdecken, Notfallweg, Kit, Import, V der Hello-Art, Format.</summary>
public class HelloTests
{
    private static string Json(SchutzTresor t) => t.F.JsonOnDisk();

    [Fact]
    public void Einrichten_kennzeichnet_die_Art_und_schreibt_nur_Kennung_und_Version()
    {
        using var t = SchutzTresor.Make(hello: true);
        Assert.Equal(DeviceKeyKind.WindowsHello, t.Vault.EntryDeviceKeyKind);
        Assert.Equal(FactorSet.All, t.Vault.EnrolledFactors);
        var json = Json(t);
        Assert.Contains("\"windowsHello\":{\"keyID\":\"" + Bytes.GuidText(t.P.HelloKeyId) + "\",\"version\":1}", json, StringComparison.Ordinal);
        Assert.Contains("\"secureEnclave\":null", json, StringComparison.Ordinal);
        Assert.Equal(0, t.P.HelloCount);
        // Mac-Art: kein Schlüssel "windowsHello" (Inhalt bytegleich zum Swift-Kern).
        using var m = SchutzTresor.Make();
        Assert.Equal(DeviceKeyKind.SecureEnclaveP256, m.Vault.EntryDeviceKeyKind);
        Assert.DoesNotContain("windowsHello", Json(m), StringComparison.Ordinal);
        Assert.DoesNotContain("\"hello\"", Json(m), StringComparison.Ordinal);
        // Ohne Eintrags-Gerätefaktor: keine Art.
        using var n = SchutzTresor.Make(enroll: FactorSet.Card);
        Assert.Null(n.Vault.EntryDeviceKeyKind);
    }

    [Fact]
    public async Task Synchron_versiegeln_braucht_die_Signatur_und_schreibt_nichts()
    {
        using var t = SchutzTresor.Make(hello: true);
        var gen = t.Vault.Generation;
        var e = SchutzEntries.Make("Bank", EntryProtection.Fingerabdruck);
        KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => t.Vault.Upsert(e));
        Assert.Equal(gen, t.Vault.Generation);
        Assert.Empty(t.Vault.Entries);
        Assert.Equal(0, t.P.HelloCount);
        // Ohne Anbieter auch async nicht.
        await KT.ThrowsAsync(SiegelErrorCode.FactorMissing, "secureEnclave", () => t.Vault.UpsertAsync(e, null));
        Assert.Equal(gen, t.Vault.Generation);
        // Schutz 1 braucht nichts; Schutz setzen braucht die Signatur.
        var o = SchutzEntries.Make("Offen", EntryProtection.Normal);
        t.Vault.Upsert(o);
        var gen1 = t.Vault.Generation;
        KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave",
            () => t.Vault.SetProtection(EntryProtection.Hoch, o.Id, SchutzEntries.SecretsOf(o)));
        Assert.Equal(gen1, t.Vault.Generation);
        Assert.False(t.Vault.Entries.Single(x => x.Id == o.Id).SecretsSealed);
        await t.Vault.SetProtectionAsync(EntryProtection.Hoch, o.Id, SchutzEntries.SecretsOf(o), t.P);
        Assert.True(t.Vault.Entries.Single(x => x.Id == o.Id).SecretsSealed);
        Assert.Equal(gen1 + 1, t.Vault.Generation);
        // Ein Eintrag + neue Gruppe (Anker) → zwei Signaturen, ein Schreibvorgang.
        Assert.Equal(2, t.P.HelloCount);
        SchutzEntries.SameSecrets(o, await t.Vault.RevealSecretsAsync(o.Id, t.P));
        Assert.Equal(3, t.P.HelloCount);
    }

    [Fact]
    public async Task Schutz_1_bis_5_versiegeln_und_aufdecken_wie_die_Mac_Art()
    {
        using var t = SchutzTresor.Make(hello: true);
        var originals = new Dictionary<EntryProtection, VaultEntry>();
        foreach (var p in Enum.GetValues<EntryProtection>())
        {
            var e = SchutzEntries.Make("E" + (int)p, p);
            await t.Vault.UpsertAsync(e, t.P);
            originals[p] = e;
        }
        // Signaturen: je Eintrag mit Gerätefaktor eine, dazu je neue Gruppe (Masken {SE}, {SE, Karte}, alle) eine.
        Assert.Equal(4 + 3, t.P.HelloCount);
        Assert.Equal(0, t.P.Count(FactorKind.Card));
        var json = Json(t);
        foreach (var p in Enum.GetValues<EntryProtection>())
        {
            var o = originals[p];
            Assert.Equal(p == EntryProtection.Normal, json.Contains(o.Password, StringComparison.Ordinal));
        }
        Assert.Contains("\"hello\":{\"salt\":\"", json, StringComparison.Ordinal);
        Assert.Contains("\",\"version\":1},\"nonce\":\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"se\":\"", json, StringComparison.Ordinal);

        var v = t.Reopen();
        Assert.Equal(DeviceKeyKind.WindowsHello, v.EntryDeviceKeyKind);
        foreach (var p in Enum.GetValues<EntryProtection>())
        {
            var o = originals[p];
            t.P.Reset();
            SchutzEntries.SameSecrets(o, await v.RevealSecretsAsync(o.Id, p == EntryProtection.Normal ? null : t.P));
            var m = p.Factors();
            Assert.Equal(m.Contains(FactorKind.SecureEnclave) ? 1 : 0, t.P.HelloCount);
            Assert.Equal([m.Contains(FactorKind.SecureEnclave) ? 1 : 0, m.Contains(FactorKind.Card) ? 1 : 0, m.Contains(FactorKind.SecurityKey) ? 1 : 0],
                t.P.Counts);
        }
        // Ändern ohne neuen Schutz versiegelt neu (neues Salz, neue Signatur).
        var a = originals[EntryProtection.Maximal];
        var before = Json(t);
        t.P.Reset();
        await v.SetProtectionAsync(EntryProtection.Maximal, a.Id, SchutzEntries.SecretsOf(a).ReplacingPassword("Neu-Hello-1"), t.P);
        Assert.Equal(1, t.P.HelloCount);
        Assert.NotEqual(before, Json(t));
        Assert.Equal("Neu-Hello-1", (await v.RevealSecretsAsync(a.Id, t.P)).Password);
    }

    [Fact]
    public async Task Falsche_Signatur_Abbruch_und_Fehler_der_Plattform()
    {
        using var t = SchutzTresor.Make(hello: true);
        var e = SchutzEntries.Make("Bank", EntryProtection.Hoch);
        await t.Vault.UpsertAsync(e, t.P);
        foreach (var (verhalten, code) in new[]
                 {
                     (SchutzProvider.Verhalten.Falsch, SiegelErrorCode.WrongPassword),
                     (SchutzProvider.Verhalten.Abbruch, SiegelErrorCode.FactorCancelled),
                     (SchutzProvider.Verhalten.NichtVerfuegbar, SiegelErrorCode.FactorUnavailable),
                     (SchutzProvider.Verhalten.FremderFehler, SiegelErrorCode.FactorUnavailable),
                 })
        {
            t.P.Set(FactorKind.SecureEnclave, verhalten);
            var x = await KT.ThrowsAsync(code, () => t.Vault.RevealSecretsAsync(e.Id, t.P));
            Assert.DoesNotContain("Geheimnis", x.Message, StringComparison.Ordinal);
            // Beim Versiegeln: nichts geschrieben (eine falsche Signatur fällt erst beim Aufdecken auf).
            if (verhalten != SchutzProvider.Verhalten.Falsch)
            {
                var gen = t.Vault.Generation;
                await KT.ThrowsAsync(code, () => t.Vault.UpsertAsync(SchutzEntries.Make("Neu", EntryProtection.Fingerabdruck), t.P));
                Assert.Equal(gen, t.Vault.Generation);
            }
        }
        t.P.Set(FactorKind.SecureEnclave, SchutzProvider.Verhalten.Richtig);
        SchutzEntries.SameSecrets(e, await t.Vault.RevealSecretsAsync(e.Id, t.P));
        Assert.Single(t.Vault.Entries);
        // Abgesagtes Token: FactorCancelled (nie eine fremde Ausnahme), nichts geschrieben.
        var g = t.Vault.Generation;
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await KT.ThrowsAsync(SiegelErrorCode.FactorCancelled, () => t.Vault.UpsertAsync(SchutzEntries.Make("Neu", EntryProtection.Hoch), t.P, cts.Token));
        await KT.ThrowsAsync(SiegelErrorCode.FactorCancelled, () => t.Vault.ImportEntriesAsync([KT.Entry("Shop")], t.P, cts.Token));
        Assert.Equal(g, t.Vault.Generation);
    }

    [Fact]
    public async Task Notfallweg_und_neues_Kit_ohne_und_mit_Windows_Hello()
    {
        using var t = SchutzTresor.Make(SecurityLevel.Maximal, hello: true);
        var a = SchutzEntries.Make("Bank", EntryProtection.Maximal);
        var b = SchutzEntries.Make("Mail", EntryProtection.Fingerabdruck);
        var c = SchutzEntries.Make("Krypto", EntryProtection.Festung);
        foreach (var e in new[] { a, b, c }) { await t.Vault.UpsertAsync(e, t.P); }
        // Neues Kit: Gruppen werden über ihre Anker (Hello-Signatur) neu gekapselt.
        t.P.Reset();
        var kit = t.Vault.PrepareRecovery(KT.Pw1, t.K.Secrets(SecurityLevel.Maximal.Factors()), RecoveryScheme.Shamir2Of3);
        await t.Vault.CommitRecoveryAsync(kit, KernStufen.Confirmation(kit), t.P);
        Assert.Equal(3, t.P.HelloCount);
        foreach (var e in new[] { a, b, c }) { SchutzEntries.SameSecrets(e, await t.Vault.RevealSecretsAsync(e.Id, t.P)); }
        // Notfallweg mit dem neuen Kit: kein Gerät nötig, alles kommt offen zurück.
        t.Vault.Lock();
        using var r = t.Store.Recover([kit.Shares[0].Formatted, kit.Shares[2].Formatted], KT.Pw2, KT.Kdf);
        Assert.Equal(SecurityLevel.Standard, r.Level);
        foreach (var e in new[] { a, b, c })
        {
            var got = r.Entries.Single(x => x.Id == e.Id);
            Assert.Equal(e.Password, got.Password);
            Assert.Equal(e.Totp, got.Totp);
        }
        Assert.Null(r.EntryDeviceKeyKind);
    }

    [Fact]
    public async Task Import_und_Stufen_Standardschutz_mit_Signaturen()
    {
        using var t = SchutzTresor.Make(SecurityLevel.Maximal, hello: true);
        var items = new List<VaultEntry> { KT.Entry("Shop"), KT.Entry("Velo", user: "velo") };
        var gen = t.Vault.Generation;
        // Stufe 4: Standardschutz 2 → versiegeln → Signaturen nötig.
        KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => t.Vault.ImportEntries(items));
        Assert.Equal(gen, t.Vault.Generation);
        var report = await t.Vault.ImportEntriesAsync(items, t.P);
        Assert.Equal(2, report.Added);
        Assert.Equal(gen + 1, t.Vault.Generation);
        Assert.All(t.Vault.Entries, x => Assert.True(x.SecretsSealed));
        foreach (var x in t.Vault.Entries) { Assert.Equal("Geheim-123", (await t.Vault.RevealSecretsAsync(x.Id, t.P)).Password); }
        // Stufe 4 → 5 (gleicher Gerätefaktor): bleibt lesbar.
        KernStufen.Change(t.Vault, SecurityLevel.Festung, t.K, FactorSet.All, new NewFactorMaterial());
        Assert.Equal(DeviceKeyKind.WindowsHello, t.Vault.EntryDeviceKeyKind);
        foreach (var x in t.Vault.Entries) { Assert.Equal("Geheim-123", (await t.Vault.RevealSecretsAsync(x.Id, t.P)).Password); }
        // Den Gerätefaktor ersetzen (auch durch die Mac-Art) geht nicht, solange Einträge daran hängen.
        KT.Throws(SiegelErrorCode.NotAllowedAtLevel, () => t.Vault.EnrollFactors(new NewFactorMaterial(EntryKey: t.P.EntryKey), KT.Pw1,
            t.K.Secrets(SecurityLevel.Festung.Factors())));
        KT.Throws(SiegelErrorCode.NotAllowedAtLevel, () => t.Vault.EnrollFactors(new NewFactorMaterial(EntryKey: EntryKeyEnrollment.WindowsHello(Guid.NewGuid())),
            KT.Pw1, t.K.Secrets(SecurityLevel.Festung.Factors())));
    }

    [Fact]
    public async Task V_der_Windows_Hello_Art_vernichtbar_versiegeln_aufdecken_vernichten()
    {
        using var t = SchutzTresor.Make(SecurityLevel.Maximal, hello: true);
        var hv = new HelloVProvider(t.P, Guid.NewGuid());
        t.Store.DestructionKeyEraser = hv.Eraser;
        var a = SchutzEntries.Make("Bank", EntryProtection.Maximal);
        var b = SchutzEntries.Make("Mail", EntryProtection.Maximal);
        await t.Vault.UpsertAsync(a, hv);
        await t.Vault.UpsertAsync(b, hv);
        var factors = t.K.Secrets(SecurityLevel.Maximal.Factors());
        // Synchron: neu markieren braucht die Geheimteile → FactorMissing.
        KT.Throws(SiegelErrorCode.FactorMissing, "secureEnclave", () => t.Vault.ConfigureDestruction(new DestructionSettings(DeadmanDays: 30), null,
            new HashSet<Guid> { a.Id }, KT.Pw1, factors, hv.Enrollment));
        using (KT.Now(VH.T0))
        {
            await t.Vault.ConfigureDestructionAsync(new DestructionSettings(DeadmanDays: 30), null, new HashSet<Guid> { a.Id }, KT.Pw1, factors,
                hv.Enrollment, hv);
        }
        // Versiegeln an V brauchte eine V-Signatur.
        Assert.Equal(1, hv.VCount);
        VH.SameSet([a.Id], t.Vault.DestructibleEntries);
        Assert.Equal(hv.VKeyId, t.Vault.DestructionKeyId);
        Assert.Contains("\"vKey\":{\"keyID\":\"" + Bytes.GuidText(hv.VKeyId) + "\",\"windowsHello\":1}", Json(t), StringComparison.Ordinal);
        using (var c = t.Vault.ContentForTesting!)
        {
            Assert.True(c.Destruction!.VKey!.IsWindowsHello);
            Assert.NotNull(c.Destructible[a.Id].Factors.Hello);
            Assert.Null(c.Destructible[a.Id].Factors.SeEphemeral);
            c.CheckSealing(Fehler.Corrupt);
        }
        // V darf nicht der Eintrags-Gerätefaktor sein.
        await KT.ThrowsAsync(SiegelErrorCode.Crypto, "factor.keyID", () => t.Vault.ConfigureDestructionAsync(new DestructionSettings(DeadmanDays: 30),
            null, new HashSet<Guid> { a.Id }, KT.Pw1, factors, t.P.HelloEntryKey, hv));

        // Aufdecken über V (nicht über den Eintrags-Gerätefaktor).
        t.P.Reset();
        SchutzEntries.SameSecrets(a, await t.Vault.RevealSecretsAsync(a.Id, hv));
        Assert.Equal(2, hv.VCount);
        Assert.Equal(0, t.P.HelloCount);
        var v = t.Reopen();
        SchutzEntries.SameSecrets(a, await v.RevealSecretsAsync(a.Id, hv));
        Assert.Equal(3, hv.VCount);

        // Totmann: V vernichtet (über die Plattform), danach unlesbar ohne Anfrage.
        v.Lock();
        Assert.True(t.Store.CheckDeadman(VH.T(31 * VH.Tag)));
        Assert.Equal([hv.VKeyId], hv.Erased);
        v = t.Reopen();
        Assert.Equal([a.Id], v.DestroyedEntries);
        await KT.ThrowsAsync(SiegelErrorCode.FactorUnavailable, "secureEnclave", () => v.RevealSecretsAsync(a.Id, hv));
        Assert.Equal(3, hv.VCount);
        SchutzEntries.SameSecrets(b, await v.RevealSecretsAsync(b.Id, hv));
        v.RemoveDestroyedEntries();
        Assert.DoesNotContain(v.Entries, x => x.Id == a.Id);
        Assert.Equal(DestructionStatus.Off, t.Store.GetDestructionStatus());
    }

    [Fact]
    public async Task Entmarkieren_versiegelt_mit_dem_Eintrags_Geraetefaktor_neu()
    {
        using var t = SchutzTresor.Make(SecurityLevel.Maximal, hello: true);
        var hv = new HelloVProvider(t.P, Guid.NewGuid());
        t.Store.DestructionKeyEraser = hv.Eraser;
        var a = SchutzEntries.Make("Bank", EntryProtection.Festung);
        await t.Vault.UpsertAsync(a, hv);
        var factors = t.K.Secrets(SecurityLevel.Maximal.Factors());
        await t.Vault.ConfigureDestructionAsync(DestructionSettings.Off, null, new HashSet<Guid> { a.Id }, KT.Pw1, factors, hv.Enrollment, hv);
        t.P.Reset();
        await t.Vault.ConfigureDestructionAsync(DestructionSettings.Off, null, new HashSet<Guid>(), KT.Pw1, factors, null, hv);
        // Öffnen über V, neu versiegeln mit dem Eintrags-Gerätefaktor: eine Signatur für den Eintrag, eine für den Anker
        // der Gruppe (sie war mit dem Markieren weggefallen, weil kein versiegelter Eintrag sie mehr brauchte).
        Assert.Equal(2, hv.VCount);
        Assert.Equal(2, t.P.HelloCount);
        Assert.Empty(t.Vault.DestructibleEntries);
        SchutzEntries.SameSecrets(a, await t.Vault.RevealSecretsAsync(a.Id, hv));
        Assert.Equal(3, t.P.HelloCount);
        // Alles aus: V vernichtet.
        await t.Vault.ConfigureDestructionAsync(DestructionSettings.Off, null, new HashSet<Guid>(), KT.Pw1, factors, null, hv);
        Assert.Equal([hv.VKeyId], hv.Erased);
    }

    [Fact]
    public async Task Format_Rundlauf_und_Mischformen_abgelehnt()
    {
        using var t = SchutzTresor.Make(SecurityLevel.Maximal, hello: true);
        var a = SchutzEntries.Make("Bank", EntryProtection.Maximal);
        await t.Vault.UpsertAsync(a, t.P);
        using var c = t.Vault.ContentForTesting!;
        c.CheckSealing(Fehler.Corrupt);
        // Rundlauf: kodieren → lesen → kodieren ergibt dieselben Bytes.
        var (p1, _) = PayloadCodec.Encode(c);
        using (p1)
        {
            using var back = PayloadCodec.Decode(p1).Content;
            var (p2, _) = PayloadCodec.Encode(back);
            using (p2) { Assert.True(p1.ConstantTimeEquals(p2)); }
            Assert.Equal(c.EntryFactors, back.EntryFactors);
            Assert.Equal(c.Sealed.OrderBy(x => x.Key), back.Sealed.OrderBy(x => x.Key));
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
        var blob = c.Sealed[a.Id].Blob;
        var eph = P256.RandomPoint();
        Assert.False(Abgelehnt(_ => { }));
        // Beide Arten im Blob, Mac-Art-Blob in einem Hello-Tresor, Hello-Blob ohne Hello-Schlüssel.
        Assert.True(Abgelehnt(x => x.Sealed[a.Id] = x.Sealed[a.Id] with { Blob = blob with { Factors = blob.Factors with { SeEphemeral = eph } } }));
        Assert.True(Abgelehnt(x => x.Sealed[a.Id] = x.Sealed[a.Id] with
        {
            Blob = blob with { Factors = blob.Factors with { SeEphemeral = eph, Hello = null } },
        }));
        Assert.True(Abgelehnt(x => x.EntryFactors = x.EntryFactors with { WindowsHello = null }));
        // Unbekannte Version, falsche Salzlänge.
        Assert.True(Abgelehnt(x => x.Sealed[a.Id] = x.Sealed[a.Id] with
        {
            Blob = blob with { Factors = blob.Factors with { Hello = blob.Factors.Hello! with { Version = 2 } } },
        }));
        Assert.True(Abgelehnt(x => x.Sealed[a.Id] = x.Sealed[a.Id] with
        {
            Blob = blob with { Factors = blob.Factors with { Hello = new HelloPart(new byte[16]) } },
        }));
        // Beide Gerätefaktor-Arten eingerichtet (ein Mac-Schlüssel dazu) → beim Lesen beschädigt.
        using var mac = SchutzTresor.Make();
        using var mc = mac.Vault.ContentForTesting!;
        var beide = c.EntryFactors with { SecureEnclave = mc.EntryFactors.SecureEnclave };
        KT.Corrupt("payload.factors", beide.Validate);
        using var x2 = c.Clone();
        x2.EntryFactors = beide;
        x2.Sealed.Clear();
        x2.RecoveryGroups.Clear();
        foreach (var e in x2.Entries) { e.SecretsSealed = false; e.Protection = EntryProtection.Normal; }
        var (p3, _) = PayloadCodec.Encode(x2);
        using (p3) { KT.Corrupt("payload.factors", () => PayloadCodec.Decode(p3).Content.Dispose()); }
        KT.Corrupt("payload.factors", (c.EntryFactors with { WindowsHello = new EntryFactorKeys.HelloKey(t.P.HelloKeyId, 2) }).Validate);
    }

    /// <summary>Nur von Hand (<c>SIEGEL_CS_HELLO_PROBE</c> = Ordner): Tresor der Windows-Hello-Art mit echtem KDF-Profil
    /// (256 MiB, t = 3) für die Gegenprobe mit dem Swift-Kern (wie reagiert der Mac auf das „andere Gerät“?). Nicht
    /// eingecheckt; Passwort <c>KT.Pw1</c>, Stufe 1, ein offener und ein Schutz-2-Eintrag.</summary>
    [Fact]
    public async Task Probe_fuer_Swift_nur_von_Hand()
    {
        var target = Environment.GetEnvironmentVariable("SIEGEL_CS_HELLO_PROBE");
        if (string.IsNullOrEmpty(target)) { return; }
        var kdf = new KdfParameters(3, 256UL << 20);
        using var hooks = KT.Hook(() => TestHooks.LevelKdfOverride = kdf, () => TestHooks.LevelKdfOverride = null);
        using var dir = new KernTempDir();
        var store = VaultStore.ForTesting(Path.Combine(dir.Path, "Siegel"), new InMemoryRollbackGuard(), testKdf: false);
        var (vault, _) = store.Create(KT.Pw1, kdf);
        using (vault)
        {
            var p = new SchutzProvider(new KernFaktoren());
            vault.EnrollFactors(new NewFactorMaterial(EntryKey: p.HelloEntryKey), KT.Pw1, new FactorSecrets());
            vault.Upsert(KT.Entry("Offen", password: "Offen-123"));
            await vault.UpsertAsync(SchutzEntries.Make("Hello", EntryProtection.Fingerabdruck, "Hello-123"), p);
            Directory.CreateDirectory(target);
            File.Copy(store.VaultPath, Path.Combine(target, "cs_hello_probe.siegel"), overwrite: true);
        }
    }

    [Fact]
    public void Testvektor_Herausforderung_und_ss()
    {
        // Feste Eingaben; die Hex-Werte unabhängig mit Python (hashlib/hmac) gerechnet (KERN-NOTIZEN-CS.md, W4.1).
        var vaultId = KT.Seq(0x10, 16);
        var keyId = Guid.Parse("01234567-89AB-4CDE-8F01-23456789ABCD");
        var id = Guid.Parse("FEDCBA98-7654-4321-8FED-CBA987654321");
        var salt = KT.Repeat(0xA5, 32);
        var challenge = EntrySealing.HelloChallenge(vaultId, keyId, id, salt);
        Assert.Equal("6f0a5d91ca2d9d1cd32a54ee2c03084e6de8b12c357abefc314cda545610a4bc", KT.Hex(challenge));

        // roh = SHA-256("Siegel v2 windows hello entry" ‖ Signatur); ss = HKDF-SHA512(roh, salt = id, info).
        var signature = KT.Repeat(0x5A, 256);
        byte[] raw = SHA256.HashData([.. EntrySealing.HelloRawLabel, .. signature]);
        Assert.Equal("461ff8f69aaf8b64fab38a68951246d9713bfdb082c0d8dcb74e782defabdfe2", KT.Hex(raw));
        using var rawBuffer = KT.Secure(raw);
        using var ss = EntrySealing.SeSecret(rawBuffer, Bytes.OfGuid(id), EntrySealing.HelloInfo);
        Assert.Equal("9cbce3890ffe4aee6b01949bbb659dedeb8f408a4c00cc574c6309710caf485d", ss.HexForTesting());
        using var ssV = EntrySealing.SeSecret(rawBuffer, Bytes.OfGuid(id), EntrySealing.HelloDestructionInfo);
        Assert.Equal("efa6b655c0b784e310b40f53a182b1ad5849fe31e15f0f117da22f8394b03d0d", ssV.HexForTesting());
        // Getrennte Bereiche: das Mac-Art-Label ergibt ein anderes ss.
        using var ssMac = EntrySealing.SeSecret(rawBuffer, Bytes.OfGuid(id), EntrySealing.SeInfo);
        Assert.False(ss.ConstantTimeEquals(ssMac));
        // Der Test-Ersatz rechnet genauso (HMAC statt RSA-Signatur, Label gleich).
        var stand = SchutzProvider.HelloRaw(KT.Repeat(1, 32), keyId, challenge);
        byte[] macKey = KT.Repeat(1, 32);
        byte[] message = [.. Bytes.OfGuid(keyId), .. challenge];
        var mac = HMACSHA256.HashData(macKey, message);
        Assert.Equal(SHA256.HashData([.. EntrySealing.HelloRawLabel, .. mac]), stand);
    }
}
#endif
