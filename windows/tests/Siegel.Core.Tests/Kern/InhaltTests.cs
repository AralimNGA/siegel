#if DEBUG
// Die Kern-Tests brauchen die Testschalter des DEBUG-Baus (wie Swift @testable + #if DEBUG).
using System.Text;
using System.Text.Json;
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Inhalts-JSON (§3, v4): Schlüssel, Reihenfolge, Nullwerte, Zahlen und Zeiten wie Swift; strenges Lesen nach
/// Swift-Regeln; Konsistenzregeln; Polsterung.</summary>
public class InhaltTests
{
    private static RecoveryPublicKeys Pk() => new(Zufall.Bytes(1568), Zufall.Bytes(32));

    private static byte[] P256() => [0x04, .. Zufall.Bytes(64)];

    private static HybridCapsule Capsule() => new(Zufall.Bytes(1568), Zufall.Bytes(32));

    private static HybridWrap Wrap() => new(Capsule(), Zufall.Bytes(72));

    /// <summary>Ein Inhalt mit allem, was das JSON tragen kann (Stufe 5, versiegelt, vernichtbar, Gruppen, Vernichtung).
    /// Die Siegel sind formal gültige Zufallsbytes: geprüft wird hier nur das Format, nicht die Kryptografie (Stufe B).</summary>
    internal static VaultContent Reich()
    {
        var now = Clock.Now();
        var seKey = new EntryFactorKeys.SecureEnclaveKey(Zufall.NewGuid(), P256());
        var factors = new EntryFactorKeys(seKey, new EntryFactorKeys.CardKey(Zufall.Bytes(4), Pk()),
            new EntryFactorKeys.SecurityKeyInfo(Zufall.Bytes(64), Zufall.Bytes(32), Zufall.Bytes(16), Zufall.Bytes(32), Pk()));
        var open = new VaultEntry
        {
            Title = "Offen / mit \"Zeichen\"", Username = "anna\\b", Password = "p\u0001w\t\n\u2028", Url = "https://x.example/a?b=c",
            Notes = "äöü «» – 😀 e\u0301", Totp = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
            Created = now.AddDays(-40), Modified = now, DeletedAt = now.AddDays(-1),
            History = [new PasswordHistoryItem("alt-1", now.AddDays(-3)), new PasswordHistoryItem("alt-2", now.AddDays(-35))],
        };
        var sealedEntry = new VaultEntry { Title = "Versiegelt", Protection = EntryProtection.Fingerabdruck, Created = now, Modified = now };
        sealedEntry.SecretsSealed = true;
        var doomed = new VaultEntry { Title = "Vernichtbar", Protection = EntryProtection.Maximal, Created = now, Modified = now };
        doomed.SecretsSealed = true;
        var content = new VaultContent(now, now.AddHours(-2), SecurityLevel.Festung, factors, [open, sealedEntry, doomed])
        {
            EntryKey = EntryBaseKey.Generate(),
        };
        content.Meta[open.Id] = new EntryMeta(Zufall.Bytes(16), 3, now.AddDays(-3));
        content.Meta[sealedEntry.Id] = new EntryMeta(Zufall.Bytes(16), 4, now);
        content.Meta[doomed.Id] = new EntryMeta(null, null, null);
        content.Sealed[sealedEntry.Id] = new SealedSecrets(
            new SealedBlob(new SealedFactors(SeEphemeral: P256()), Zufall.Bytes(24), Zufall.Bytes(256 + 16)), Wrap());
        content.Destructible[doomed.Id] = new SealedBlob(new SealedFactors(P256(), Capsule()), Zufall.Bytes(24), Zufall.Bytes(272));
        content.RecoveryGroups.Add(new RecoveryGroup(Zufall.NewGuid(), FactorSet.SecureEnclave, Pk(), Wrap(),
            new SealedBlob(new SealedFactors(SeEphemeral: P256()), Zufall.Bytes(24), Zufall.Bytes(64))));
        content.Destruction = new DestructionConfig(new DestructionSettings(30, null, true),
            new DestructionConfig.VKeyInfo(Zufall.NewGuid(), P256()),
            new DestructionConfig.DuressInfo(Zufall.NewGuid(), Zufall.Bytes(16), Zufall.Bytes(16), Pk()));
        content.PrepareForSave(now);
        return content;
    }

    private static string Json(VaultContent c, bool legacyV1 = false)
    {
        var (padded, _) = PayloadCodec.Encode(c, legacyV1);
        using (padded) { return PayloadCodec.JsonStringForTesting(padded)!; }
    }

    /// <summary>JSON-Text → gepolsterter Klartext → Decode (wie aus einer Datei).</summary>
    internal static VaultContent Decode(string json)
    {
        var raw = Encoding.UTF8.GetBytes(json);
        var size = (raw.Length / PayloadCodec.BlockSize + 1) * PayloadCodec.BlockSize;
        var buf = new byte[size];
        raw.CopyTo(buf, 0);
        buf[raw.Length] = 0x80; // ISO/IEC 7816-4 wie sodium_pad
        using var padded = SecureBuffer.Copy(buf);
        return PayloadCodec.Decode(padded).Content;
    }

    private static void AssertSorted(JsonElement e, string path)
    {
        if (e.ValueKind == JsonValueKind.Object)
        {
            var names = e.EnumerateObject().Select(p => p.Name).ToList();
            Assert.Equal(names.Order(StringComparer.Ordinal), names);
            foreach (var p in e.EnumerateObject()) { AssertSorted(p.Value, path + "." + p.Name); }
        }
        else if (e.ValueKind == JsonValueKind.Array)
        {
            foreach (var x in e.EnumerateArray()) { AssertSorted(x, path + "[]"); }
        }
    }

    [Fact]
    public void Reicher_Inhalt_Rundlauf_bytegleich_sortiert_und_null_explizit()
    {
        using var c = Reich();
        var json = Json(c);
        using var back = Decode(json);
        Assert.Equal(json, Json(back));
        using var doc = JsonDocument.Parse(json);
        AssertSorted(doc.RootElement, "$");
        var root = doc.RootElement;
        Assert.Equal(["destruction", "entries", "entryKey", "factors", "level", "recoveryConfirmedAt", "recoveryGroups", "savedAt", "v"],
            root.EnumerateObject().Select(p => p.Name));
        Assert.Equal(2, root.GetProperty("v").GetInt32());
        var e0 = root.GetProperty("entries")[0];
        Assert.Equal(["created", "deletedAt", "history", "id", "meta", "modified", "notes", "password", "protection", "sealed", "title",
            "totp", "url", "username"], e0.EnumerateObject().Select(p => p.Name));
        Assert.Equal(JsonValueKind.Null, e0.GetProperty("sealed").ValueKind);
        var e2 = root.GetProperty("entries")[2];
        Assert.Equal(JsonValueKind.Null, e2.GetProperty("sealed").GetProperty("recovery").ValueKind);
        Assert.Equal(JsonValueKind.Null, e2.GetProperty("meta").GetProperty("tag").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("destruction").GetProperty("settings").GetProperty("maxFailedAttempts").ValueKind);
        // Swift-Schreibweise: „/“ als „\/“, Steuerzeichen klein, U+2028 und Nicht-ASCII roh
        Assert.Contains("\"https:\\/\\/x.example\\/a?b=c\"", json, StringComparison.Ordinal);
        Assert.Contains("p\\u0001w\\t\\n\u2028", json, StringComparison.Ordinal);
        Assert.Contains("äöü «» – 😀 e\u0301", json, StringComparison.Ordinal);
        Assert.Contains("\"Offen \\/ mit \\\"Zeichen\\\"\"", json, StringComparison.Ordinal);
        Assert.Contains("\"anna\\\\b\"", json, StringComparison.Ordinal);
        Assert.Contains("\"id\":\"" + Bytes.GuidText(c.Entries[0].Id) + "\"", json, StringComparison.Ordinal);
        // Inhalt und Tabellen kommen genau zurück
        Assert.Equal(c.Entries.Select(e => (e.Id, e.Title, e.Password, e.Notes, e.Created, e.Modified, e.DeletedAt, e.Protection)),
            back.Entries.Select(e => (e.Id, e.Title, e.Password, e.Notes, e.Created, e.Modified, e.DeletedAt, e.Protection)));
        Assert.Equal(c.Entries[0].History, back.Entries[0].History);
        Assert.Equal([false, true, true], back.Entries.Select(e => e.SecretsSealed));
        Assert.True(back.EntryKey!.Key.ConstantTimeEquals(c.EntryKey!.Key));
        Assert.Single(back.Sealed);
        Assert.Single(back.Destructible);
        Assert.Single(back.RecoveryGroups);
        Assert.Equal(c.Destruction!.Settings, back.Destruction!.Settings);
        Assert.Equal(SecurityLevel.Festung, back.Level);
        Assert.Equal(FactorSet.All, back.EntryFactors.Enrolled);
    }

    [Fact]
    public void Ohne_Selbstvernichtung_fehlt_destruction_ganz_und_v1_Schema_ist_kurz()
    {
        using var c = VaultContent.Empty(Clock.Now());
        c.Entries.Add(TestTresor.Entry("A"));
        c.PrepareForSave(Clock.Now());
        var json = Json(c);
        Assert.DoesNotContain("destruction", json, StringComparison.Ordinal);
        Assert.StartsWith("{\"entries\":[{\"created\":", json, StringComparison.Ordinal);
        Assert.Contains("\"entryKey\":null,\"factors\":{\"card\":null,\"secureEnclave\":null,\"securityKey\":null},\"level\":1,"
            + "\"recoveryConfirmedAt\":null,\"recoveryGroups\":[]", json, StringComparison.Ordinal);
        Assert.EndsWith(",\"v\":2}", json, StringComparison.Ordinal);
        var v1 = Json(c, legacyV1: true);
        using var doc = JsonDocument.Parse(v1);
        Assert.Equal(["entries", "recoveryConfirmedAt", "savedAt", "v"], doc.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(["created", "deletedAt", "history", "id", "modified", "notes", "password", "title", "url", "username"],
            doc.RootElement.GetProperty("entries")[0].EnumerateObject().Select(p => p.Name));
        using var back = Decode(v1);
        Assert.Equal(SecurityLevel.Standard, back.Level);
        Assert.Equal("", back.Entries[0].Totp);
        Assert.Equal(EntryProtection.Normal, back.Entries[0].Protection);
    }

    [Fact]
    public void Zahlen_wie_Swift_description()
    {
        // Gemessen mit Swift JSONEncoder (macOS 26) am 18.10.2026.
        (double X, string Swift)[] cases =
        [
            (1792000000.0, "1792000000"), (1792000000.123, "1792000000.123"), (0.0, "0"), (-1.5, "-1.5"), (1e-7, "1e-07"),
            (1e20, "1e+20"), (1e16, "1e+16"), (1e15, "1000000000000000"), (123456789012345680.0, "1.2345678901234568e+17"),
            (0.1, "0.1"), (1e-5, "1e-05"), (0.0001, "0.0001"), (5e-324, "5e-324"), (1.7976931348623157e308, "1.7976931348623157e+308"),
            (-0.0, "-0"), (9007199254740992.0, "9007199254740992"), (9007199254740994.0, "9.007199254740994e+15"),
            (1792000000.5, "1792000000.5"), (1760000000.1234567, "1760000000.1234567"), (1792189558.570235, "1792189558.570235"),
        ];
        foreach (var (x, swift) in cases) { Assert.Equal(swift, SwiftDouble.Format(x)); }
        KT.Throws(SiegelErrorCode.Io, "payload.encode", () => SwiftDouble.Format(double.NaN));
    }

    [Fact]
    public void Zeiten_double_zu_Ticks_und_zurueck_bitgenau_und_kanonisch()
    {
        var rng = new Random(42);
        for (var i = 0; i < 20_000; i++)
        {
            var x = 1.0e9 + rng.NextDouble() * 3.0e9;
            var d = Clock.FromSeconds(x)!.Value;
            Assert.Equal(BitConverter.DoubleToInt64Bits(x), BitConverter.DoubleToInt64Bits(Clock.ToSeconds(d)));
            var t = new DateTimeOffset(DateTimeOffset.UnixEpoch.UtcTicks + (long)(rng.NextDouble() * 3e16) + 1_000_000_000_0000000L, TimeSpan.Zero);
            var c = Clock.Canonical(t);
            Assert.Equal(c, Clock.Canonical(c));
            Assert.True(Math.Abs((c - t).Ticks) <= 2);
        }
        Assert.Equal(DateTimeOffset.UnixEpoch, Clock.FromSeconds(0));
        Assert.Equal(DateTimeOffset.UnixEpoch.AddSeconds(-1.5), Clock.FromSeconds(-1.5));
        Assert.Equal(-1.5, Clock.ToSeconds(DateTimeOffset.UnixEpoch.AddSeconds(-1.5)));
        Assert.Null(Clock.FromSeconds(1e300));
        Assert.Null(Clock.FromSeconds(double.PositiveInfinity));
        // Fixture-Wert: 1792189558.570235 → Ticks → derselbe Text
        Assert.Equal("1792189558.570235", SwiftDouble.Format(Clock.ToSeconds(Clock.FromSeconds(1792189558.570235)!.Value)));
    }

    [Fact]
    public void Lesen_nach_Swift_Regeln()
    {
        const string Rest = "\"entries\":[],\"factors\":{},\"level\":1,\"savedAt\":1792000000";
        using (var c = Decode("{\"v\":2," + Rest + "}")) { Assert.Empty(c.Entries); Assert.Null(c.EntryKey); }
        // erster von doppelten Schlüsseln gilt (gemessen), unbekannte Schlüssel werden übergangen
        using (var c = Decode("{\"v\":2,\"v\":3,\"neu\":{\"x\":[1,2]}," + Rest + "}")) { Assert.Empty(c.Entries); }
        // Int auch aus 2.0 und 2e0
        using (Decode("{\"v\":2.0," + Rest + "}")) { }
        using (Decode("{\"v\":2e0," + Rest + "}")) { }
        KT.Corrupt("payload.json", () => Decode("{\"v\":2.5," + Rest + "}"));
        KT.Corrupt("payload.version", () => Decode("{\"v\":3," + Rest + "}"));
        KT.Corrupt("payload.version", () => Decode("{\"v\":0,\"entries\":[],\"savedAt\":1}"));
        KT.Corrupt("payload.json", () => Decode("{\"v\":2,\"entries\":[],\"factors\":{},\"savedAt\":1}"));      // level fehlt
        KT.Corrupt("payload.json", () => Decode("{\"v\":2,\"entries\":[],\"factors\":{},\"level\":6,\"savedAt\":1}"));
        KT.Corrupt("payload.json", () => Decode("{\"v\":2,\"factors\":{},\"level\":1,\"savedAt\":1}"));        // entries fehlt
        KT.Corrupt("payload.json", () => Decode("{\"v\":2,\"entries\":[],\"factors\":{},\"level\":1,\"savedAt\":\"1\"}"));
        KT.Corrupt("payload.json", () => Decode("[]"));
        KT.Corrupt("payload.json", () => Decode("{\"v\":2," + Rest + "} x"));
        KT.Corrupt("payload.json", () => Decode("{\"v\":2," + Rest + ",}"));
        // v1 liest level/factors gar nicht (auch kaputte nicht)
        using (Decode("{\"v\":1,\"entries\":[],\"level\":\"kaputt\",\"factors\":7,\"savedAt\":1}")) { }
        // Data: striktes Base64 mit Auffüllung; „\/“ ist erlaubt
        var key32 = Convert.ToBase64String(new byte[32]);
        using (var c = Decode("{\"v\":2,\"entryKey\":\"" + key32.Replace("/", "\\/", StringComparison.Ordinal) + "\"," + Rest + "}"))
        {
            Assert.NotNull(c.EntryKey);
        }
        KT.Corrupt("payload.json", () => Decode("{\"v\":2,\"entryKey\":\"" + key32.TrimEnd('=') + "\"," + Rest + "}"));
        KT.Corrupt("payload.json", () => Decode("{\"v\":2,\"entryKey\":\" " + key32[1..] + "\"," + Rest + "}"));
        KT.Corrupt("payload.entryKey", () => Decode("{\"v\":2,\"entryKey\":\"" + Convert.ToBase64String(new byte[31]) + "\"," + Rest + "}"));
        // UUID nur mit 36 Zeichen
        const string E = "{\"created\":1,\"history\":[],\"modified\":1,\"notes\":\"\",\"password\":\"\",\"title\":\"\",\"url\":\"\",\"username\":\"\",\"id\":";
        using (var c = Decode("{\"v\":2,\"entries\":[" + E + "\"06caf7c7-5bfa-4c75-abec-76e7488cc7a2\"}],\"factors\":{},\"level\":1,\"savedAt\":1}"))
        {
            Assert.Equal(Guid.Parse("06CAF7C7-5BFA-4C75-ABEC-76E7488CC7A2"), c.Entries[0].Id);
            Assert.Equal(DateTimeOffset.UnixEpoch.AddSeconds(1), c.Entries[0].Created);
        }
        foreach (var bad in new[] { "\"06CAF7C75BFA4C75ABEC76E7488CC7A2\"", "\"{06CAF7C7-5BFA-4C75-ABEC-76E7488CC7A2}\"",
                     "\" 06CAF7C7-5BFA-4C75-ABEC-76E7488CC7A2\"", "7" })
        {
            KT.Corrupt("payload.json", () => Decode("{\"v\":2,\"entries\":[" + E + bad + "}],\"factors\":{},\"level\":1,\"savedAt\":1}"));
        }
        // Einzelnes Surrogat und rohe Steuerzeichen im String → Fehler (wie Swift), Surrogat-Paar → ein Zeichen
        static string WithTitle(string t) =>
            "{\"v\":2,\"entries\":[{\"created\":1,\"history\":[],\"modified\":1,\"notes\":\"\",\"password\":\"\",\"url\":\"\","
            + "\"username\":\"\",\"id\":\"06caf7c7-5bfa-4c75-abec-76e7488cc7a2\",\"title\":\"" + t + "\"}],\"factors\":{},\"level\":1,"
            + "\"savedAt\":1}";
        KT.Corrupt("payload.json", () => Decode(WithTitle("\\ud800")));
        KT.Corrupt("payload.json", () => Decode(WithTitle("a\nb")));
        KT.Corrupt("payload.json", () => Decode(WithTitle("a\u0000b")));
        using (var c = Decode(WithTitle("\\ud83d\\ude00 \\/ \\u00e4"))) { Assert.Equal("😀 / ä", c.Entries[0].Title); }
    }

    [Fact]
    public void Konsistenzregeln_beim_Lesen_und_Schreiben()
    {
        using var c = Reich();
        var json = Json(c);
        // Schutz ≥ 2 ohne Siegel
        using (var x = Reich())
        {
            x.Sealed.Clear();
            KT.Throws(SiegelErrorCode.Crypto, "entry.sealedState", () => PayloadCodec.Encode(x));
        }
        // Gruppe für eine ungültige Maske
        using (var x = Reich())
        {
            x.RecoveryGroups[0] = x.RecoveryGroups[0] with { Mask = FactorSet.Card };
            KT.Throws(SiegelErrorCode.Crypto, "payload.recoveryGroup", () => PayloadCodec.Encode(x));
        }
        // Vernichtbar ohne V
        using (var x = Reich())
        {
            x.Destruction = x.Destruction! with { VKey = null };
            KT.Throws(SiegelErrorCode.Crypto, "payload.destruction", () => PayloadCodec.Encode(x));
        }
        // Frist ausserhalb 7…365
        using (var x = Reich())
        {
            x.Destruction = x.Destruction! with { Settings = x.Destruction.Settings with { DeadmanDays = 5 } };
            KT.Throws(SiegelErrorCode.Crypto, "payload.destruction", () => PayloadCodec.Encode(x));
        }
        // reuseTag mit falscher Länge
        using (var x = Reich())
        {
            var id = x.Entries[0].Id;
            x.Meta[id] = x.Meta[id] with { Tag = new byte[15] };
            KT.Throws(SiegelErrorCode.Crypto, "payload.meta", () => PayloadCodec.Encode(x));
        }
        // Beim Lesen dieselben Regeln als corruptFile: versiegelter Eintrag mit Klartext-Passwort
        var tampered = json.Replace("\"password\":\"\",\"protection\":2", "\"password\":\"x\",\"protection\":2", StringComparison.Ordinal);
        Assert.NotEqual(json, tampered);
        KT.Corrupt("entry.sealedState", () => Decode(tampered));
        // Faktor-Teile mit falscher Länge
        var fidoCheck = Convert.ToBase64String(c.EntryFactors.SecurityKey!.Check).Replace("/", "\\/", StringComparison.Ordinal);
        KT.Corrupt("payload.factors", () => Decode(json.Replace("\"check\":\"" + fidoCheck + "\"", "\"check\":\"AAAA\"", StringComparison.Ordinal)));
        // doppelte Kennung mit Schutzdaten
        using var doc = JsonDocument.Parse(json);
        var e1 = doc.RootElement.GetProperty("entries")[1].GetRawText();
        var dup = json.Replace("\"entries\":[", "\"entries\":[" + e1 + ",", StringComparison.Ordinal);
        KT.Corrupt("payload.duplicateID", () => Decode(dup));
    }

    [Fact]
    public void Polsterung_verbirgt_kleine_Groessenunterschiede()
    {
        using var a = VaultContent.Empty(Clock.Now());
        using var b = VaultContent.Empty(Clock.Now());
        b.Entries.Add(TestTresor.Entry("Ein kurzer Eintrag", password: "x"));
        var (pa, _) = PayloadCodec.Encode(a);
        var (pb, _) = PayloadCodec.Encode(b);
        using (pa)
        using (pb)
        {
            Assert.Equal(PayloadCodec.BlockSize, pa.Length);
            Assert.Equal(pa.Length, pb.Length);
        }
        // Immer ≥ 1 Byte Polster: genau 16384 Byte JSON → zwei Blöcke
        using var c = VaultContent.Empty(Clock.Now());
        var baseLen = Encoding.UTF8.GetByteCount(Json(c));
        c.Entries.Add(TestTresor.Entry("", password: "", url: ""));
        var withEntry = Encoding.UTF8.GetByteCount(Json(c));
        c.Entries[0].Notes = new string('n', PayloadCodec.BlockSize - withEntry);
        Assert.Equal(PayloadCodec.BlockSize, Encoding.UTF8.GetByteCount(Json(c)));
        var (pc, _) = PayloadCodec.Encode(c);
        using (pc) { Assert.Equal(2 * PayloadCodec.BlockSize, pc.Length); }
        Assert.True(baseLen < withEntry);
        // Kaputtes Polster
        using var bad = SecureBuffer.Copy(new byte[PayloadCodec.BlockSize]);
        KT.Corrupt("payload.padding", () => PayloadCodec.Decode(bad));
        using var odd = SecureBuffer.Copy(new byte[100]);
        KT.Corrupt("payload.padding", () => PayloadCodec.Decode(odd));
    }

    [Fact]
    public void Verlaufsregel_und_Speichervorbereitung()
    {
        var now = Clock.Now();
        var old = Enumerable.Range(0, 15).Select(i => new PasswordHistoryItem("alt" + i, now.AddDays(-100 - i))).ToList();
        Assert.Equal(10, VaultContent.ApplyHistoryRule(old, now).Count);
        var young = Enumerable.Range(0, 35).Select(i => new PasswordHistoryItem("j" + i, now.AddHours(-i))).ToList();
        var kept = VaultContent.ApplyHistoryRule(young, now);
        Assert.Equal(30, kept.Count);
        Assert.Equal("j0", kept[0].Password);
        using var c = VaultContent.Empty(now);
        c.Entries.Add(new VaultEntry { Title = "weg", DeletedAt = now.AddDays(-31) });
        c.Entries.Add(new VaultEntry { Title = "bleibt", DeletedAt = now.AddDays(-29) });
        c.PrepareForSave(now);
        Assert.Equal(["bleibt"], c.Entries.Select(e => e.Title));
        Assert.Equal(c.Entries[0].Created, Clock.Canonical(c.Entries[0].Created));
        KT.Throws(SiegelErrorCode.Io, "entry.notesTooLong",
            () => VaultContent.Validate(new VaultEntry { Notes = new string('x', (256 << 10) + 1) }));
        KT.Throws(SiegelErrorCode.Io, "entry.passwordTooLong",
            () => VaultContent.Validate(new VaultEntry { History = [new PasswordHistoryItem(new string('x', 4097), now)] }));
    }

    [Fact]
    public void Wiederherstellung_setzt_Stufe_1_nur_ohne_Siegel()
    {
        using var c = Reich();
        KT.Throws(SiegelErrorCode.Crypto, "recovery.sealed", c.ResetAfterRecovery);
        using var open = VaultContent.Empty(Clock.Now());
        open.Level = SecurityLevel.Hoch;
        open.Entries.Add(new VaultEntry { Protection = EntryProtection.Normal });
        open.ResetAfterRecovery();
        Assert.Equal(SecurityLevel.Standard, open.Level);
    }

    [Fact]
    public void Klon_ist_unabhaengig()
    {
        using var c = Reich();
        using var k = c.Clone();
        k.Entries[0].Title = "geändert";
        k.Meta.Clear();
        Assert.NotEqual("geändert", c.Entries[0].Title);
        Assert.Equal(3, c.Meta.Count);
        Assert.True(k.EntryKey!.Key.ConstantTimeEquals(c.EntryKey!.Key));
        k.Dispose();
        Assert.True(c.EntryKey.Key.ConstantTimeEquals(c.EntryKey.Key));
    }
}
#endif
