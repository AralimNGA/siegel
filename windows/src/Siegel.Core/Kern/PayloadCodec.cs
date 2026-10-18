using Siegel.Core.Native;
using Siegel.Modell;

namespace Siegel.Core;

/// <summary>
/// JSON ↔ gepolsterter Klartext in <see cref="SecureBuffer"/> (SPEC §1.4, §3, §5), Schlüssel und Nullwerte genau wie
/// <c>PayloadCodec</c>/<c>ContentDTO</c> in VaultContent.swift (eigene Abbildung, keine Reflexion):
/// <code>
/// {"destruction":{…}?,"entries":[{"created","deletedAt","history":[{"changed","password"}],"id","meta","modified",
///   "notes","password","protection","sealed","title","totp","url","username"}],"entryKey","factors":{"card",
///   "secureEnclave","securityKey"},"level","recoveryConfirmedAt","recoveryGroups":[…],"savedAt","v":2}
/// </code>
/// Wahlfelder stehen als <c>null</c> da; nur <c>destruction</c> fehlt, wenn nichts eingerichtet ist.
/// </summary>
internal static class PayloadCodec
{
    internal const int BlockSize = 16_384;

    /// <summary>Kodiert und polstert (<c>sodium_pad</c>, immer ≥ 1 Byte). Liefert zusätzlich SHA-256 des JSON.</summary>
    internal static (SecureBuffer Padded, byte[] Digest) Encode(VaultContent content, bool legacyV1 = false)
    {
        // Nie einen inkonsistenten Eintrags-Schutz schreiben (Programmfehler fallen hier auf, nicht beim Lesen).
        if (!legacyV1) { content.CheckSealing(Fehler.Crypto); }
        using var w = new SecureJsonWriter();
        WriteContent(w, content, legacyV1 ? 1 : VaultContent.Version);
        using var json = w.Borrow(out var unpadded);
        var padded = (unpadded / BlockSize + 1) * BlockSize;
        if ((long)padded + Aead.TagBytes > FileFormat.MaxCiphertext) { throw Fehler.Io("payload.tooLarge"); }
        var digest = Sha256Hash.Of(json.Span[..unpadded]);
        var buffer = SecureBuffer.Scratch(padded);
        try
        {
            using (var o = buffer.BorrowWritable())
            {
                json.Span[..unpadded].CopyTo(o.Span);
                Pad(o.Span, unpadded);
            }
            buffer.Freeze();
            return (buffer, digest);
        }
        catch
        {
            buffer.Dispose();
            throw;
        }
    }

    private static unsafe void Pad(Span<byte> buf, int unpadded)
    {
        Libsodium.EnsureReady();
        nuint result = 0;
        int rc;
        fixed (byte* p = buf)
        {
            rc = Libsodium.sodium_pad(&result, p, (nuint)unpadded, BlockSize, (nuint)buf.Length);
        }
        if (rc != 0 || result != (nuint)buf.Length) { throw Fehler.Io("payload.pad"); }
    }

    /// <summary>Entfernt das Padding und dekodiert direkt aus dem sicheren Puffer. Prüft danach wie Swift: Version
    /// (<c>payload.version</c>), Faktor-Teile, Grundschlüssel, doppelte Kennungen, Selbstvernichtung, Schutz-Regeln.</summary>
    internal static unsafe (VaultContent Content, byte[] Digest) Decode(SecureBuffer padded)
    {
        using var l = padded.Borrow();
        var buf = l.Span;
        if (buf.Length == 0 || buf.Length % BlockSize != 0) { throw Fehler.Corrupt("payload.padding"); }
        Libsodium.EnsureReady();
        nuint unpadded = 0;
        int rc;
        fixed (byte* p = buf)
        {
            rc = Libsodium.sodium_unpad(&unpadded, p, (nuint)buf.Length, BlockSize);
        }
        if (rc != 0) { throw Fehler.Corrupt("payload.padding"); }
        var raw = buf[..(int)unpadded];
        var digest = Sha256Hash.Of(raw);
        var root = JNode.Parse(raw);
        return (ReadContent(root), digest);
    }

#if DEBUG
    /// <summary>Nur Tests: JSON-Text eines gepolsterten Klartexts.</summary>
    internal static unsafe string? JsonStringForTesting(SecureBuffer padded)
    {
        using var l = padded.Borrow();
        nuint n = 0;
        fixed (byte* p = l.Span)
        {
            if (Libsodium.sodium_unpad(&n, p, (nuint)l.Span.Length, BlockSize) != 0) { return null; }
        }
        return System.Text.Encoding.UTF8.GetString(l.Span[..(int)n]);
    }
#endif

    // MARK: Schreiben (Schlüssel ordinal sortiert, wie JSONEncoder .sortedKeys)

    private static void WriteContent(SecureJsonWriter w, VaultContent c, int version)
    {
        w.BeginObject();
        if (version >= 2 && c.Destruction is { } d)
        {
            // Nur geschrieben, wenn eingerichtet: Inhalte ohne Selbstvernichtung bleiben bytegleich.
            w.Key("destruction");
            WriteDestruction(w, d);
        }
        w.Key("entries");
        w.BeginArray();
        foreach (var e in c.Entries)
        {
            c.Meta.TryGetValue(e.Id, out var meta);
            c.Sealed.TryGetValue(e.Id, out var sealedSecrets);
            c.Destructible.TryGetValue(e.Id, out var destructible);
            WriteEntry(w, e, meta, sealedSecrets, destructible, version);
        }
        w.EndArray();
        if (version >= 2)
        {
            w.Key("entryKey");
            if (c.EntryKey is { } k)
            {
                using var kl = k.Key.Borrow();
                w.Base64(kl.Span);
            }
            else
            {
                w.Null();
            }
            w.Key("factors");
            WriteFactors(w, c.EntryFactors);
            w.Key("level");
            w.Integer((int)c.Level);
        }
        w.Key("recoveryConfirmedAt");
        if (c.RecoveryConfirmedAt is { } rc) { w.Date(rc); } else { w.Null(); }
        if (version >= 2)
        {
            w.Key("recoveryGroups");
            w.BeginArray();
            foreach (var g in c.RecoveryGroups) { WriteGroup(w, g); }
            w.EndArray();
        }
        w.Key("savedAt");
        w.Date(c.SavedAt);
        w.Key("v");
        w.Integer(version);
        w.EndObject();
    }

    private static void WriteEntry(SecureJsonWriter w, VaultEntry e, EntryMeta? meta, SealedSecrets? sealedSecrets,
        SealedBlob? destructible, int version)
    {
        w.BeginObject();
        w.Key("created");
        w.Date(e.Created);
        w.Key("deletedAt");
        if (e.DeletedAt is { } del) { w.Date(del); } else { w.Null(); }
        w.Key("history");
        w.BeginArray();
        foreach (var h in e.History)
        {
            w.BeginObject();
            w.Key("changed");
            w.Date(h.Changed);
            w.Key("password");
            w.String(h.Password);
            w.EndObject();
        }
        w.EndArray();
        w.Key("id");
        w.Uuid(e.Id);
        if (version >= 2)
        {
            w.Key("meta");
            if (meta is null) { w.Null(); } else { WriteMeta(w, meta); }
        }
        w.Key("modified");
        w.Date(e.Modified);
        w.Key("notes");
        w.String(e.Notes);
        w.Key("password");
        w.String(e.Password);
        if (version >= 2)
        {
            w.Key("protection");
            w.Integer((int)e.Protection);
            w.Key("sealed");
            if (sealedSecrets is not null)
            {
                WriteSealed(w, sealedSecrets.Blob, sealedSecrets.Recovery);
            }
            else if (destructible is not null)
            {
                WriteSealed(w, destructible, null);
            }
            else
            {
                w.Null();
            }
        }
        w.Key("title");
        w.String(e.Title);
        if (version >= 2)
        {
            w.Key("totp");
            w.String(e.Totp);
        }
        w.Key("url");
        w.String(e.Url);
        w.Key("username");
        w.String(e.Username);
        w.EndObject();
    }

    private static void WriteMeta(SecureJsonWriter w, EntryMeta m)
    {
        w.BeginObject();
        w.Key("changed");
        if (m.Changed is { } c) { w.Date(c); } else { w.Null(); }
        w.Key("strength");
        if (m.Strength is { } s) { w.Integer(s); } else { w.Null(); }
        w.Key("tag");
        if (m.Tag is { } t) { w.Base64(t); } else { w.Null(); }
        w.EndObject();
    }

    private static void WriteCapsule(SecureJsonWriter w, HybridCapsule c)
    {
        w.BeginObject();
        w.Key("ctM");
        w.Base64(c.CtM);
        w.Key("ctX");
        w.Base64(c.CtX);
        w.EndObject();
    }

    private static void WriteWrap(SecureJsonWriter w, HybridWrap x)
    {
        w.BeginObject();
        w.Key("ctM");
        w.Base64(x.Capsule.CtM);
        w.Key("ctX");
        w.Base64(x.Capsule.CtX);
        w.Key("key");
        w.Base64(x.Wrapped);
        w.EndObject();
    }

    private static void WriteBlob(SecureJsonWriter w, SealedBlob b)
    {
        w.BeginObject();
        w.Key("card");
        if (b.Factors.Card is { } card) { WriteCapsule(w, card); } else { w.Null(); }
        w.Key("ct");
        w.Base64(b.Ciphertext);
        w.Key("fido");
        if (b.Factors.Fido is { } fido) { WriteCapsule(w, fido); } else { w.Null(); }
        if (b.Factors.Hello is { } hello)
        {
            // Windows-Hello-Art (W4.1): nur wenn vorhanden, damit Mac-Inhalte bytegleich bleiben.
            w.Key("hello");
            w.BeginObject();
            w.Key("salt");
            w.Base64(hello.Salt);
            w.Key("version");
            w.Integer(hello.Version);
            w.EndObject();
        }
        w.Key("nonce");
        w.Base64(b.Nonce);
        w.Key("se");
        if (b.Factors.SeEphemeral is { } se) { w.Base64(se); } else { w.Null(); }
        w.EndObject();
    }

    private static void WriteSealed(SecureJsonWriter w, SealedBlob blob, HybridWrap? recovery)
    {
        w.BeginObject();
        w.Key("blob");
        WriteBlob(w, blob);
        w.Key("recovery");
        if (recovery is not null) { WriteWrap(w, recovery); } else { w.Null(); }
        w.EndObject();
    }

    private static void WriteGroup(SecureJsonWriter w, RecoveryGroup g)
    {
        w.BeginObject();
        w.Key("anchor");
        WriteBlob(w, g.Anchor);
        w.Key("id");
        w.Uuid(g.Id);
        w.Key("kit");
        WriteWrap(w, g.Kit);
        w.Key("mask");
        w.Integer((byte)g.Mask);
        w.Key("pkM");
        w.Base64(g.Pk.PkM);
        w.Key("pkX");
        w.Base64(g.Pk.PkX);
        w.EndObject();
    }

    private static void WriteFactors(SecureJsonWriter w, EntryFactorKeys f)
    {
        w.BeginObject();
        w.Key("card");
        if (f.Card is { } c)
        {
            w.BeginObject();
            w.Key("pkM");
            w.Base64(c.Pk.PkM);
            w.Key("pkX");
            w.Base64(c.Pk.PkX);
            w.Key("tag");
            w.Base64(c.Tag);
            w.EndObject();
        }
        else
        {
            w.Null();
        }
        w.Key("secureEnclave");
        if (f.SecureEnclave is { } se)
        {
            w.BeginObject();
            w.Key("keyID");
            w.Uuid(se.KeyId);
            w.Key("publicKey");
            w.Base64(se.PublicKey);
            w.EndObject();
        }
        else
        {
            w.Null();
        }
        w.Key("securityKey");
        if (f.SecurityKey is { } k)
        {
            w.BeginObject();
            w.Key("check");
            w.Base64(k.Check);
            w.Key("credentialID");
            w.Base64(k.CredentialId);
            w.Key("entrySalt");
            w.Base64(k.EntrySalt);
            w.Key("pkM");
            w.Base64(k.Pk.PkM);
            w.Key("pkX");
            w.Base64(k.Pk.PkX);
            w.Key("salt");
            w.Base64(k.Salt);
            w.EndObject();
        }
        else
        {
            w.Null();
        }
        if (f.WindowsHello is { } h)
        {
            // Windows-Hello-Art (W4.1): nur wenn eingerichtet (Mac-Inhalte bleiben bytegleich).
            w.Key("windowsHello");
            w.BeginObject();
            w.Key("keyID");
            w.Uuid(h.KeyId);
            w.Key("version");
            w.Integer(h.Version);
            w.EndObject();
        }
        w.EndObject();
    }

    private static void WriteDestruction(SecureJsonWriter w, DestructionConfig d)
    {
        w.BeginObject();
        w.Key("duress");
        if (d.Duress is { } x)
        {
            w.BeginObject();
            w.Key("check");
            w.Base64(x.Check);
            w.Key("fileID");
            w.Uuid(x.FileId);
            w.Key("pkM");
            w.Base64(x.Pk.PkM);
            w.Key("pkX");
            w.Base64(x.Pk.PkX);
            w.Key("salt");
            w.Base64(x.Salt);
            w.EndObject();
        }
        else
        {
            w.Null();
        }
        w.Key("settings");
        w.BeginObject();
        w.Key("deadmanDays");
        if (d.Settings.DeadmanDays is { } dd) { w.Integer(dd); } else { w.Null(); }
        w.Key("duressEnabled");
        w.Bool(d.Settings.DuressEnabled);
        w.Key("maxFailedAttempts");
        if (d.Settings.MaxFailedAttempts is { } n) { w.Integer(n); } else { w.Null(); }
        w.EndObject();
        w.Key("vKey");
        if (d.VKey is { } v)
        {
            w.BeginObject();
            w.Key("keyID");
            w.Uuid(v.KeyId);
            if (v.IsWindowsHello)
            {
                w.Key("windowsHello");
                w.Integer(v.HelloVersion);
            }
            else
            {
                w.Key("publicKey");
                w.Base64(v.PublicKey);
            }
            w.EndObject();
        }
        else
        {
            w.Null();
        }
        w.EndObject();
    }

    // MARK: Lesen (wie die Decodable-Implementierungen der Swift-DTOs)

    private sealed record EntryRead(VaultEntry Entry, EntryMeta? Meta, SealedBlob? Blob, HybridWrap? Recovery, bool HasSealed);

    private static VaultContent ReadContent(JNode rootNode)
    {
        var root = JRead.Obj(rootNode);
        var v = JRead.Int(root.Required("v"));
        var savedAt = JRead.Date(root.Required("savedAt"));
        var recoveryConfirmedAt = root.Optional("recoveryConfirmedAt") is { } rca ? JRead.Date(rca) : (DateTimeOffset?)null;
        var level = SecurityLevel.Standard;
        var factors = EntryFactorKeys.None;
        SecureBuffer? entryKey = null;
        var groups = new List<RecoveryGroup>();
        DestructionRead? destruction = null;
        try
        {
            if (v >= 2)
            {
                level = ReadLevel(root.Required("level"));
                factors = ReadFactors(root.Required("factors"));
                // Direkt in sodium-Speicher: keine verwaltete Rohkopie des Grundschlüssels (Befund hygiene-3).
                if (root.Optional("entryKey") is { } ek) { entryKey = JRead.SecretData(ek); }
                if (root.Optional("recoveryGroups") is { } rg) { groups = [.. JRead.Arr(rg).Select(ReadGroup)]; }
                if (root.Optional("destruction") is { } dn) { destruction = ReadDestruction(dn); }
            }
            var entries = JRead.Arr(root.Required("entries")).Select(ReadEntry).ToList();
            if (v is not (1 or VaultContent.Version)) { throw Fehler.Corrupt("payload.version"); }
            factors.Validate();
            var content = new VaultContent(savedAt, recoveryConfirmedAt, level, factors, [.. entries.Select(e => e.Entry)]);
            try
            {
                if (entryKey is not null)
                {
                    if (entryKey.Length != 32) { throw Fehler.Corrupt("payload.entryKey"); }
                    content.EntryKey = new EntryBaseKey(entryKey);
                    entryKey = null;                                    // gehört jetzt dem Inhalt
                }
                var ids = new HashSet<Guid>();
                foreach (var e in entries)
                {
                    var id = e.Entry.Id;
                    // Jede Kennung nur einmal (v4.8, Befund robust-8): mit Schutzdaten würden Geheimteile vertauscht, und
                    // ohne würde das Speichern (Meta je Kennung) einen Inhalt schreiben, der nicht wieder lesbar ist.
                    if (!ids.Add(id)) { throw Fehler.Corrupt("payload.duplicateID"); }
                    if (e.Meta is not null) { content.Meta[id] = e.Meta; }
                    if (e.Blob is not null)
                    {
                        if (e.Recovery is not null) { content.Sealed[id] = new SealedSecrets(e.Blob, e.Recovery); }
                        else { content.Destructible[id] = e.Blob; }
                    }
                }
                content.RecoveryGroups = groups;
                if (destruction is not null) { content.Destruction = destruction.Value(); }
                content.CheckSealing(Fehler.Corrupt);
                return content;
            }
            catch
            {
                content.Dispose();
                throw;
            }
        }
        finally
        {
            entryKey?.Dispose();
        }
    }

    private static SecurityLevel ReadLevel(JNode n)
    {
        var raw = JRead.Int(n);
        return raw is >= 1 and <= 5 ? (SecurityLevel)raw : throw Fehler.Corrupt("payload.json");
    }

    private static EntryProtection ReadProtection(JNode n)
    {
        var raw = JRead.Int(n);
        return raw is >= 1 and <= 5 ? (EntryProtection)raw : throw Fehler.Corrupt("payload.json");
    }

    private static EntryRead ReadEntry(JNode node)
    {
        var o = JRead.Obj(node);
        var e = new VaultEntry
        {
            Id = JRead.Uuid(o.Required("id")),
            Title = JRead.Str(o.Required("title")),
            Username = JRead.Str(o.Required("username")),
            Password = JRead.Str(o.Required("password")),
            Url = JRead.Str(o.Required("url")),
            Notes = JRead.Str(o.Required("notes")),
            Created = JRead.Date(o.Required("created")),
            Modified = JRead.Date(o.Required("modified")),
            DeletedAt = o.Optional("deletedAt") is { } d ? JRead.Date(d) : null,
            History = [.. JRead.Arr(o.Required("history")).Select(ReadHistory)],
            // v1-Inhalte kennen TOTP und Schutz nicht.
            Totp = o.Optional("totp") is { } t ? JRead.Str(t) : "",
            Protection = o.Optional("protection") is { } p ? ReadProtection(p) : EntryProtection.Normal,
        };
        // Stufe A und v1 kennen meta/sealed nicht.
        EntryMeta? meta = null;
        if (o.Optional("meta") is { } m)
        {
            var mo = JRead.Obj(m);
            meta = new EntryMeta(
                mo.Optional("tag") is { } tag ? JRead.Data(tag) : null,
                mo.Optional("strength") is { } s ? ClampInt(JRead.Int(s)) : null,
                mo.Optional("changed") is { } c ? JRead.Date(c) : null);
        }
        SealedBlob? blob = null;
        HybridWrap? recovery = null;
        var hasSealed = false;
        if (o.Optional("sealed") is { } sn)
        {
            var so = JRead.Obj(sn);
            blob = ReadBlob(so.Required("blob"));
            recovery = so.Optional("recovery") is { } r ? ReadWrap(r) : null;
            hasSealed = true;
        }
        e.SecretsSealed = hasSealed;
        return new EntryRead(e, meta, blob, recovery, hasSealed);
    }

    /// <summary>Swift Int ist 64 Bit; ausserhalb von Int32 kann es ohnehin keine gültige Stärke sein (0…4).</summary>
    private static int ClampInt(long v) => v is >= int.MinValue and <= int.MaxValue ? (int)v : int.MaxValue;

    private static PasswordHistoryItem ReadHistory(JNode node)
    {
        var o = JRead.Obj(node);
        return new PasswordHistoryItem(JRead.Str(o.Required("password")), JRead.Date(o.Required("changed")));
    }

    private static HybridCapsule ReadCapsule(JNode node)
    {
        var o = JRead.Obj(node);
        return new HybridCapsule(JRead.Data(o.Required("ctM")), JRead.Data(o.Required("ctX")));
    }

    private static HybridWrap ReadWrap(JNode node)
    {
        var o = JRead.Obj(node);
        return new HybridWrap(new HybridCapsule(JRead.Data(o.Required("ctM")), JRead.Data(o.Required("ctX"))),
            JRead.Data(o.Required("key")));
    }

    private static SealedBlob ReadBlob(JNode node)
    {
        var o = JRead.Obj(node);
        var nonce = JRead.Data(o.Required("nonce"));
        var ct = JRead.Data(o.Required("ct"));
        var se = o.Optional("se") is { } s ? JRead.Data(s) : null;
        var card = o.Optional("card") is { } c ? ReadCapsule(c) : null;
        var fido = o.Optional("fido") is { } f ? ReadCapsule(f) : null;
        HelloPart? hello = null;
        if (o.Optional("hello") is { } h)
        {
            var ho = JRead.Obj(h);
            hello = new HelloPart(JRead.Data(ho.Required("salt")), ClampInt(JRead.Int(ho.Required("version"))));
        }
        return new SealedBlob(new SealedFactors(se, card, fido, hello), nonce, ct);
    }

    private static RecoveryGroup ReadGroup(JNode node)
    {
        var o = JRead.Obj(node);
        return new RecoveryGroup(JRead.Uuid(o.Required("id")), (FactorSet)JRead.UInt8(o.Required("mask")),
            new RecoveryPublicKeys(JRead.Data(o.Required("pkM")), JRead.Data(o.Required("pkX"))), ReadWrap(o.Required("kit")),
            ReadBlob(o.Required("anchor")));
    }

    private static EntryFactorKeys ReadFactors(JNode node)
    {
        var o = JRead.Obj(node);
        EntryFactorKeys.SecureEnclaveKey? se = null;
        if (o.Optional("secureEnclave") is { } s)
        {
            var so = JRead.Obj(s);
            se = new EntryFactorKeys.SecureEnclaveKey(JRead.Uuid(so.Required("keyID")), JRead.Data(so.Required("publicKey")));
        }
        EntryFactorKeys.CardKey? card = null;
        if (o.Optional("card") is { } c)
        {
            var co = JRead.Obj(c);
            card = new EntryFactorKeys.CardKey(JRead.Data(co.Required("tag")),
                new RecoveryPublicKeys(JRead.Data(co.Required("pkM")), JRead.Data(co.Required("pkX"))));
        }
        EntryFactorKeys.SecurityKeyInfo? key = null;
        if (o.Optional("securityKey") is { } k)
        {
            var ko = JRead.Obj(k);
            key = new EntryFactorKeys.SecurityKeyInfo(JRead.Data(ko.Required("credentialID")), JRead.Data(ko.Required("salt")),
                JRead.Data(ko.Required("check")), JRead.Data(ko.Required("entrySalt")),
                new RecoveryPublicKeys(JRead.Data(ko.Required("pkM")), JRead.Data(ko.Required("pkX"))));
        }
        EntryFactorKeys.HelloKey? hello = null;
        if (o.Optional("windowsHello") is { } h)
        {
            var ho = JRead.Obj(h);
            hello = new EntryFactorKeys.HelloKey(JRead.Uuid(ho.Required("keyID")), ClampInt(JRead.Int(ho.Required("version"))));
        }
        return new EntryFactorKeys(se, card, key, hello);
    }

    /// <summary>Roh gelesene Selbstvernichtung; Längen prüft <see cref="Value"/> (wie Swift <c>DestructionDTO.value()</c>).</summary>
    private sealed record DestructionRead(DestructionSettings Settings, (Guid KeyId, byte[]? PublicKey, int HelloVersion)? VKey,
        (Guid FileId, byte[] Salt, byte[] Check, byte[] PkM, byte[] PkX)? Duress)
    {
        internal DestructionConfig Value()
        {
            DestructionConfig.VKeyInfo? vKey = null;
            if (VKey is { } v)
            {
                // Mac: öffentlicher P-256-Schlüssel; Windows: Windows-Hello-Schlüssel (Version), nie beides.
                vKey = v.PublicKey is { } pub && v.HelloVersion == 0
                    ? new DestructionConfig.VKeyInfo(v.KeyId, pub)
                    : v.PublicKey is null && v.HelloVersion != 0
                        ? new DestructionConfig.VKeyInfo(v.KeyId, [], v.HelloVersion)
                        : throw Fehler.Corrupt("payload.destruction");
                if (!vKey.IsWellFormed) { throw Fehler.Corrupt("payload.destruction"); }
            }
            DestructionConfig.DuressInfo? duress = null;
            if (Duress is { } d)
            {
                if (d.Salt.Length != DestructionConfig.DuressSaltBytes || d.Check.Length != DestructionConfig.DuressCheckBytes
                    || d.PkM.Length != RecoveryPublicKeys.PkMBytes || d.PkX.Length != RecoveryPublicKeys.PkXBytes)
                {
                    throw Fehler.Corrupt("payload.destruction");
                }
                duress = new DestructionConfig.DuressInfo(d.FileId, d.Salt, d.Check, new RecoveryPublicKeys(d.PkM, d.PkX));
            }
            return new DestructionConfig(Settings, vKey, duress);
        }
    }

    private static DestructionRead ReadDestruction(JNode node)
    {
        var o = JRead.Obj(node);
        var so = JRead.Obj(o.Required("settings"));
        var settings = new DestructionSettings(
            so.Optional("deadmanDays") is { } dd ? ClampInt(JRead.Int(dd)) : null,
            so.Optional("maxFailedAttempts") is { } mf ? ClampInt(JRead.Int(mf)) : null,
            JRead.Bool(so.Required("duressEnabled")));
        (Guid, byte[]?, int)? vKey = null;
        if (o.Optional("vKey") is { } v)
        {
            var vo = JRead.Obj(v);
            var hello = vo.Optional("windowsHello") is { } h ? ClampInt(JRead.Int(h)) : 0;
            var pub = vo.Optional("publicKey") is { } pk ? JRead.Data(pk) : null;
            // Mac-Inhalte (ohne windowsHello) verlangen publicKey wie die Swift-DTO.
            if (hello == 0 && pub is null) { throw Fehler.Corrupt("payload.json"); }
            vKey = (JRead.Uuid(vo.Required("keyID")), pub, hello);
        }
        (Guid, byte[], byte[], byte[], byte[])? duress = null;
        if (o.Optional("duress") is { } d)
        {
            var dO = JRead.Obj(d);
            duress = (JRead.Uuid(dO.Required("fileID")), JRead.Data(dO.Required("salt")), JRead.Data(dO.Required("check")),
                JRead.Data(dO.Required("pkM")), JRead.Data(dO.Required("pkX")));
        }
        return new DestructionRead(settings, vKey, duress);
    }
}
