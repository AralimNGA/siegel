using Siegel.Modell;

namespace Siegel.Core;

/// <summary>
/// Vernichtungs-Passwort (§23.2 Nr. 3, v4.4), byte-genau wie DuressCrypto in DestructionState.swift:
/// <code>
///   d      = Argon2id(Vernichtungs-Passwort, dSalt[16], Parameter des Kopfes)
///   pk     = Hybrid(HKDF(d, salt = vaultID, "Siegel v2 duress ML-KEM-1024 seed" / "Siegel v2 duress X25519"))
///   check  = HKDF-SHA512(d, salt = vaultID, "Siegel v2 duress check", 16)
///   F      = HKDF-SHA512(e ‖ c ‖ [y] (§13.1), salt = vaultID, "Siegel v2 duress factors" ‖ factorMask, 32)
///   kek    = HKDF-SHA512(Kombinierer §1.3 (Label "Siegel v2 duress", Zusatzfeld fileID) ‖ F, salt = fileID,
///                        "Siegel v2 duress kek", 32)
///   wrap   = XChaCha20-Poly1305(kek, DEK, AD = "Siegel v2 duress" ‖ vaultID ‖ fileID ‖ dSalt)
/// </code>
/// </summary>
internal static class DuressCrypto
{
    internal const int SaltBytes = 16;
    internal const int CheckBytes = 16;
    internal static readonly byte[] Label = Bytes.Ascii("Siegel v2 duress");
    internal static readonly byte[] SeedInfo = Bytes.Ascii("Siegel v2 duress ML-KEM-1024 seed");
    internal static readonly byte[] X25519Info = Bytes.Ascii("Siegel v2 duress X25519");
    internal static readonly byte[] CheckInfo = Bytes.Ascii("Siegel v2 duress check");
    internal static readonly byte[] BindingInfo = Bytes.Ascii("Siegel v2 duress factors");
    internal static readonly byte[] KekInfo = Bytes.Ascii("Siegel v2 duress kek");

    /// <summary>F aus den Faktoren, die der Kopf verlangt; null ohne Faktoren (v1, Stufe 1). Fehlt ein verlangter Faktor →
    /// <c>FactorMissing</c>. Gehört dem Aufrufer.</summary>
    internal static SecureBuffer? Binding(VaultHeader header, FactorSecrets factors)
    {
        if (header.FormatVersion < 2 || header.Factors == FactorSet.None) { return null; }
        var keys = new List<SecureBuffer>();
        try
        {
            foreach (var kind in header.Factors.Kinds())
            {
                var raw = factors.Secret(kind) ?? throw Fehler.FactorMissing(kind);
                keys.Add(FactorKdf.FactorKey(raw, kind, header.VaultId));
            }
            using var ikm = FactorKdf.Concatenate(keys);
            return Hkdf.Derive(ikm, header.VaultId, [.. BindingInfo, (byte)header.Factors], 32);
        }
        finally
        {
            foreach (var k in keys) { k.Dispose(); }
        }
    }

    /// <summary>Wie <see cref="Binding"/>, aber ohne Fehler (null, wenn etwas fehlt) – wie Swift <c>try?</c>.</summary>
    internal static SecureBuffer? TryBinding(VaultHeader header, FactorSecrets factors)
    {
        try
        {
            return Binding(header, factors);
        }
        catch (SiegelException)
        {
            return null;
        }
    }

    internal static SecureBuffer BoundKek(SecureBuffer combined, SecureBuffer binding, Guid fileId)
    {
        using var ikm = FactorKdf.Concatenate([combined, binding]);
        return Hkdf.Derive(ikm, Bytes.OfGuid(fileId), KekInfo, 32);
    }

    /// <summary>d (32 B). Gleiche Fehler wie beim Master-Passwort.</summary>
    internal static SecureBuffer Derive(SecureBuffer password, byte[] salt, KdfParameters kdf, KdfLimits limits)
    {
        if (salt.Length != SaltBytes) { throw Fehler.Crypto("duress.salt"); }
        return Kdf.DeriveKek(password, salt, kdf, limits);
    }

    internal static RecoveryPublicKeys PublicKeys(SecureBuffer d, byte[] vaultId) =>
        RecoveryKem.DerivePublicKeys(d, vaultId, SeedInfo, X25519Info);

    internal static byte[] Check(SecureBuffer d, byte[] vaultId)
    {
        using var c = Hkdf.Derive(d, vaultId, CheckInfo, CheckBytes);
        using var l = c.Borrow();
        return l.Span.ToArray();
    }

    internal static byte[] WrapAd(byte[] vaultId, Guid fileId, byte[] salt) => Bytes.Concat(Label, vaultId, Bytes.OfGuid(fileId), salt);

    /// <summary>Neuer Umschlag des DEK (frische Kapselung, an F gebunden) als Datei-Inhalt.</summary>
    internal static DuressFile Seal(SecureBuffer dek, DestructionConfig.DuressInfo duress, SecureBuffer binding, byte[] vaultId)
    {
        using var enc = RecoveryKem.Encapsulate(duress.Pk, Label, Bytes.OfGuid(duress.FileId));
        using var kek = BoundKek(enc.Kek, binding, duress.FileId);
        var wrapped = Aead.Wrap(kek, dek, WrapAd(vaultId, duress.FileId, duress.Salt));
        return new DuressFile(duress.FileId, duress.Salt, duress.Check, new HybridCapsule(enc.CtM, enc.CtX), wrapped);
    }

    /// <summary>Ergebnis mit d: erkannt (Prüfwert passt) und – wenn der Umschlag zu Passwort und Faktoren passt – der DEK
    /// (gehört dem Aufrufer).</summary>
    internal static (bool Recognized, SecureBuffer? Dek) Open(DuressFile file, SecureBuffer d, SecureBuffer? binding, byte[] vaultId)
    {
        try
        {
            if (!Bytes.ConstantTimeEqual(Check(d, vaultId), file.Check)) { return (false, null); }
        }
        catch (SiegelException)
        {
            return (false, null);
        }
        if (binding is null) { return (true, null); }
        try
        {
            var pk = PublicKeys(d, vaultId);
            using var keys = RecoveryKem.PrivateKeys(d, vaultId, SeedInfo, X25519Info, pk);
            if (keys is null) { return (true, null); }
            using var combined = RecoveryKem.Decapsulate(keys, file.Capsule.CtM, file.Capsule.CtX, Label, Bytes.OfGuid(file.FileId));
            using var kek = BoundKek(combined, binding, file.FileId);
            return (true, Aead.Unwrap(kek, file.Wrapped, WrapAd(vaultId, file.FileId, file.Salt)));
        }
        catch (SiegelException)
        {
            return (true, null);
        }
    }
}

/// <summary>
/// <c>Hardware/&lt;fileID&gt;.siegelhw</c> (§23.2 Nr. 3): magic <c>"SIEGELHW"</c> ‖ version u16 = 1 ‖ kind u8 = 2 ‖
/// fileID (16) ‖ blobLength u16 = 1922 ‖ blob ‖ point (P-256 x963, 65) ‖ SHA3-256("Siegel v2 hw file check" ‖ alles
/// davor) (32); blob = dSalt ‖ check ‖ ctM ‖ ctX ‖ wrap ‖ Zufall. Immer genau 2048 Byte.
/// </summary>
internal sealed record DuressFile(Guid FileId, byte[] Salt, byte[] Check, HybridCapsule Capsule, byte[] Wrapped)
{
    internal static readonly byte[] Magic = Bytes.Ascii("SIEGELHW");
    internal const ushort FormatVersion = 1;
    internal const byte Kind = 2;
    internal const int BlobLength = 1922;
    internal const int PointLength = 65;
    internal const int ChecksumLength = 32;
    internal const int FixedLength = 8 + 2 + 1 + 16 + 2;
    internal const int FileLength = FixedLength + BlobLength + PointLength + ChecksumLength;
    internal const int PayloadLength = DuressCrypto.SaltBytes + DuressCrypto.CheckBytes + RecoveryKem.CtMBytes + RecoveryKem.CtXBytes
        + Aead.WrappedBytes;
    internal static readonly byte[] ChecksumLabel = Bytes.Ascii("Siegel v2 hw file check");

    public bool Equals(DuressFile? other) =>
        other is not null && FileId == other.FileId && Bytes.Same(Salt, other.Salt) && Bytes.Same(Check, other.Check)
        && Capsule.Equals(other.Capsule) && Bytes.Same(Wrapped, other.Wrapped);

    public override int GetHashCode() => FileId.GetHashCode();

    internal byte[] Encoded()
    {
        if (Salt.Length != DuressCrypto.SaltBytes || Check.Length != DuressCrypto.CheckBytes || !Capsule.IsWellFormed
            || Wrapped.Length != Aead.WrappedBytes)
        {
            throw Fehler.Crypto("duress.file");
        }
        var w = new ByteWriter(FileLength);
        w.Write(Magic);
        w.WriteU16(FormatVersion);
        w.WriteByte(Kind);
        w.Write(Bytes.OfGuid(FileId));
        w.WriteU16(BlobLength);
        w.Write(Salt);
        w.Write(Check);
        w.Write(Capsule.CtM);
        w.Write(Capsule.CtX);
        w.Write(Wrapped);
        w.Write(Zufall.Bytes(BlobLength - PayloadLength));
        w.Write(P256.RandomPoint());
        w.Write(Checksum(w.Written));
        return w.ToArray();
    }

    /// <summary>Strenger Parser; jede Abweichung → <c>CorruptFile("duress.…")</c>.</summary>
    internal static DuressFile Decode(byte[] bytes, Guid expectedId)
    {
        if (bytes.Length != FileLength) { throw Fehler.Corrupt("duress.length"); }
        var bodyLength = FileLength - ChecksumLength;
        if (!Bytes.ConstantTimeEqual(Checksum(bytes.AsSpan(0, bodyLength)), bytes.AsSpan(bodyLength)))
        {
            throw Fehler.Corrupt("duress.checksum");
        }
        var r = new ByteReader(bytes, 0, bodyLength);
        if (!r.Take(8, "duress.magic").AsSpan().SequenceEqual(Magic) || r.ReadU16("duress.version") != FormatVersion
            || r.ReadU8("duress.kind") != Kind)
        {
            throw Fehler.Corrupt("duress.magic");
        }
        var id = Bytes.ToGuid(r.Take(16, "duress.id"));
        if (id != expectedId) { throw Fehler.Corrupt("duress.id"); }
        if (r.ReadU16("duress.blob") != BlobLength) { throw Fehler.Corrupt("duress.blob"); }
        var salt = r.Take(DuressCrypto.SaltBytes, "duress.blob");
        var check = r.Take(DuressCrypto.CheckBytes, "duress.blob");
        var ctM = r.Take(RecoveryKem.CtMBytes, "duress.blob");
        var ctX = r.Take(RecoveryKem.CtXBytes, "duress.blob");
        var wrapped = r.Take(Aead.WrappedBytes, "duress.blob");
        _ = r.Take(BlobLength - PayloadLength, "duress.blob");
        var point = r.Take(PointLength, "duress.point");
        if (point[0] != 0x04 || !P256.IsValidPublicKey(point) || r.Remaining != 0) { throw Fehler.Corrupt("duress.point"); }
        return new DuressFile(id, salt, check, new HybridCapsule(ctM, ctX), wrapped);
    }

    internal static byte[] Checksum(ReadOnlySpan<byte> body) => new Sha3Hasher().Update(ChecksumLabel).Update(body).Final();

    /// <summary>Form einer Ablage (Länge, magic, Version, kind, Bloblänge)? Prüfsumme, Kennung und Inhalt zählen nicht:
    /// auch eine beschädigte Ablage darf ersetzt werden, ein Schlüssel (andere Länge bzw. Bloblänge) nie.</summary>
    internal static bool HasShape(byte[] bytes) =>
        bytes.Length == FileLength && bytes.AsSpan(0, 8).SequenceEqual(Magic) && bytes[8] == (FormatVersion & 0xFF)
        && bytes[9] == FormatVersion >> 8 && bytes[10] == Kind && bytes[27] == (BlobLength & 0xFF) && bytes[28] == BlobLength >> 8;
}

/// <summary>
/// <c>Hardware/zustand.json</c> (§23.3, nicht geheim), wie DestructionState.swift (sortierte Schlüssel, Swift-Zahlen):
/// <code>{"destroyed": null|{"at","keyID","trigger"}, "duressFileID", "failedAttempts", "lastGenuineUnlock",
///  ["rekeyPending": true,] "settings": {…}, "v": 1, "vKeyID", "vaultID"}</code>
/// </summary>
internal sealed record DestructionState(Guid VaultId)
{
    internal sealed record Destroyed(Guid KeyId, DestructionTrigger Trigger, DateTimeOffset At);

    internal const int StateVersion = 1;
    internal const string FileName = "zustand.json";
    internal const int MaxFileBytes = 16 << 10;

    /// <summary>Obergrenze des Zählers in der Datei (mehr gilt als beschädigt).</summary>
    internal const int MaxCounter = 1_000_000;

    internal DestructionSettings Settings { get; set; } = DestructionSettings.Off;
    internal Guid? VKeyId { get; set; }
    internal Guid? DuressFileId { get; set; }
    internal DateTimeOffset? LastGenuineUnlock { get; set; }
    internal int FailedAttempts { get; set; }
    internal Destroyed? DestroyedInfo { get; set; }

    /// <summary>Seit der letzten Vernichtungs-Sitzung noch keine DEK-Rotation (v4.4).</summary>
    internal bool RekeyPending { get; set; }

    /// <summary>Nichts mehr zu merken (dann wird die Datei entfernt).</summary>
    internal bool IsEmpty =>
        !Settings.AnyTriggerEnabled && VKeyId is null && DuressFileId is null && DestroyedInfo is null && !RekeyPending;

    /// <summary>Nennt der Zustand diese Kennung (als V, als vernichtet oder als Ablage)?</summary>
    internal bool Names(Guid id) => VKeyId == id || DestroyedInfo?.KeyId == id || DuressFileId == id;

    internal DateTimeOffset? Deadline =>
        Settings.DeadmanDays is { } days && LastGenuineUnlock is { } last ? Clock.AddDaysSaturating(last, days) : null;

    internal DestructionStatus Status =>
        new(Settings, LastGenuineUnlock, FailedAttempts, Deadline, DestroyedInfo?.Trigger, DestroyedInfo?.At,
            VKeyId is not null || DestroyedInfo is not null);

    internal DestructionState Copy() => this with { };

    // MARK: JSON

    internal static string TriggerCode(DestructionTrigger t) => t switch
    {
        DestructionTrigger.Deadman => "deadman",
        DestructionTrigger.FailedAttempts => "failedAttempts",
        _ => "duressPassword",
    };

    internal byte[] Encoded()
    {
        using var w = new SecureJsonWriter();
        w.BeginObject();
        w.Key("destroyed");
        if (DestroyedInfo is { } d)
        {
            w.BeginObject();
            w.Key("at");
            w.Date(d.At);
            w.Key("keyID");
            w.Uuid(d.KeyId);
            w.Key("trigger");
            w.String(TriggerCode(d.Trigger));
            w.EndObject();
        }
        else
        {
            w.Null();
        }
        w.Key("duressFileID");
        if (DuressFileId is { } f) { w.Uuid(f); } else { w.Null(); }
        w.Key("failedAttempts");
        w.Integer(FailedAttempts);
        w.Key("lastGenuineUnlock");
        if (LastGenuineUnlock is { } l) { w.Date(l); } else { w.Null(); }
        if (RekeyPending)
        {
            w.Key("rekeyPending");
            w.Bool(true);
        }
        w.Key("settings");
        w.BeginObject();
        w.Key("deadmanDays");
        if (Settings.DeadmanDays is { } dd) { w.Integer(dd); } else { w.Null(); }
        w.Key("duressEnabled");
        w.Bool(Settings.DuressEnabled);
        w.Key("maxFailedAttempts");
        if (Settings.MaxFailedAttempts is { } n) { w.Integer(n); } else { w.Null(); }
        w.EndObject();
        w.Key("v");
        w.Integer(StateVersion);
        w.Key("vKeyID");
        if (VKeyId is { } v) { w.Uuid(v); } else { w.Null(); }
        w.Key("vaultID");
        w.Uuid(VaultId);
        w.EndObject();
        using var json = w.Borrow(out var count);
        return json.Span[..count].ToArray();
    }

    /// <summary>Strenger Leser: unbekannte Version, Bereiche oder Werte → <c>CorruptFile("destruction.state")</c>.</summary>
    internal static DestructionState Decode(byte[] bytes)
    {
        try
        {
            var o = JRead.Obj(JNode.Parse(bytes));
            var v = JRead.Int(o.Required("v"));
            var vaultId = JRead.Uuid(o.Required("vaultID"));
            var so = JRead.Obj(o.Required("settings"));
            var settings = new DestructionSettings(
                so.Optional("deadmanDays") is { } dd ? Clamp(JRead.Int(dd)) : null,
                so.Optional("maxFailedAttempts") is { } mf ? Clamp(JRead.Int(mf)) : null,
                JRead.Bool(so.Required("duressEnabled")));
            var vKey = o.Optional("vKeyID") is { } vk ? JRead.Uuid(vk) : (Guid?)null;
            var duress = o.Optional("duressFileID") is { } df ? JRead.Uuid(df) : (Guid?)null;
            var last = o.Optional("lastGenuineUnlock") is { } lg ? JRead.Date(lg) : (DateTimeOffset?)null;
            var failed = JRead.Int(o.Required("failedAttempts"));
            Destroyed? destroyed = null;
            if (o.Optional("destroyed") is { } dn)
            {
                var d = JRead.Obj(dn);
                destroyed = new Destroyed(JRead.Uuid(d.Required("keyID")), ParseTrigger(JRead.Str(d.Required("trigger"))),
                    Clock.Canonical(JRead.Date(d.Required("at"))));
            }
            var rekey = o.Optional("rekeyPending") is { } rp && JRead.Bool(rp);
            if (v != StateVersion || failed is < 0 or > MaxCounter || settings.DuressEnabled != (duress is not null))
            {
                throw Fehler.Corrupt("destruction.state");
            }
            settings.Validate();
            return new DestructionState(vaultId)
            {
                Settings = settings,
                VKeyId = vKey,
                DuressFileId = duress,
                LastGenuineUnlock = last is { } x ? Clock.Canonical(x) : null,
                FailedAttempts = (int)failed,
                DestroyedInfo = destroyed,
                RekeyPending = rekey,
            };
        }
        catch (SiegelException)
        {
            throw Fehler.Corrupt("destruction.state");
        }
    }

    private static int Clamp(long v) => v is >= int.MinValue and <= int.MaxValue ? (int)v : int.MaxValue;

    private static DestructionTrigger ParseTrigger(string s) => s switch
    {
        "deadman" => DestructionTrigger.Deadman,
        "failedAttempts" => DestructionTrigger.FailedAttempts,
        "duressPassword" => DestructionTrigger.DuressPassword,
        _ => throw Fehler.Corrupt("destruction.state"),
    };

    // MARK: Datei

    internal static string PathIn(string hardware) => System.IO.Path.Combine(hardware, FileName);

    /// <summary>null = fehlt oder unlesbar (dann gilt „nichts eingerichtet“).</summary>
    internal static DestructionState? Read(string hardware)
    {
        try
        {
            return Decode(FileIO.Read(PathIn(hardware), MaxFileBytes));
        }
        catch (SiegelException)
        {
            return null;
        }
    }

    /// <summary>Atomar ersetzen. Jeder Schreibfehler → <c>Io("destruction.write")</c>.</summary>
    internal static void Write(DestructionState state, string hardware)
    {
        try
        {
            FileIO.EnsureDirectory(hardware);
        }
        catch (SiegelException)
        {
            throw Fehler.Io("destruction.write");
        }
        WriteAtomically(state.Encoded(), PathIn(hardware), hardware);
    }

    internal static void Remove(string hardware)
    {
        if (FileIO.RemoveChecked(PathIn(hardware))) { FileIO.TrySyncDirectory(hardware); }
    }

    /// <summary>Gemeinsamer Weg für zustand.json und die Ablage des Vernichtungs-Passworts (Temp + Durchschreiben +
    /// Ersetzen + Ordner). Fehler: <c>Io("destruction.write")</c>.</summary>
    internal static void WriteAtomically(byte[] bytes, string target, string directory)
    {
        string? tmp = null;
        for (var i = 0; i < 16 && tmp is null; i++)
        {
            var candidate = System.IO.Path.Combine(directory, "." + System.IO.Path.GetFileName(target) + "."
                + Bytes.Hex(Zufall.Bytes(4)) + ".tmp");
            try
            {
                FileIO.WriteExclusive(candidate, bytes);
                tmp = candidate;
            }
            catch (FileIO.ExistsException)
            {
                // nächster Name
            }
            catch (SiegelException)
            {
                throw Fehler.Io("destruction.write");
            }
        }
        if (tmp is null) { throw Fehler.Io("destruction.write"); }
        try
        {
            FileIO.Rename(tmp, target);
        }
        catch (SiegelException)
        {
            FileIO.RemoveTemp(tmp);
            throw Fehler.Io("destruction.write");
        }
        FileIO.TrySyncDirectory(directory);
        try
        {
            FileIO.ExcludeFromIndexing(target);
        }
        catch (SiegelException)
        {
            // bestes Bemühen
        }
    }
}
