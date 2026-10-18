using System.Buffers.Binary;
using System.Globalization;

// Dateiformat `.siegel` (SPEC §2, §13.2), byte-genau wie Sources/SiegelCore/Kern/VaultFile.swift. Little-Endian, strenger
// Parser:
//   KOPF (v1: 1653 B; v2: 1709 B + Länge der FIDO-Credential-ID) ‖ SLOTS (1744) ‖
//   INHALT (generation u64 ‖ nonce 24 ‖ ctLen u32 ‖ ct‖tag) ‖ PRÜFSUMME (32)
// Die Prüfsumme (letzte 32 Byte = SHA3-256("Siegel v<n> file check" ‖ alles davor)) wird vor allem anderen geprüft. Das
// Label hängt an der Version in Byte 6–7: eine neuere Datei wird als UnsupportedVersion erkannt, ein gekipptes
// Versionsbyte als CorruptFile.
namespace Siegel.Core;

internal static class FileFormat
{
    internal static readonly byte[] Magic = Bytes.Ascii("SIEGEL");

    /// <summary>Geschrieben wird immer die neueste Version; gelesen werden 1 und 2.</summary>
    internal const ushort CurrentVersion = 2;

    internal const byte KdfAlgArgon2id13 = 1;
    internal const int ChecksumBytes = 32;
    internal const int MinCiphertext = 16_400;
    internal const int MaxCiphertext = 64 << 20;
    internal const int PayloadPrefixBytes = 8 + 24 + 4;
    internal const int MinFileBytes = VaultHeader.V1Size + VaultSlots.Size + PayloadPrefixBytes + MinCiphertext + ChecksumBytes;
    internal const int MaxFileBytes = VaultHeader.MaxSize + VaultSlots.Size + PayloadPrefixBytes + MaxCiphertext + ChecksumBytes;

    /// <summary>Labels einer Formatversion (§13.2). Die Labels des Notfallcodes bleiben „Siegel v1 …“.</summary>
    internal sealed class Labels
    {
        internal Labels(ushort version)
        {
            var v = "Siegel v" + version.ToString(CultureInfo.InvariantCulture) + " ";
            PwSlot = Bytes.Ascii(v + "slot pw");
            RecSlot = Bytes.Ascii(v + "slot rec");
            Payload = Bytes.Ascii(v + "payload");
            HybridKem = Bytes.Ascii(v + "hybrid KEM");
        }

        internal byte[] PwSlot { get; }
        internal byte[] RecSlot { get; }
        internal byte[] Payload { get; }
        internal byte[] HybridKem { get; }
    }

    internal static byte[] ChecksumLabel(ushort version) =>
        Bytes.Ascii("Siegel v" + version.ToString(CultureInfo.InvariantCulture) + " file check");

    /// <summary>Version laut Byte 6–7 (ungeprüft; nur für die Wahl des Prüfsummen-Labels).</summary>
    internal static ushort StatedVersion(ReadOnlySpan<byte> bytes) =>
        bytes.Length >= 8 ? BinaryPrimitives.ReadUInt16LittleEndian(bytes.Slice(6, 2)) : (ushort)0;

    internal static byte[] FileChecksum(ReadOnlySpan<byte> body, ushort version) =>
        new Sha3Hasher().Update(ChecksumLabel(version)).Update(body).Final();

    /// <summary>Prüfsumme mit dem Label der Version, die im Kopf steht.</summary>
    internal static byte[] FileChecksum(ReadOnlySpan<byte> body) => FileChecksum(body, StatedVersion(body));
}

/// <summary>Nicht geheime Faktor-Angaben im KOPF v2 (§13.2). Ein Feld ist genau dann gesetzt, wenn das Bit der Maske
/// gesetzt ist; ungesetzte Felder werden als Nullbytes geschrieben.</summary>
internal sealed record HeaderFactorFields(Guid? SeKeyId = null, byte[]? CardTag = null, byte[]? FidoCredentialId = null,
    byte[]? FidoSalt = null)
{
    internal static HeaderFactorFields None { get; } = new();

    internal FactorSet Mask =>
        (SeKeyId is null ? FactorSet.None : FactorSet.SecureEnclave)
        | (CardTag is null ? FactorSet.None : FactorSet.Card)
        | (FidoCredentialId is null ? FactorSet.None : FactorSet.SecurityKey);

    /// <summary>Längen und Konsistenz; Verstoss → <paramref name="fail"/> (lesen CorruptFile, schreiben Crypto).</summary>
    internal void Validate(Func<string, Exception> fail)
    {
        if (SeKeyId is { } id && Bytes.AllZero(Bytes.OfGuid(id))) { throw fail("header.seKeyID"); }
        if (CardTag is { } t && t.Length != VaultHeader.CardTagBytes) { throw fail("header.cardTag"); }
        switch (FidoCredentialId, FidoSalt)
        {
            case (null, null):
                break;
            case ({ } cred, { } salt):
                if (cred.Length is < VaultHeader.MinFidoCredential or > VaultHeader.MaxFidoCredential)
                {
                    throw fail("header.fidoCredential");
                }
                if (salt.Length != VaultHeader.FidoSaltBytes || Bytes.AllZero(salt)) { throw fail("header.fidoSalt"); }
                break;
            default:
                throw fail("header.fidoSalt");
        }
    }

    public bool Equals(HeaderFactorFields? other) =>
        other is not null && SeKeyId == other.SeKeyId && Same(CardTag, other.CardTag)
        && Same(FidoCredentialId, other.FidoCredentialId) && Same(FidoSalt, other.FidoSalt);

    public override int GetHashCode() => HashCode.Combine(SeKeyId, CardTag?.Length, FidoCredentialId?.Length);

    private static bool Same(byte[]? a, byte[]? b) => a is null ? b is null : b is not null && a.AsSpan().SequenceEqual(b);
}

/// <summary>KOPF (v1 oder v2). Die serialisierten Bytes sind Teil der AD.</summary>
internal sealed class VaultHeader : IEquatable<VaultHeader>
{
    internal const int V1Size = 1653;

    /// <summary>v2 ohne Credential-ID: 6+2+16+1+4+8+16+1+1+16+4+2+32+1568+32</summary>
    internal const int V2FixedSize = 1709;

    internal const int SeKeyIdBytes = 16;
    internal const int CardTagBytes = 4;
    internal const int FidoSaltBytes = 32;
    internal const int MinFidoCredential = 16;
    internal const int MaxFidoCredential = 1024;
    internal const int MaxSize = V2FixedSize + MaxFidoCredential;

    /// <summary>Bit 0 = Gerätefaktor, Bit 1 = Karte, Bit 2 = FIDO2.</summary>
    internal const byte KnownMaskBits = 0x07;

    private VaultHeader(ushort formatVersion, byte[] vaultId, KdfParameters kdf, byte[] salt, HeaderFactorFields fields,
        RecoveryScheme scheme, RecoveryPublicKeys pk, byte[] bytes)
    {
        FormatVersion = formatVersion;
        VaultId = vaultId;
        Kdf = kdf;
        Salt = salt;
        FactorFields = fields;
        RecoveryScheme = scheme;
        Pk = pk;
        Bytes = bytes;
    }

    internal ushort FormatVersion { get; }
    internal byte[] VaultId { get; }
    internal KdfParameters Kdf { get; }
    internal byte[] Salt { get; }

    /// <summary>v1: immer leer.</summary>
    internal HeaderFactorFields FactorFields { get; }

    /// <summary>v1: immer Single.</summary>
    internal RecoveryScheme RecoveryScheme { get; }

    internal RecoveryPublicKeys Pk { get; }

    /// <summary>Serialisierte Bytes (Teil der AD).</summary>
    internal byte[] Bytes { get; }

    internal Guid Uuid => Core.Bytes.ToGuid(VaultId);

    internal FactorSet Factors => FactorFields.Mask;

    internal FileFormat.Labels Labels => new(FormatVersion);

    private static void CheckFields(byte[] vaultId, byte[] salt, RecoveryPublicKeys pk)
    {
        if (vaultId.Length != 16 || salt.Length != Core.Kdf.SaltBytes) { throw Fehler.Crypto("header.fields"); }
        if (!pk.HasValidLengths) { throw Fehler.Crypto("header.pk"); }
    }

    /// <summary>Kopf v1 (nur noch zum Lesen alter Dateien und für Tests).</summary>
    internal static VaultHeader V1(byte[] vaultId, KdfParameters kdf, byte[] salt, RecoveryPublicKeys pk)
    {
        CheckFields(vaultId, salt, pk);
        var w = new ByteWriter(V1Size);
        w.Write(FileFormat.Magic);
        w.WriteU16(1);
        w.Write(vaultId);
        w.WriteByte(FileFormat.KdfAlgArgon2id13);
        w.WriteU32(kdf.OpsLimit);
        w.WriteU64(kdf.MemLimitBytes);
        w.Write(salt);
        w.Write(pk.PkM);
        w.Write(pk.PkX);
        return new VaultHeader(1, vaultId, kdf, salt, HeaderFactorFields.None, RecoveryScheme.SingleCode, pk, w.ToArray());
    }

    /// <summary>Kopf v2. Faktor-Felder werden geprüft (falsche Längen → <c>Crypto(...)</c>).</summary>
    internal static VaultHeader V2(byte[] vaultId, KdfParameters kdf, byte[] salt, HeaderFactorFields fields, RecoveryScheme scheme,
        RecoveryPublicKeys pk)
    {
        fields.Validate(Fehler.Crypto);
        CheckFields(vaultId, salt, pk);
        if (scheme is not (RecoveryScheme.SingleCode or RecoveryScheme.Shamir2Of3)) { throw Fehler.Crypto("header.recoveryScheme"); }
        var cred = fields.FidoCredentialId ?? [];
        var w = new ByteWriter(V2FixedSize + cred.Length);
        w.Write(FileFormat.Magic);
        w.WriteU16(2);
        w.Write(vaultId);
        w.WriteByte(FileFormat.KdfAlgArgon2id13);
        w.WriteU32(kdf.OpsLimit);
        w.WriteU64(kdf.MemLimitBytes);
        w.Write(salt);
        w.WriteByte((byte)fields.Mask);
        w.WriteByte((byte)scheme);
        if (fields.SeKeyId is { } se) { w.Write(Core.Bytes.OfGuid(se)); } else { w.WriteZeros(SeKeyIdBytes); }
        if (fields.CardTag is { } tag) { w.Write(tag); } else { w.WriteZeros(CardTagBytes); }
        w.WriteU16((ushort)cred.Length);
        w.Write(cred);
        if (fields.FidoSalt is { } fs) { w.Write(fs); } else { w.WriteZeros(FidoSaltBytes); }
        w.Write(pk.PkM);
        w.Write(pk.PkX);
        return new VaultHeader(2, vaultId, kdf, salt, fields, scheme, pk, w.ToArray());
    }

    /// <summary>Derselbe Kopf mit neuem Salz/KDF/Kit/Faktoren (immer v2).</summary>
    internal VaultHeader Rebuilt(byte[] salt, KdfParameters? kdf = null, HeaderFactorFields? factors = null,
        RecoveryScheme? recoveryScheme = null, RecoveryPublicKeys? pk = null) =>
        V2(VaultId, kdf ?? Kdf, salt, factors ?? FactorFields, recoveryScheme ?? RecoveryScheme, pk ?? Pk);

    /// <summary>Liest den KOPF ab <paramref name="reader"/> (Version 1 oder 2, streng). Rundlauf muss bytegenau sein.</summary>
    internal static VaultHeader Parse(ByteReader reader)
    {
        var start = reader.Offset;
        if (reader.Remaining < V1Size) { throw Fehler.Corrupt("header.length"); }
        var magic = reader.Take(6, "header.length");
        if (!magic.AsSpan().SequenceEqual(FileFormat.Magic)) { throw Fehler.Corrupt("header.magic"); }
        var version = reader.ReadU16("header.length");
        if (version == 0) { throw Fehler.Corrupt("header.version"); }
        if (version > FileFormat.CurrentVersion) { throw Fehler.UnsupportedVersion(version); }
        var vaultId = reader.Take(16, "header.length");
        var alg = reader.ReadU8("header.length");
        if (alg != FileFormat.KdfAlgArgon2id13) { throw Fehler.Corrupt("header.kdfAlg"); }
        var ops = reader.ReadU32("header.length");
        var mem = reader.ReadU64("header.length");
        var kdf = new KdfParameters(ops, mem);
        var salt = reader.Take(Core.Kdf.SaltBytes, "header.length");
        VaultHeader header;
        if (version == 1)
        {
            var pkM = reader.Take(RecoveryPublicKeys.PkMBytes, "header.length");
            var pkX = reader.Take(RecoveryPublicKeys.PkXBytes, "header.length");
            header = V1(vaultId, kdf, salt, new RecoveryPublicKeys(pkM, pkX));
        }
        else
        {
            var mask = reader.ReadU8("header.length");
            if ((mask & ~KnownMaskBits) != 0) { throw Fehler.Corrupt("header.factorMask"); }
            var schemeRaw = reader.ReadU8("header.length");
            if (schemeRaw is not ((byte)RecoveryScheme.SingleCode or (byte)RecoveryScheme.Shamir2Of3))
            {
                throw Fehler.Corrupt("header.recoveryScheme");
            }
            var scheme = (RecoveryScheme)schemeRaw;
            var factors = (FactorSet)mask;
            var seRaw = reader.Take(SeKeyIdBytes, "header.length");
            var tag = reader.Take(CardTagBytes, "header.length");
            var credLen = (int)reader.ReadU16("header.length");
            if (factors.Contains(FactorKind.SecurityKey))
            {
                if (credLen is < MinFidoCredential or > MaxFidoCredential) { throw Fehler.Corrupt("header.fidoCredential"); }
            }
            else if (credLen != 0)
            {
                throw Fehler.Corrupt("header.fidoCredential");
            }
            var cred = reader.Take(credLen, "header.length");
            var fidoSalt = reader.Take(FidoSaltBytes, "header.length");
            var pkM = reader.Take(RecoveryPublicKeys.PkMBytes, "header.length");
            var pkX = reader.Take(RecoveryPublicKeys.PkXBytes, "header.length");
            // Konsistenz Maske ↔ Nullfelder
            Guid? seKeyId = null;
            byte[]? cardTag = null;
            byte[]? fidoCred = null;
            byte[]? fidoSaltField = null;
            if (factors.Contains(FactorKind.SecureEnclave)) { seKeyId = Core.Bytes.ToGuid(seRaw); }
            else if (!Core.Bytes.AllZero(seRaw)) { throw Fehler.Corrupt("header.seKeyID"); }
            if (factors.Contains(FactorKind.Card)) { cardTag = tag; }
            else if (!Core.Bytes.AllZero(tag)) { throw Fehler.Corrupt("header.cardTag"); }
            if (factors.Contains(FactorKind.SecurityKey))
            {
                fidoCred = cred;
                fidoSaltField = fidoSalt;
            }
            else if (!Core.Bytes.AllZero(fidoSalt))
            {
                throw Fehler.Corrupt("header.fidoSalt");
            }
            var fields = new HeaderFactorFields(seKeyId, cardTag, fidoCred, fidoSaltField);
            fields.Validate(Fehler.Corrupt);
            try
            {
                header = V2(vaultId, kdf, salt, fields, scheme, new RecoveryPublicKeys(pkM, pkX));
            }
            catch (Siegel.Modell.SiegelException)
            {
                throw Fehler.Corrupt("header.encoding");
            }
        }
        if (!reader.Source.AsSpan(start, reader.Offset - start).SequenceEqual(header.Bytes))
        {
            throw Fehler.Corrupt("header.encoding");
        }
        return header;
    }

    /// <summary>Kopf-Auskunft ohne Geheimnis (§13.3).</summary>
    internal VaultHeaderInfo Info =>
        new(FormatVersion, Uuid, Factors, RecoveryScheme, FactorFields.SeKeyId, FactorFields.CardTag?.ToArray(),
            FactorFields.FidoCredentialId?.ToArray(), FactorFields.FidoSalt?.ToArray(), Kdf, Pk.KitId);

    public bool Equals(VaultHeader? other) => other is not null && Bytes.AsSpan().SequenceEqual(other.Bytes);

    public override bool Equals(object? obj) => Equals(obj as VaultHeader);

    public override int GetHashCode() => HashCode.Combine(FormatVersion, Bytes.Length, Uuid);
}

/// <summary>SLOTS (1744 Byte): pwSlot ‖ recSlot.ctM ‖ recSlot.ctX ‖ recSlot.</summary>
internal sealed class VaultSlots : IEquatable<VaultSlots>
{
    internal const int Size = 1744;

    internal VaultSlots(byte[] pwSlot, byte[] ctM, byte[] ctX, byte[] recSlot)
    {
        if (pwSlot.Length != Aead.WrappedBytes || recSlot.Length != Aead.WrappedBytes) { throw Fehler.Crypto("slots.wrap"); }
        if (ctM.Length != RecoveryKem.CtMBytes || ctX.Length != RecoveryKem.CtXBytes) { throw Fehler.Crypto("slots.ct"); }
        PwSlot = pwSlot;
        CtM = ctM;
        CtX = ctX;
        RecSlot = recSlot;
    }

    internal byte[] PwSlot { get; }
    internal byte[] CtM { get; }
    internal byte[] CtX { get; }
    internal byte[] RecSlot { get; }

    internal byte[] Bytes => Core.Bytes.Concat(PwSlot, CtM, CtX, RecSlot);

    internal static VaultSlots Parse(ByteReader reader)
    {
        if (reader.Remaining < Size) { throw Fehler.Corrupt("slots.length"); }
        return new VaultSlots(reader.Take(Aead.WrappedBytes, "slots.length"), reader.Take(RecoveryKem.CtMBytes, "slots.length"),
            reader.Take(RecoveryKem.CtXBytes, "slots.length"), reader.Take(Aead.WrappedBytes, "slots.length"));
    }

    /// <summary>AD = Label ‖ KOPF (Label je nach Formatversion).</summary>
    internal static byte[] PwAd(VaultHeader header) => Core.Bytes.Concat(header.Labels.PwSlot, header.Bytes);

    internal static byte[] RecAd(VaultHeader header) => Core.Bytes.Concat(header.Labels.RecSlot, header.Bytes);

    public bool Equals(VaultSlots? other) => other is not null && Bytes.AsSpan().SequenceEqual(other.Bytes);

    public override bool Equals(object? obj) => Equals(obj as VaultSlots);

    public override int GetHashCode() => HashCode.Combine(PwSlot[0], RecSlot[0]);
}

/// <summary>Ganze Datei (ohne Prüfsumme im Speicher; sie wird beim Serialisieren angehängt).</summary>
internal sealed class VaultFile(VaultHeader header, VaultSlots slots, ulong generation, byte[] nonce, byte[] ciphertext)
{
    internal VaultHeader Header { get; } = header;
    internal VaultSlots Slots { get; } = slots;
    internal ulong Generation { get; } = generation;
    internal byte[] Nonce { get; } = nonce;
    internal byte[] Ciphertext { get; } = ciphertext;

    /// <summary>AD des Inhalts: "Siegel v&lt;n&gt; payload" ‖ KOPF ‖ SLOTS ‖ generation</summary>
    internal static byte[] PayloadAdFor(VaultHeader header, VaultSlots slots, ulong generation)
    {
        var w = new ByteWriter(header.Bytes.Length + VaultSlots.Size + 64);
        w.Write(header.Labels.Payload);
        w.Write(header.Bytes);
        w.Write(slots.Bytes);
        w.WriteU64(generation);
        return w.ToArray();
    }

    internal byte[] PayloadAd => PayloadAdFor(Header, Slots, Generation);

    /// <summary>Serialisiert inkl. Prüfsumme (Label der Kopf-Version).</summary>
    internal byte[] Serialize()
    {
        var w = new ByteWriter(Header.Bytes.Length + VaultSlots.Size + FileFormat.PayloadPrefixBytes + Ciphertext.Length
            + FileFormat.ChecksumBytes);
        w.Write(Header.Bytes);
        w.Write(Slots.Bytes);
        w.WriteU64(Generation);
        w.Write(Nonce);
        w.WriteU32((uint)Ciphertext.Length);
        w.Write(Ciphertext);
        w.Write(FileFormat.FileChecksum(w.Written, Header.FormatVersion));
        return w.ToArray();
    }

    /// <summary>Prüfsumme (vor allem anderen), dann Kopf, Slots, Inhalt. Restbytes → Fehler.</summary>
    internal static VaultFile Parse(byte[] bytes)
    {
        VerifyChecksum(bytes);
        var bodyEnd = bytes.Length - FileFormat.ChecksumBytes;
        var r = new ByteReader(bytes, 0, bodyEnd);
        var header = VaultHeader.Parse(r);
        var slots = VaultSlots.Parse(r);
        var generation = r.ReadU64("payload.length");
        var nonce = r.Take(Aead.NonceBytes, "payload.length");
        var ctLen = (long)r.ReadU32("payload.length");
        if (ctLen < FileFormat.MinCiphertext || ctLen > FileFormat.MaxCiphertext
            || (ctLen - Aead.TagBytes) % PayloadCodec.BlockSize != 0)
        {
            throw Fehler.Corrupt("payload.length");
        }
        if (r.Remaining != ctLen) { throw Fehler.Corrupt("file.length"); }
        var ct = r.Take((int)ctLen, "payload.length");
        return new VaultFile(header, slots, generation, nonce, ct);
    }

    /// <summary>Nur Länge und Prüfsumme (Bitfäule-Erkennung). Label nach der Version in Byte 6–7.</summary>
    internal static void VerifyChecksum(byte[] bytes)
    {
        if (bytes.Length < FileFormat.ChecksumBytes + VaultHeader.V1Size) { throw Fehler.Corrupt("file.length"); }
        if (bytes.Length > FileFormat.MaxFileBytes) { throw Fehler.Corrupt("file.length"); }
        var bodyEnd = bytes.Length - FileFormat.ChecksumBytes;
        var expected = FileFormat.FileChecksum(bytes.AsSpan(0, bodyEnd));
        if (!bytes.AsSpan(bodyEnd).SequenceEqual(expected)) { throw Fehler.Corrupt("file.checksum"); }
    }

    /// <summary>Nur den Kopf lesen (Anfang der Datei, ohne Prüfsumme).</summary>
    internal static VaultHeader ParseHeaderOnly(byte[] bytes) => VaultHeader.Parse(new ByteReader(bytes));

    /// <summary>Kopf-Auskunft aus ganzen Dateibytes: Prüfsumme, dann Kopf (kein Argon2), wie Swift <c>inspect</c>.</summary>
    internal static VaultHeaderInfo Inspect(byte[] bytes)
    {
        VerifyChecksum(bytes);
        return ParseHeaderOnly(bytes[..^FileFormat.ChecksumBytes]).Info;
    }
}
