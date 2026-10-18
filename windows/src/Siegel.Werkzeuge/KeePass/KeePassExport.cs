using System.Buffers.Binary;
using System.Text;
using Siegel.Modell;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Werkzeuge;

/// <summary>Argon2id-Parameter des KeePass-Exports (SPEC §19: p = 1, m = 256 MiB, t = 3).</summary>
internal readonly record struct KdbxKdf(ulong OpsLimit, ulong MemLimitBytes)
{
    internal static readonly KdbxKdf Export = new(3, 256UL << 20);
}

/// <summary>
/// KeePass-Export KDBX 4.1 (SPEC §19), byte-kompatibel zu Sources/SiegelCore/Werkzeuge/KeePassExport.swift und lesbar
/// mit KeePassXC, KeePass 2 und referenz/siegel_referenz.py.
/// Äusserer Kopf (ChaCha20, keine Kompression, MasterSeed 32 B, IV 12 B, Argon2id S 16 B, P 1, M 256 MiB, I 3, V 0x13),
/// SHA-256 und HMAC-SHA-256 des Kopfs, HMAC-Blockstrom (≤ 1 MiB je Block, leerer Abschlussblock), darin mit ChaCha20
/// verschlüsselt der innere Kopf (Zufallsstrom ChaCha20, 64-B-Schlüssel) und das KeePass-XML (Gruppe „Siegel“).
/// Schlüssel: SHA-256(SHA-256(Passwort-UTF-8)) → Argon2id → SHA-256(Seed ‖ T) bzw. SHA-512(Seed ‖ T ‖ 0x01).
/// Password und otp geschützt; Werte mit in XML verbotenen Zeichen oder nur aus Leerraum ebenso; CR als <c>&amp;#13;</c>.
/// Nicht exportiert: gelöschte Einträge, Schutz 4/5, der Verlauf. Das Export-Passwort muss die Master-Passwort-Regel
/// erfüllen (<see cref="SiegelErrorCode.PasswordTooWeak"/>). Klartext entsteht nur in sodium_malloc-Speicher.
/// </summary>
public static class KeePassExport
{
    public static byte[] Kdbx(IEnumerable<(VaultEntry Entry, EntrySecrets Secrets)> items, string password) =>
        Kdbx(items, password, KdbxKdf.Export, DateTimeOffset.UtcNow);

    /// <summary>Mit wählbaren Argon2-Parametern (Tests) und Zeitpunkt.</summary>
    internal static byte[] Kdbx(IEnumerable<(VaultEntry Entry, EntrySecrets Secrets)> items, string password, KdbxKdf kdf,
        DateTimeOffset now)
    {
        return Build([.. items ?? []], password ?? "", kdf, now);
    }

    // Konstanten

    internal const uint Signature1 = 0x9AA2_D903;
    internal const uint Signature2 = 0xB54B_FB67;
    internal const uint Version = 0x0004_0001;                // 4.1
    internal static readonly byte[] CipherChaCha20 =
        [0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A];
    internal static readonly byte[] KdfArgon2id =
        [0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6];
    internal const uint InnerStreamChaCha20 = 3;
    internal const int BlockSize = 1 << 20;
    /// <summary>Sekunden von 0001-01-01T00:00:00Z bis 1970-01-01T00:00:00Z.</summary>
    internal const long SecondsTo1970 = 62_135_596_800;

    private const byte FieldEnd = 0, FieldCipherId = 2, FieldCompression = 3, FieldMasterSeed = 4, FieldIv = 7, FieldKdf = 11;
    private const byte InnerEnd = 0, InnerStreamId = 1, InnerStreamKey = 2;

    // Aufbau

    private static unsafe byte[] Build(List<(VaultEntry Entry, EntrySecrets Secrets)> items, string password, KdbxKdf kdf,
        DateTimeOffset now)
    {
        Sodium.EnsureReady();
        var policy = MasterPasswordPolicy.Check(password);
        if (!policy.Ok) { throw new SiegelException(SiegelErrorCode.PasswordTooWeak) { Bits = policy.Bits }; }

        var masterSeed = Sodium.RandomBytes(32);
        var encryptionIv = Sodium.RandomBytes(12);
        var kdfSalt = Sodium.RandomBytes((int)Sodium.crypto_pwhash_argon2id_saltbytes());
        using var innerKey = Geheimpuffer.Zufall(64);

        // Schlüssel
        using var composite = PasswordCompositeKey(password);
        using var transformed = Argon2id(composite, kdfSalt, kdf);
        using var t = transformed.Lesen();
        using var encryptionKey = SodiumHash.Sha256(masterSeed, t.Span);
        using var hmacBase = SodiumHash.Sha512(masterSeed, t.Span, [0x01]);

        // Äusserer Kopf
        var header = new List<byte>();
        header.AddRange(Le(Signature1));
        header.AddRange(Le(Signature2));
        header.AddRange(Le(Version));
        Field(header, FieldCipherId, CipherChaCha20);
        Field(header, FieldCompression, Le(0u));
        Field(header, FieldMasterSeed, masterSeed);
        Field(header, FieldIv, encryptionIv);
        Field(header, FieldKdf, KdfParameters(kdfSalt, kdf));
        Field(header, FieldEnd, [0x0D, 0x0A, 0x0D, 0x0A]);
        var headerBytes = header.ToArray();

        var output = new List<byte>(headerBytes.Length + 1024);
        output.AddRange(headerBytes);
        using (var headerHash = SodiumHash.Sha256(headerBytes))
        using (var h = headerHash.Lesen())
        {
            output.AddRange(h.Span.ToArray());
        }
        output.AddRange(Hmac(ulong.MaxValue, hmacBase, headerBytes));

        // Klartext (innerer Kopf + XML) in zwei Durchgängen (zählen, schreiben) direkt in sodium-Speicher, dann dort
        // verschlüsseln: nie eine Klartext-Kopie in gewachsenem und freigegebenem Speicher.
        var entries = items.Where(i => i.Entry.DeletedAt is null && i.Entry.Protection < EntryProtection.Maximal).ToList();
        var groupId = Sodium.RandomBytes(16);
        var counter = new ByteSink(null, 0);
        using (var countingStream = new InnerStream(innerKey, writing: false))
        {
            WritePayload(counter, innerKey, entries, groupId, now, countingStream);
        }
        var payloadLength = counter.Count;

        using var payload = Geheimpuffer.Rechenflaeche(payloadLength);
        // Eine Leihe über den ganzen Aufbau: ByteSink schreibt über den Zeiger, danach wird der Geheimtext gelesen.
        using var payloadLeihe = payload.Schreiben();
        var buffer = payloadLeihe.Zeiger;
        var sink = new ByteSink(buffer, payloadLength);
        using (var stream = new InnerStream(innerKey, writing: true))
        {
            WritePayload(sink, innerKey, entries, groupId, now, stream);
        }
        if (sink.Count != payloadLength) { throw new SiegelException(SiegelErrorCode.Crypto, "kdbx.length"); }
        // Äussere Verschlüsselung ChaCha20 (Zähler 0), an Ort und Stelle
        using (var ek = encryptionKey.Lesen())
        fixed (byte* n = encryptionIv)
        {
            if (Sodium.crypto_stream_chacha20_ietf_xor(buffer, buffer, (ulong)payloadLength, n, ek.Zeiger) != 0)
            {
                throw new SiegelException(SiegelErrorCode.Crypto, "kdbx.encrypt");
            }
        }

        // HMAC-Blockstrom über den Geheimtext
        ReadOnlySpan<byte> cipher = payloadLeihe.Span;
        ulong index = 0;
        var offset = 0;
        do
        {
            var length = Math.Min(BlockSize, cipher.Length - offset);
            var block = cipher.Slice(offset, length);
            var message = new byte[12 + length];
            BinaryPrimitives.WriteUInt64LittleEndian(message, index);
            BinaryPrimitives.WriteUInt32LittleEndian(message.AsSpan(8), (uint)length);
            block.CopyTo(message.AsSpan(12));
            output.AddRange(Hmac(index, hmacBase, message));
            output.AddRange(Le((uint)length));
            output.AddRange(block.ToArray());
            offset += length;
            index++;
        }
        while (offset < cipher.Length);
        // Abschluss: leerer Block
        var final = new byte[12];
        BinaryPrimitives.WriteUInt64LittleEndian(final, index);
        output.AddRange(Hmac(index, hmacBase, final));
        output.AddRange(Le(0u));
        return [.. output];
    }

    /// <summary>VariantDictionary (Version 0x0100) mit den Argon2id-Parametern.</summary>
    internal static byte[] KdfParameters(byte[] salt, KdbxKdf kdf)
    {
        var d = new List<byte> { 0x00, 0x01 };
        void Item(byte type, string key, byte[] value)
        {
            d.Add(type);
            d.AddRange(Le((uint)Encoding.UTF8.GetByteCount(key)));
            d.AddRange(Encoding.UTF8.GetBytes(key));
            d.AddRange(Le((uint)value.Length));
            d.AddRange(value);
        }
        Item(0x42, "$UUID", KdfArgon2id);
        Item(0x42, "S", salt);
        Item(0x04, "P", Le(1u));
        Item(0x05, "M", Le(kdf.MemLimitBytes));
        Item(0x05, "I", Le(kdf.OpsLimit));
        Item(0x04, "V", Le(0x13u));
        d.Add(0x00);
        return [.. d];
    }

    // Schlüssel

    /// <summary>SHA-256(SHA-256(UTF-8 des Passworts)), unverändert wie KeePass (ohne die Abbildung aus §1.1).</summary>
    private static Geheimpuffer PasswordCompositeKey(string password)
    {
        var bytes = Encoding.UTF8.GetBytes(password);
        try
        {
            using var first = SodiumHash.Sha256(bytes);
            using var f = first.Lesen();
            return SodiumHash.Sha256(f.Span);
        }
        finally
        {
            Sodium.Wipe(bytes);
        }
    }

    private static unsafe Geheimpuffer Argon2id(Geheimpuffer composite, byte[] salt, KdbxKdf kdf)
    {
        if (salt.Length != (int)Sodium.crypto_pwhash_argon2id_saltbytes()) { throw new SiegelException(SiegelErrorCode.Crypto, "kdbx.salt"); }
        using var leihe = composite.Lesen();
        var pw = leihe.Zeiger;
        var pwLength = composite.Length;
        return Geheimpuffer.Neu(32, ziel =>
        {
            fixed (byte* o = ziel)
            fixed (byte* s = salt)
            {
                var rc = Sodium.crypto_pwhash(o, 32, pw, (ulong)pwLength, s, kdf.OpsLimit, (nuint)kdf.MemLimitBytes,
                    Sodium.crypto_pwhash_alg_argon2id13());
                if (rc != 0) { throw new SiegelException(SiegelErrorCode.KdfFailed); }
            }
        });
    }

    /// <summary>HMAC-SHA-256 mit dem Block-Schlüssel SHA-512(Index ‖ HMAC-Basis).</summary>
    private static byte[] Hmac(ulong blockIndex, Geheimpuffer hmacBase, byte[] message)
    {
        using var hb = hmacBase.Lesen();
        using var blockKey = SodiumHash.Sha512(Le(blockIndex), hb.Span);
        using var bk = blockKey.Lesen();
        return SodiumHash.HmacSha256(bk.Span, message);
    }

    // Klartext (innerer Kopf + XML)

    private static void WritePayload(ByteSink sink, Geheimpuffer innerKey, List<(VaultEntry Entry, EntrySecrets Secrets)> entries,
        byte[] groupId, DateTimeOffset now, InnerStream stream)
    {
        // Innerer Kopf
        sink.Append(InnerStreamId);
        sink.Append(Le(4u));
        sink.Append(Le(InnerStreamChaCha20));
        sink.Append(InnerStreamKey);
        sink.Append(Le(64u));
        using (var ik = innerKey.Lesen()) { sink.Append(ik.Span); }
        sink.Append(InnerEnd);
        sink.Append(Le(0u));

        // XML
        var xml = new XmlWriter(sink, stream);
        var time = TimeText(now);
        var zeroUuid = Convert.ToBase64String(new byte[16]);
        xml.Raw("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\n<KeePassFile>\n<Meta>\n");
        xml.Element("Generator", "Siegel");
        xml.Element("DatabaseName", "Siegel");
        xml.Element("DatabaseNameChanged", time);
        xml.Element("DatabaseDescription", "Export aus Siegel");
        xml.Element("DatabaseDescriptionChanged", time);
        xml.Element("DefaultUserName", "");
        xml.Element("DefaultUserNameChanged", time);
        xml.Element("MaintenanceHistoryDays", "365");
        xml.Element("Color", "");
        xml.Element("MasterKeyChanged", time);
        xml.Element("MasterKeyChangeRec", "-1");
        xml.Element("MasterKeyChangeForce", "-1");
        xml.Raw("<MemoryProtection>\n");
        xml.Element("ProtectTitle", "False");
        xml.Element("ProtectUserName", "False");
        xml.Element("ProtectPassword", "True");
        xml.Element("ProtectURL", "False");
        xml.Element("ProtectNotes", "False");
        xml.Raw("</MemoryProtection>\n");
        xml.Element("RecycleBinEnabled", "False");
        xml.Element("RecycleBinUUID", zeroUuid);
        xml.Element("RecycleBinChanged", time);
        xml.Element("EntryTemplatesGroup", zeroUuid);
        xml.Element("EntryTemplatesGroupChanged", time);
        xml.Element("HistoryMaxItems", "10");
        xml.Element("HistoryMaxSize", "6291456");
        xml.Element("LastSelectedGroup", zeroUuid);
        xml.Element("LastTopVisibleGroup", zeroUuid);
        xml.Element("SettingsChanged", time);
        xml.Raw("<CustomData/>\n</Meta>\n<Root>\n<Group>\n");
        xml.Element("UUID", Convert.ToBase64String(groupId));
        xml.Element("Name", "Siegel");
        xml.Element("Notes", "");
        xml.Element("IconID", "48");
        xml.Times(time, time);
        xml.Element("IsExpanded", "True");
        xml.Element("DefaultAutoTypeSequence", "");
        xml.Element("EnableAutoType", "null");
        xml.Element("EnableSearching", "null");
        xml.Element("LastTopVisibleEntry", zeroUuid);
        foreach (var (entry, given) in entries)
        {
            var secrets = EffectiveSecrets(entry, given);
            xml.Raw("<Entry>\n");
            xml.Element("UUID", Convert.ToBase64String(UuidBytes(entry.Id)));
            xml.Element("IconID", "0");
            xml.Element("ForegroundColor", "");
            xml.Element("BackgroundColor", "");
            xml.Element("OverrideURL", "");
            xml.Element("Tags", "");
            xml.Times(TimeText(entry.Created), TimeText(entry.Modified));
            // Reihenfolge wie KeePass (ordinal sortiert); Password und otp geschützt
            xml.String("Notes", secrets.Notes, isProtected: false);
            xml.String("Password", secrets.Password, isProtected: true);
            xml.String("Title", entry.Title, isProtected: false);
            xml.String("URL", entry.Url, isProtected: false);
            xml.String("UserName", entry.Username, isProtected: false);
            var otp = OtpValue(secrets.Totp, entry.Title);
            if (otp.Length > 0) { xml.String("otp", otp, isProtected: true); }
            xml.Raw("<AutoType>\n");
            xml.Element("Enabled", "True");
            xml.Element("DataTransferObfuscation", "0");
            xml.Raw("</AutoType>\n<History/>\n</Entry>\n");
        }
        xml.Raw("</Group>\n<DeletedObjects/>\n</Root>\n</KeePassFile>\n");
    }

    /// <summary>Geheimteile eines Eintrags: aus <see cref="EntrySecrets"/>; bei nicht versiegelten Einträgen ergänzt ein
    /// leeres Feld aus dem Eintrag selbst (dort stehen die Werte dann im Klartext, beide Quellen sind gleich).</summary>
    internal static EntrySecrets EffectiveSecrets(VaultEntry entry, EntrySecrets given)
    {
        given ??= new EntrySecrets();
        if (entry.SecretsSealed) { return given; }
        return new EntrySecrets
        {
            Password = given.Password.Length == 0 ? entry.Password : given.Password,
            Notes = given.Notes.Length == 0 ? entry.Notes : given.Notes,
            Totp = given.Totp.Length == 0 ? entry.Totp : given.Totp,
            History = given.History,
        };
    }

    /// <summary><c>otp</c>-Feld: otpauth-URI unverändert (ohne Rand-Leerraum); reines Base32 →
    /// <c>otpauth://totp/&lt;Titel&gt;?secret=…</c> mit Standardwerten; was <see cref="Totp.Parse"/> nicht annimmt, bleibt roh.</summary>
    internal static string OtpValue(string stored, string title)
    {
        var trimmed = SwiftText.Trimmen(stored ?? "", SwiftText.IstLeerzeichenOderUmbruch);
        if (trimmed.Length == 0 || !Totp.IsValid(trimmed)) { return trimmed; }
        if (SwiftText.Klein(trimmed).StartsWith("otpauth://", StringComparison.Ordinal)) { return trimmed; }
        var secret = SwiftText.OhneSkalare(trimmed, s => s == '=' || SwiftUnicode.IstLeerraum(s));
        var label = ProzentKodieren(title.Length == 0 ? "Siegel" : title);
        return "otpauth://totp/" + label + "?secret=" + SwiftText.Gross(secret) + "&period=30&digits=6&algorithm=SHA1";
    }

    /// <summary>Foundation addingPercentEncoding mit den erlaubten Zeichen A–Z a–z 0–9 - . _ ~ @.</summary>
    private static string ProzentKodieren(string text)
    {
        var sb = new StringBuilder();
        foreach (var b in Encoding.UTF8.GetBytes(text))
        {
            if (b is (>= (byte)'A' and <= (byte)'Z') or (>= (byte)'a' and <= (byte)'z') or (>= (byte)'0' and <= (byte)'9')
                or (byte)'-' or (byte)'.' or (byte)'_' or (byte)'~' or (byte)'@')
            {
                sb.Append((char)b);
            }
            else
            {
                sb.Append('%').Append(b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
            }
        }
        return sb.ToString();
    }

    /// <summary>Base64 eines Int64 (Sekunden seit 0001-01-01, Little-Endian) wie KDBX 4.</summary>
    internal static string TimeText(DateTimeOffset date)
    {
        var seconds = Math.Max(-62_000_000_000L, Math.Min(date.ToUnixTimeSeconds(), 250_000_000_000L));
        return Convert.ToBase64String(Le((ulong)Math.Max(0, seconds + SecondsTo1970)));
    }

    /// <summary>UUID-Bytes in RFC-Reihenfolge (wie Swift <c>UUID.uuid</c>; .NET-Guid ist sonst teilweise Little-Endian).</summary>
    internal static byte[] UuidBytes(Guid id) => id.ToByteArray(bigEndian: true);

    // Hilfstypen

    /// <summary>Zählt Bytes (Zeiger null) oder schreibt sie in einen Puffer fester Grösse.</summary>
    private sealed unsafe class ByteSink(byte* buffer, int capacity)
    {
        internal int Count { get; private set; }

        internal void Append(byte b)
        {
            if (buffer is not null && Count < capacity) { buffer[Count] = b; }
            Count++;
        }

        internal void Append(ReadOnlySpan<byte> bytes)
        {
            foreach (var b in bytes) { Append(b); }
        }

        /// <summary>Feste ASCII-Texte (Markup), keine Geheimnisse.</summary>
        internal void Append(string text)
        {
            foreach (var c in text) { Append((byte)c); }
        }
    }

    /// <summary>Innerer Zufallsstrom (ChaCha20, RFC 7539): Schlüssel und Nonce aus SHA-512(InnerRandomStreamKey).</summary>
    private sealed unsafe class InnerStream : IDisposable
    {
        private readonly Geheimpuffer keyAndNonce;            // [0..<32] Schlüssel, [32..<44] Nonce
        private readonly Geheimpuffer block;                  // aktueller Schlüsselstrom-Block
        private int used = 64;
        private uint blockCounter;
        private readonly bool writing;

        internal InnerStream(Geheimpuffer key, bool writing)
        {
            using (var k = key.Lesen()) { keyAndNonce = SodiumHash.Sha512(k.Span); }
            block = Geheimpuffer.Rechenflaeche(64);
            this.writing = writing;
        }

        internal byte Next()
        {
            if (!writing) { return 0; }
            using var b = block.Schreiben();
            if (used == 64)
            {
                var o = b.Zeiger;
                Sodium.sodium_memzero(o, 64);
                using var kn = keyAndNonce.Lesen();
                var k = kn.Zeiger;
                _ = Sodium.crypto_stream_chacha20_ietf_xor_ic(o, o, 64, k + 32, blockCounter, k);
                blockCounter = unchecked(blockCounter + 1);
                used = 0;
            }
            return b.Span[used++];
        }

        public void Dispose()
        {
            keyAndNonce.Dispose();
            block.Dispose();
        }
    }

    /// <summary>Schreibt das KeePass-XML; geschützte Werte laufen durch den inneren Strom.</summary>
    private sealed class XmlWriter(ByteSink sink, InnerStream stream)
    {
        private static readonly byte[] Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"u8.ToArray();

        internal void Raw(string text) => sink.Append(text);

        internal void Element(string name, string value)
        {
            if (value.Length == 0)
            {
                sink.Append("<" + name + "/>\n");
            }
            else
            {
                sink.Append("<" + name + ">");
                Escaped(value);
                sink.Append("</" + name + ">\n");
            }
        }

        internal void Times(string created, string modified)
        {
            Raw("<Times>\n");
            Element("CreationTime", created);
            Element("LastModificationTime", modified);
            Element("LastAccessTime", modified);
            Element("ExpiryTime", created);
            Element("Expires", "False");
            Element("UsageCount", "0");
            Element("LocationChanged", modified);
            Raw("</Times>\n");
        }

        internal void String(string key, string value, bool isProtected)
        {
            sink.Append("<String><Key>" + key + "</Key>");
            if (isProtected || NeedsProtection(value))
            {
                sink.Append("<Value Protected=\"True\">");
                ProtectedBase64(value);
                sink.Append("</Value></String>\n");
            }
            else
            {
                sink.Append("<Value>");
                Escaped(value);
                sink.Append("</Value></String>\n");
            }
        }

        /// <summary>Zeichen, die XML 1.0 nicht erlaubt (auch nicht als Zeichenreferenz), oder nur Leerraum.</summary>
        internal static bool NeedsProtection(string value)
        {
            if (value.Length > 0 && value.All(c => c is ' ' or '\t' or '\n' or '\r')) { return true; }
            return SwiftText.EnthaeltSkalar(value, s => s is not (0x09 or 0x0A or 0x0D) && (s is <= 0x1F or 0xFFFE or 0xFFFF));
        }

        /// <summary>UTF-8 der Zeichenkette in einen Puffer, der danach genullt wird.</summary>
        private static void MitUtf8(string value, Action<byte[], int> body)
        {
            var bytes = new byte[Encoding.UTF8.GetMaxByteCount(value.Length)];
            try
            {
                var length = Encoding.UTF8.GetBytes(value, bytes);
                body(bytes, length);
            }
            finally
            {
                Sodium.Wipe(bytes);
            }
        }

        private void Escaped(string value) => MitUtf8(value, (bytes, length) =>
        {
            for (var i = 0; i < length; i++)
            {
                switch (bytes[i])
                {
                    case (byte)'&': sink.Append("&amp;"); break;
                    case (byte)'<': sink.Append("&lt;"); break;
                    case (byte)'>': sink.Append("&gt;"); break;
                    case 0x0D: sink.Append("&#13;"); break;
                    default: sink.Append(bytes[i]); break;
                }
            }
        });

        /// <summary>UTF-8 ⊕ Schlüsselstrom, Base64.</summary>
        private void ProtectedBase64(string value) => MitUtf8(value, (bytes, length) =>
        {
            uint group = 0;
            var filled = 0;
            for (var i = 0; i < length; i++)
            {
                group = (group << 8) | (uint)(bytes[i] ^ stream.Next());
                filled++;
                if (filled == 3)
                {
                    foreach (var shift in (ReadOnlySpan<int>)[18, 12, 6, 0]) { sink.Append(Alphabet[(int)((group >> shift) & 0x3F)]); }
                    group = 0;
                    filled = 0;
                }
            }
            if (filled == 1)
            {
                group <<= 16;
                sink.Append(Alphabet[(int)((group >> 18) & 0x3F)]);
                sink.Append(Alphabet[(int)((group >> 12) & 0x3F)]);
                sink.Append("==");
            }
            else if (filled == 2)
            {
                group <<= 8;
                sink.Append(Alphabet[(int)((group >> 18) & 0x3F)]);
                sink.Append(Alphabet[(int)((group >> 12) & 0x3F)]);
                sink.Append(Alphabet[(int)((group >> 6) & 0x3F)]);
                sink.Append("=");
            }
        });
    }

    // Little-Endian

    internal static byte[] Le(uint value)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(b, value);
        return b;
    }

    internal static byte[] Le(ulong value)
    {
        var b = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(b, value);
        return b;
    }

    /// <summary>KDBX-4-Kopffeld: id (1 B) ‖ Länge (4 B) ‖ Daten.</summary>
    private static void Field(List<byte> header, byte id, byte[] data)
    {
        header.Add(id);
        header.AddRange(Le((uint)data.Length));
        header.AddRange(data);
    }
}
