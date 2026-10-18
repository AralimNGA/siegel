using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Siegel.Werkzeuge.Tests;

internal enum KdbxFehler
{
    Kurz, Signatur, Version, Kopf, KopfHash, KopfHmac, Kdf, Block, Restbytes, Cipher, Kompression, InnererKopf,
    InnererStrom, Xml, Utf8,
}

#pragma warning disable CA1032, CA1064 // nur Tests: schlanke Ausnahme ohne Standard-Konstruktoren
internal sealed class KdbxLeserException(KdbxFehler fehler) : Exception(fehler.ToString())
#pragma warning restore CA1032, CA1064
{
    internal KdbxFehler Fehler { get; } = fehler;
}

/// <summary>
/// Unabhängiger KDBX-4-Leser nur für Tests (SPEC §19 „Prüfung“, Gegenstück zu KDBXLeser.swift): nach der
/// KDBX-4-Beschreibung geschrieben, nicht aus <see cref="KeePassExport"/> abgeleitet. .NET-Kryptografie für SHA-256,
/// SHA-512 und HMAC, libsodium nur für Argon2id und ChaCha20, XML über <see cref="XmlDocument"/>. Prüft Signaturen,
/// Version, Kopf-Hash, Kopf-HMAC (falsches Passwort), jeden Block-HMAC, Abschlussblock, keine Restbytes.
/// </summary>
internal static class KdbxLeser
{
    internal sealed record Eintrag(byte[] Uuid, Dictionary<string, string> Werte, HashSet<string> Geschuetzt,
        DateTimeOffset Erstellt, DateTimeOffset Geaendert);

    internal sealed record Datei(uint Version, Dictionary<byte, byte[]> KopfFelder, Dictionary<string, byte[]> Kdf,
        Dictionary<string, byte> KdfTypen, int Bloecke, uint InnererStromId, string Xml, string Gruppe, List<Eintrag> Eintraege);

    internal static readonly byte[] Argon2id = [0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6];
    internal static readonly byte[] ChaCha20 = [0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A];

    private sealed class Cursor(byte[] data)
    {
        internal byte[] Data { get; } = data;
        internal int Position { get; private set; }

        internal byte[] Bytes(int n)
        {
            if (n < 0 || Position + n > Data.Length) { throw new KdbxLeserException(KdbxFehler.Kurz); }
            var result = Data[Position..(Position + n)];
            Position += n;
            return result;
        }

        internal byte U8() => Bytes(1)[0];
        internal ushort U16() => BinaryPrimitives.ReadUInt16LittleEndian(Bytes(2));
        internal uint U32() => BinaryPrimitives.ReadUInt32LittleEndian(Bytes(4));
    }

    private static bool Gleich(byte[]? a, byte[] b) => a is not null && a.AsSpan().SequenceEqual(b);

    internal static unsafe Datei Lesen(byte[] data, string passwort)
    {
        Sodium.EnsureReady();
        var c = new Cursor(data);
        if (c.U32() != 0x9AA2_D903 || c.U32() != 0xB54B_FB67) { throw new KdbxLeserException(KdbxFehler.Signatur); }
        var version = c.U32();
        if (version >> 16 != 4 || (version & 0xFFFF) > 1) { throw new KdbxLeserException(KdbxFehler.Version); }

        // Äusserer Kopf
        var felder = new Dictionary<byte, byte[]>();
        while (true)
        {
            var id = c.U8();
            var laenge = (int)c.U32();
            var wert = c.Bytes(laenge);
            if (!felder.TryAdd(id, wert)) { throw new KdbxLeserException(KdbxFehler.Kopf); }
            if (id == 0) { break; }
        }
        var kopf = data[..c.Position];
        var kopfHash = c.Bytes(32);
        if (!SHA256.HashData(kopf).AsSpan().SequenceEqual(kopfHash)) { throw new KdbxLeserException(KdbxFehler.KopfHash); }
        var kopfHmac = c.Bytes(32);

        if (!Gleich(felder.GetValueOrDefault((byte)2), ChaCha20)) { throw new KdbxLeserException(KdbxFehler.Cipher); }
        if (!Gleich(felder.GetValueOrDefault((byte)3), [0, 0, 0, 0])) { throw new KdbxLeserException(KdbxFehler.Kompression); }
        if (felder.GetValueOrDefault((byte)4) is not { Length: 32 } seed || felder.GetValueOrDefault((byte)7) is not { Length: 12 } iv
            || felder.GetValueOrDefault((byte)11) is not { } kdfDaten)
        {
            throw new KdbxLeserException(KdbxFehler.Kopf);
        }

        // VariantDictionary
        var kdf = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var typen = new Dictionary<string, byte>(StringComparer.Ordinal);
        var v = new Cursor(kdfDaten);
        if (v.U16() >> 8 != 1) { throw new KdbxLeserException(KdbxFehler.Kdf); }
        while (true)
        {
            var typ = v.U8();
            if (typ == 0) { break; }
            var schluessel = Encoding.UTF8.GetString(v.Bytes((int)v.U32()));
            kdf[schluessel] = v.Bytes((int)v.U32());
            typen[schluessel] = typ;
        }
        if (v.Position != v.Data.Length) { throw new KdbxLeserException(KdbxFehler.Kdf); }
        if (!Gleich(kdf.GetValueOrDefault("$UUID"), Argon2id)) { throw new KdbxLeserException(KdbxFehler.Kdf); }
        if (kdf.GetValueOrDefault("S") is not { } salz || !Gleich(kdf.GetValueOrDefault("P"), [1, 0, 0, 0])
            || !Gleich(kdf.GetValueOrDefault("V"), [0x13, 0, 0, 0]) || kdf.GetValueOrDefault("M") is not { Length: 8 } m
            || kdf.GetValueOrDefault("I") is not { Length: 8 } i)
        {
            throw new KdbxLeserException(KdbxFehler.Kdf);
        }
        if (salz.Length != (int)Sodium.crypto_pwhash_argon2id_saltbytes()) { throw new KdbxLeserException(KdbxFehler.Kdf); }
        var speicher = BinaryPrimitives.ReadUInt64LittleEndian(m);
        var durchlaeufe = BinaryPrimitives.ReadUInt64LittleEndian(i);

        // Schlüssel
        var zusammengesetzt = SHA256.HashData(SHA256.HashData(Encoding.UTF8.GetBytes(passwort)));
        var transformiert = new byte[32];
        fixed (byte* o = transformiert)
        fixed (byte* p = zusammengesetzt)
        fixed (byte* s = salz)
        {
            if (Sodium.crypto_pwhash(o, 32, p, 32, s, durchlaeufe, (nuint)speicher, Sodium.crypto_pwhash_alg_argon2id13()) != 0)
            {
                throw new KdbxLeserException(KdbxFehler.Kdf);
            }
        }
        var hmacBasis = SHA512.HashData([.. seed, .. transformiert, 0x01]);
        var inhaltsSchluessel = SHA256.HashData([.. seed, .. transformiert]);

        byte[] BlockSchluessel(ulong index)
        {
            var le = new byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian(le, index);
            return SHA512.HashData([.. le, .. hmacBasis]);
        }
        if (!HMACSHA256.HashData(BlockSchluessel(ulong.MaxValue), kopf).AsSpan().SequenceEqual(kopfHmac))
        {
            throw new KdbxLeserException(KdbxFehler.KopfHmac);
        }

        // Blöcke
        var geheimtext = new List<byte>();
        ulong blockIndex = 0;
        while (true)
        {
            var mac = c.Bytes(32);
            var laenge = c.U32();
            if (laenge > int.MaxValue) { throw new KdbxLeserException(KdbxFehler.Block); }
            var daten = c.Bytes((int)laenge);
            var nachricht = new byte[12 + daten.Length];
            BinaryPrimitives.WriteUInt64LittleEndian(nachricht, blockIndex);
            BinaryPrimitives.WriteUInt32LittleEndian(nachricht.AsSpan(8), laenge);
            daten.CopyTo(nachricht, 12);
            if (!HMACSHA256.HashData(BlockSchluessel(blockIndex), nachricht).AsSpan().SequenceEqual(mac))
            {
                throw new KdbxLeserException(KdbxFehler.Block);
            }
            blockIndex++;
            if (laenge == 0) { break; }
            geheimtext.AddRange(daten);
        }
        if (c.Position != data.Length) { throw new KdbxLeserException(KdbxFehler.Restbytes); }

        // Entschlüsseln (ChaCha20, Zähler 0)
        var klartext = new byte[geheimtext.Count];
        var g = geheimtext.ToArray();
        if (g.Length > 0)
        {
            fixed (byte* o = klartext)
            fixed (byte* q = g)
            fixed (byte* n = iv)
            fixed (byte* k = inhaltsSchluessel)
            {
                _ = Sodium.crypto_stream_chacha20_ietf_xor(o, q, (ulong)g.Length, n, k);
            }
        }

        // Innerer Kopf
        var innenCursor = new Cursor(klartext);
        var innen = new Dictionary<byte, byte[]>();
        while (true)
        {
            var id = innenCursor.U8();
            var wert = innenCursor.Bytes((int)innenCursor.U32());
            if (id == 0) { break; }
            innen[id] = wert;
        }
        if (innen.GetValueOrDefault((byte)1) is not { Length: 4 } streamId || innen.GetValueOrDefault((byte)2) is not { Length: 64 } streamKey)
        {
            throw new KdbxLeserException(KdbxFehler.InnererKopf);
        }
        var stromId = BinaryPrimitives.ReadUInt32LittleEndian(streamId);
        if (stromId != 3) { throw new KdbxLeserException(KdbxFehler.InnererStrom); }
        var xmlBytes = klartext[innenCursor.Position..];
        string xmlText;
        try
        {
            xmlText = new UTF8Encoding(false, true).GetString(xmlBytes);
        }
        catch (DecoderFallbackException)
        {
            throw new KdbxLeserException(KdbxFehler.Utf8);
        }

        // XML und geschützte Werte (ein Schlüsselstrom in Dokumentreihenfolge)
        var dokument = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        try
        {
            using var reader = XmlReader.Create(new MemoryStream(xmlBytes), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit });
            dokument.Load(reader);
        }
        catch (XmlException)
        {
            throw new KdbxLeserException(KdbxFehler.Xml);
        }
        var geschuetzte = dokument.SelectNodes("//Value[@Protected='True']")?.Cast<XmlNode>().ToList() ?? [];
        var gesamt = 0;
        foreach (var knoten in geschuetzte) { gesamt += Base64(knoten.InnerText).Length; }
        var strom = SHA512.HashData(streamKey);
        var schluesselstrom = new byte[gesamt];
        if (gesamt > 0)
        {
            fixed (byte* o = schluesselstrom)
            fixed (byte* kn = strom)
            {
                _ = Sodium.crypto_stream_chacha20_ietf(o, (ulong)gesamt, kn + 32, kn);
            }
        }
        var verbraucht = 0;
        string Entschluesseln(string base64)
        {
            var roh = Base64(base64);
            if (verbraucht + roh.Length > gesamt) { throw new KdbxLeserException(KdbxFehler.Xml); }
            for (var k = 0; k < roh.Length; k++) { roh[k] ^= schluesselstrom[verbraucht + k]; }
            verbraucht += roh.Length;
            try
            {
                return new UTF8Encoding(false, true).GetString(roh);
            }
            catch (DecoderFallbackException)
            {
                throw new KdbxLeserException(KdbxFehler.Utf8);
            }
        }

        var gruppe = dokument.SelectSingleNode("/KeePassFile/Root/Group/Name")?.InnerText ?? "";
        var eintraege = new List<Eintrag>();
        foreach (XmlElement eintrag in dokument.SelectNodes("/KeePassFile/Root/Group/Entry")!)
        {
            var uuid = Base64(eintrag["UUID"]?.InnerText ?? "");
            var werte = new Dictionary<string, string>(StringComparer.Ordinal);
            var geschuetztSet = new HashSet<string>(StringComparer.Ordinal);
            foreach (XmlElement s in eintrag.GetElementsByTagName("String").Cast<XmlElement>().Where(x => x.ParentNode == eintrag))
            {
                var schluessel = s["Key"]?.InnerText ?? throw new KdbxLeserException(KdbxFehler.Xml);
                var wert = s["Value"] ?? throw new KdbxLeserException(KdbxFehler.Xml);
                if (wert.GetAttribute("Protected") == "True")
                {
                    werte[schluessel] = Entschluesseln(wert.InnerText);
                    geschuetztSet.Add(schluessel);
                }
                else
                {
                    werte[schluessel] = wert.InnerText;
                }
            }
            var zeiten = eintrag["Times"];
            eintraege.Add(new Eintrag(uuid, werte, geschuetztSet, Zeit(zeiten?["CreationTime"]?.InnerText),
                Zeit(zeiten?["LastModificationTime"]?.InnerText)));
        }
        if (verbraucht != gesamt) { throw new KdbxLeserException(KdbxFehler.Xml); }
        return new Datei(version, felder, kdf, typen, (int)blockIndex, stromId, xmlText, gruppe, eintraege);
    }

    private static byte[] Base64(string text)
    {
        try
        {
            return Convert.FromBase64String(text);
        }
        catch (FormatException)
        {
            throw new KdbxLeserException(KdbxFehler.Xml);
        }
    }

    internal static DateTimeOffset Zeit(string? text)
    {
        if (text is null) { return DateTimeOffset.MinValue; }
        var roh = Base64(text);
        if (roh.Length != 8) { return DateTimeOffset.MinValue; }
        var sekunden = BinaryPrimitives.ReadInt64LittleEndian(roh);
        return DateTimeOffset.FromUnixTimeSeconds(sekunden - 62_135_596_800);
    }
}
