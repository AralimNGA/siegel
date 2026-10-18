using System.Security.Cryptography;

namespace Siegel.Core;

/// <summary>
/// QR-Schlüsselkarte, reines Format ohne Kamera (SPEC §14.2, §22):
/// q = 32 Zufallsbytes; Inhalt = "SIEGELKARTE1:" + Crockford-Base32(q ‖ Prüfsumme 2 B), MSB-first, 55 Zeichen (3 Füllbits
/// = 0, wie beim Notfallcode); Prüfsumme = SHA3-256("Siegel v2 card checksum" ‖ q)[0..&lt;2];
/// cardTag = SHA3-256("Siegel v2 card tag" ‖ vaultID ‖ q)[0..&lt;4] (steht im Kopf bzw. im Inhalt).
/// </summary>
public static class CardCode
{
    internal const string Prefix = "SIEGELKARTE1:";
    internal const string PrefixFamily = "SIEGELKARTE";
    internal const int TagBytes = 4;
    internal static readonly byte[] ChecksumLabel = Bytes.Ascii("Siegel v2 card checksum");
    internal static readonly byte[] TagLabel = Bytes.Ascii("Siegel v2 card tag");

    /// <summary>Neues Kartengeheimnis q (32 Byte aus <c>randombytes_buf</c>).</summary>
    public static FactorSecret Generate() => new(SecureBuffer.Random(FactorSecret.Size));

    /// <summary>QR-Inhalt „SIEGELKARTE1:XXXX…“ (nur Zeichen des QR-Alphanumerik-Modus).</summary>
    public static string Payload(FactorSecret q)
    {
        Fehler.NotNull(q);
        var s = Symbols(q);
        try
        {
            return Prefix + RecoveryCodeCodec.FormatSymbols(s, RecoveryCodeCodec.SymbolCount);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(s);
        }
    }

    /// <summary>Derselbe Code in 11 Gruppen à 5 zum Abtippen (Notlösung bei defekter Kamera).</summary>
    public static string GroupedText(FactorSecret q)
    {
        Fehler.NotNull(q);
        var s = Symbols(q);
        try
        {
            return RecoveryCodeCodec.FormatSymbols(s, RecoveryCodeCodec.GroupSize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(s);
        }
    }

    /// <summary>Gescannter Inhalt (mit Präfix) oder abgetippte Gruppen (Gross/Klein egal, Leerraum und „-“ ignoriert,
    /// O→0, I/L→1). Falsche Länge/Zeichen, Füllbits ≠ 0, unbekannte Kartenversion oder falsche Prüfsumme →
    /// <c>InvalidRecoveryCodeFormat</c>.</summary>
    public static FactorSecret Decode(string scannedOrTyped)
    {
        Fehler.NotNull(scannedOrTyped);
        var rest = TrimWhiteSpaceAndNewlines(scannedOrTyped);
        if (rest.StartsWith(PrefixFamily, StringComparison.OrdinalIgnoreCase))
        {
            if (!rest.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)) { throw Fehler.InvalidCodeFormat(); }
            rest = rest[Prefix.Length..];
        }
        var syms = RecoveryCodeCodec.ParseSymbols(rest, allowUnknown: false);
        try
        {
            using var packed = SecureBuffer.Scratch(RecoveryCodeCodec.PackedBytes);
            using (var w = packed.BorrowWritable())
            {
                RecoveryCodeCodec.Pack(syms, w.Span);
                var (paddingOk, checksumOk) = RecoveryCodeCodec.PackedIsValid(w.Span, ChecksumLabel);
                if (!paddingOk || !checksumOk) { throw Fehler.InvalidCodeFormat(); }
            }
            return new FactorSecret(packed.Slice(0, FactorSecret.Size));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(syms);
        }
    }

    /// <summary>Karten-Kennung für diesen Tresor (4 Byte, nicht geheim).</summary>
    public static byte[] Tag(FactorSecret q, Guid vaultId)
    {
        Fehler.NotNull(q);
        return TagBytesFor(q, Bytes.OfGuid(vaultId));
    }

    internal static byte[] TagBytesFor(FactorSecret q, ReadOnlySpan<byte> vaultId)
    {
        var h = new Sha3Hasher().Update(TagLabel).Update(vaultId);
        using (var l = q.Storage.Borrow()) { h.Update(l.Span); }
        return h.Final().AsSpan(0, TagBytes).ToArray();
    }

    /// <summary>q ‖ Prüfsumme als 55 Base32-Symbole (geheim; der Aufrufer nullt).</summary>
    private static byte[] Symbols(FactorSecret q)
    {
        Span<byte> payload = stackalloc byte[RecoveryCodeCodec.PayloadBytes];
        try
        {
            using (var l = q.Storage.Borrow()) { l.Span.CopyTo(payload); }
            (payload[32], payload[33]) = RecoveryCodeCodec.Checksum(payload[..32], ChecksumLabel);
            return RecoveryCodeCodec.SymbolsFromBytes(payload);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    /// <summary>Wie Swift <c>trimmingCharacters(in: .whitespacesAndNewlines)</c> (Unicode White_Space).</summary>
    private static string TrimWhiteSpaceAndNewlines(string s)
    {
        var start = 0;
        var end = s.Length;
        while (start < end && RecoveryCodeCodec.IsWhiteSpace(s[start])) { start++; }
        while (end > start && RecoveryCodeCodec.IsWhiteSpace(s[end - 1])) { end--; }
        return s[start..end];
    }
}
