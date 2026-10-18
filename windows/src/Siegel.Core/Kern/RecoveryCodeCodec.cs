using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;

namespace Siegel.Core;

/// <summary>
/// Notfallcode (SPEC §1.5): R[32] ‖ Prüfsumme[2], Crockford-Base32 MSB-first, 55 Zeichen (3 Füllbits = 0), 11 Gruppen
/// à 5, getrennt mit „-“. Kit-Kennung: 8 Zeichen „XXXX-XXXX“. Prüfsummen- und Kit-Label bleiben in allen
/// Formatversionen „Siegel v1 …“ (gehören zum gedruckten Kit, §13.2 seit v4.1).
/// </summary>
internal static class RecoveryCodeCodec
{
    internal const string AlphabetText = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    internal const int SymbolCount = 55;
    internal const int GroupCount = 11;
    internal const int GroupSize = 5;

    /// <summary>R ‖ Prüfsumme</summary>
    internal const int PayloadBytes = 34;

    /// <summary>275 Bit → 35 Byte (die letzten 5 Bit immer 0).</summary>
    internal const int PackedBytes = 35;

    internal const byte UnknownSymbol = 0xFF;
    internal const int MaxUnknown = 4;

    internal static readonly byte[] Alphabet = Bytes.Ascii(AlphabetText);
    internal static readonly byte[] ChecksumLabel = Bytes.Ascii("Siegel v1 recovery checksum");
    internal static readonly byte[] KitLabel = Bytes.Ascii("Siegel v1 kit id");

    /// <summary>ASCII → Symbolwert (Gross/Klein egal, O→0, I/L→1, U ungültig); −1 = ungültig.</summary>
    private static readonly sbyte[] DecodeTable = BuildDecodeTable();

    private static sbyte[] BuildDecodeTable()
    {
        var t = new sbyte[128];
        Array.Fill(t, (sbyte)-1);
        for (var i = 0; i < Alphabet.Length; i++)
        {
            var c = Alphabet[i];
            t[c] = (sbyte)i;
            if (c is >= (byte)'A' and <= (byte)'Z') { t[c + 32] = (sbyte)i; }
        }
        foreach (var (c, v) in new[] { ('O', 0), ('I', 1), ('L', 1) })
        {
            t[c] = (sbyte)v;
            t[c + 32] = (sbyte)v;
        }
        return t;
    }

    internal static int SymbolValue(int ascii) => ascii is >= 0 and < 128 ? DecodeTable[ascii] : -1;

    /// <summary>Unicode-Eigenschaft White_Space (stabil; dieselbe Menge wie Swift <c>properties.isWhitespace</c>).</summary>
    internal static bool IsWhiteSpace(int scalar) =>
        scalar is >= 0x09 and <= 0x0D or 0x20 or 0x85 or 0xA0 or 0x1680 or (>= 0x2000 and <= 0x200A) or 0x2028 or 0x2029
            or 0x202F or 0x205F or 0x3000;

    // MARK: Eingabe

    /// <summary>Eingabe → <paramref name="count"/> Symbole (Notfallcode 55, Teil 56). White_Space und „-“ werden
    /// ignoriert; „?“ nur mit <paramref name="allowUnknown"/> (höchstens 4). Sonst <c>InvalidRecoveryCodeFormat</c>.
    /// Das Ergebnis enthält Geheimnis-Symbole: der Aufrufer nullt es nach Gebrauch.</summary>
    internal static byte[] ParseSymbols(string input, bool allowUnknown, int count = SymbolCount)
    {
        Fehler.NotNull(input);
        var output = new byte[count];
        var n = 0;
        var unknown = 0;
        try
        {
            foreach (var rune in input.EnumerateRunes())
            {
                var v = rune.Value;
                if (IsWhiteSpace(v) || v == '-') { continue; }
                byte symbol;
                if (v == '?')
                {
                    unknown++;
                    if (!allowUnknown || unknown > MaxUnknown) { throw Fehler.InvalidCodeFormat(); }
                    symbol = UnknownSymbol;
                }
                else
                {
                    var s = SymbolValue(v);
                    if (s < 0) { throw Fehler.InvalidCodeFormat(); }
                    symbol = (byte)s;
                }
                if (n >= count) { throw Fehler.InvalidCodeFormat(); }
                output[n++] = symbol;
            }
            if (n != count) { throw Fehler.InvalidCodeFormat(); }
            return output;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(output);
            throw;
        }
    }

    // MARK: Bits

    /// <summary><paramref name="count"/> Symbole → Bytes, MSB-first (55 → 35 Byte, Füllbits = unterste 3 Bit von Byte 34).</summary>
    internal static void Pack(ReadOnlySpan<byte> symbols, Span<byte> output, int count = SymbolCount)
    {
        uint acc = 0;
        var bits = 0;
        var o = 0;
        for (var i = 0; i < count; i++)
        {
            acc = (acc << 5) | (uint)(symbols[i] & 31);
            bits += 5;
            if (bits >= 8)
            {
                bits -= 8;
                output[o++] = (byte)(acc >> bits);
                acc &= (1u << bits) - 1;
            }
        }
        if (bits > 0) { output[o] = (byte)(acc << (8 - bits)); }
    }

    /// <summary>Bytes → Base32-Symbole (MSB-first, letzte Bits mit 0 aufgefüllt).</summary>
    internal static byte[] SymbolsFromBytes(ReadOnlySpan<byte> bytes)
    {
        var output = new byte[(bytes.Length * 8 + 4) / 5];
        SymbolsFromBytes(bytes, output);
        return output;
    }

    /// <summary>Wie <see cref="SymbolsFromBytes(ReadOnlySpan{byte})"/>, aber nur die ersten <c>output.Length</c> Symbole
    /// direkt ins Ziel: kein ungekürztes Zwischenfeld, das ungenullt liegen bliebe (Befund hygiene-6).</summary>
    internal static void SymbolsFromBytes(ReadOnlySpan<byte> bytes, Span<byte> output)
    {
        if (output.Length > (bytes.Length * 8 + 4) / 5) { throw Fehler.Crypto("recovery.symbolCount"); }
        var n = 0;
        uint acc = 0;
        var bits = 0;
        foreach (var b in bytes)
        {
            acc = (acc << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                if (n == output.Length) { return; }
                output[n++] = (byte)((acc >> bits) & 31);
            }
            acc &= (1u << bits) - 1;
        }
        if (bits > 0 && n < output.Length) { output[n] = (byte)((acc << (5 - bits)) & 31); }
    }

    /// <summary>Prüfsumme über R (2 Byte); <paramref name="label"/> für andere Codes desselben Formats (QR-Karte).</summary>
    internal static (byte A, byte B) Checksum(ReadOnlySpan<byte> r, ReadOnlySpan<byte> label)
    {
        var d = new Sha3Digest(256);
        return Checksum(d, r, label);
    }

    /// <summary>Wie <see cref="Checksum(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/> mit wiederverwendetem Hasher
    /// (Fehlerkorrektur: viele Kandidaten pro Thread).</summary>
    internal static (byte A, byte B) Checksum(Sha3Digest d, ReadOnlySpan<byte> r, ReadOnlySpan<byte> label)
    {
        Span<byte> h = stackalloc byte[32];
        d.BlockUpdate(label);
        d.BlockUpdate(r);
        d.DoFinal(h);
        var result = (h[0], h[1]);
        CryptographicOperations.ZeroMemory(h);
        return result;
    }

    /// <summary>Gepackter Puffer (35 Byte): Füllbits 0 und Prüfsumme korrekt?</summary>
    internal static (bool PaddingOk, bool ChecksumOk) PackedIsValid(ReadOnlySpan<byte> packed, ReadOnlySpan<byte> label)
    {
        var paddingOk = packed[34] == 0;
        var (a, b) = Checksum(packed[..32], label);
        return (paddingOk, a == packed[32] && b == packed[33]);
    }

    internal static (bool PaddingOk, bool ChecksumOk) PackedIsValid(ReadOnlySpan<byte> packed) =>
        PackedIsValid(packed, ChecksumLabel);

    // MARK: Ausgabe

    /// <summary>Symbolfolge → „XXXXX-XXXXX-…“ (Gruppen à <paramref name="groupSize"/>).</summary>
    internal static string FormatSymbols(ReadOnlySpan<byte> symbols, int groupSize)
    {
        var sb = new StringBuilder(symbols.Length + symbols.Length / groupSize);
        for (var i = 0; i < symbols.Length; i++)
        {
            if (i > 0 && i % groupSize == 0) { sb.Append('-'); }
            sb.Append((char)Alphabet[symbols[i] & 31]);
        }
        return sb.ToString();
    }

    /// <summary>R → formatierter Notfallcode.</summary>
    internal static string Format(SecureBuffer r)
    {
        if (r.Length != RecoveryKem.RBytes) { throw Fehler.Crypto("recovery.rLength"); }
        Span<byte> payload = stackalloc byte[PayloadBytes];
        byte[]? symbols = null;
        try
        {
            using (var l = r.Borrow()) { l.Span.CopyTo(payload); }
            (payload[32], payload[33]) = Checksum(payload[..32], ChecksumLabel);
            symbols = SymbolsFromBytes(payload);
            return FormatSymbols(symbols, GroupSize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
            if (symbols is not null) { CryptographicOperations.ZeroMemory(symbols); }
        }
    }

    /// <summary>Kit-Kennung = Base32 von SHA3-256("Siegel v1 kit id" ‖ pkM ‖ pkX)[0..&lt;5] → „XXXX-XXXX“.</summary>
    internal static string KitId(byte[] pkM, byte[] pkX)
    {
        var digest = Sha3Hasher.Hash(KitLabel, pkM, pkX);
        return FormatSymbols(SymbolsFromBytes(digest.AsSpan(0, 5)), 4);
    }

    // MARK: Dekodieren (exakt)

    /// <summary>Exakter Code → R. Formatfehler/Füllbits → <c>InvalidRecoveryCodeFormat</c>, Prüfsumme →
    /// <c>RecoveryCodeChecksum</c>.</summary>
    internal static SecureBuffer Decode(string input)
    {
        var symbols = ParseSymbols(input, allowUnknown: false);
        try
        {
            using var packed = SecureBuffer.Scratch(PackedBytes);
            using (var w = packed.BorrowWritable())
            {
                Pack(symbols, w.Span);
                var (paddingOk, checksumOk) = PackedIsValid(w.Span);
                if (!paddingOk) { throw Fehler.InvalidCodeFormat(); }
                if (!checksumOk) { throw Fehler.CodeChecksum(); }
            }
            return packed.Slice(0, RecoveryKem.RBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(symbols);
        }
    }

    /// <summary>Normalisiert eine eingetippte Gruppe (Bestätigung) auf Alphabet-Zeichen; null bei ungültigen Zeichen.</summary>
    internal static string? NormalizedGroup(string input)
    {
        Fehler.NotNull(input);
        var sb = new StringBuilder(input.Length);
        foreach (var rune in input.EnumerateRunes())
        {
            var v = rune.Value;
            if (IsWhiteSpace(v) || v == '-') { continue; }
            var s = SymbolValue(v);
            if (s < 0) { return null; }
            sb.Append((char)Alphabet[s]);
        }
        return sb.ToString();
    }
}

/// <summary>
/// Sucht zu einem fehlerhaften Code den richtigen (SPEC §1.5): alle Belegungen der „?“; sonst 1 ersetztes Zeichen und
/// vertauschte Nachbarn, dann 2 ersetzte Zeichen. Kandidat = Füllbits 0, Prüfsumme stimmt und <c>isMatch</c>
/// (abgeleitete pkM/pkX = Kopf). Parallel über alle Kerne; pro Kandidat werden nur die 5 geänderten Bits im gepackten
/// Puffer (sichere Rechenfläche) neu gesetzt.
/// </summary>
internal static class RecoveryCodeCorrection
{
    /// <summary>Prüft ein Kandidaten-R (32 Byte, in einer sicheren Rechenfläche) gegen den Kopf.</summary>
    internal delegate bool Matcher(ReadOnlySpan<byte> r);

    internal sealed record Hit(byte[] Symbols, int[] Changed);

    /// <summary>Gemeinsamer Zustand der Suche (Treffer + Abbruch).</summary>
    private sealed class SearchState
    {
        private readonly Lock gate = new();
        private Hit? hit;

        internal bool Found
        {
            get { lock (gate) { return hit is not null; } }
        }

        internal Hit? Result
        {
            get { lock (gate) { return hit; } }
        }

        /// <summary>Behält den Treffer mit den wenigsten Änderungen; die Symbole des verworfenen werden genullt.</summary>
        internal void Offer(Hit h)
        {
            lock (gate)
            {
                if (hit is not null && hit.Changed.Length <= h.Changed.Length)
                {
                    CryptographicOperations.ZeroMemory(h.Symbols);
                    return;
                }
                if (hit is not null) { CryptographicOperations.ZeroMemory(hit.Symbols); }
                hit = h;
            }
        }
    }

    /// <summary>Setzt das 5-Bit-Symbol an Position <paramref name="pos"/> im gepackten Puffer (MSB-first; braucht ein
    /// Reservebyte hinter dem letzten).</summary>
    internal static void SetSymbol(Span<byte> p, int pos, byte value)
    {
        var bit = 5 * pos;
        var k = bit >> 3;
        var shift = 11 - (bit & 7);
        var mask = (ushort)(0x1F << shift);
        var w = (ushort)((p[k] << 8) | p[k + 1]);
        w = (ushort)((w & ~mask) | ((value & 31) << shift));
        p[k] = (byte)(w >> 8);
        p[k + 1] = (byte)w;
    }

    /// <summary>Füllbits 0, Prüfsumme, dann der teure pk-Vergleich.</summary>
    private static bool Check(Sha3Digest d, ReadOnlySpan<byte> p, Matcher isMatch)
    {
        if (p[34] != 0) { return false; }
        var (a, b) = RecoveryCodeCodec.Checksum(d, p[..32], RecoveryCodeCodec.ChecksumLabel);
        if (a != p[32] || b != p[33]) { return false; }
        return isMatch(p[..32]);
    }

    private static void FillPacked(Span<byte> p, byte[] input)
    {
        for (var i = 0; i < input.Length; i++)
        {
            SetSymbol(p, i, input[i] == RecoveryCodeCodec.UnknownSymbol ? (byte)0 : input[i]);
        }
    }

    /// <summary>Symbole eines Treffers aus dem gepackten Puffer: genau die 55 Symbole, ohne Zwischenfeld (das 56. wäre
    /// nur Füllung).</summary>
    internal static byte[] SymbolsOf(ReadOnlySpan<byte> p)
    {
        var symbols = new byte[RecoveryCodeCodec.SymbolCount];
        RecoveryCodeCodec.SymbolsFromBytes(p[..RecoveryCodeCodec.PackedBytes], symbols);
        return symbols;
    }

    internal static Hit? Search(byte[] input, Matcher isMatch)
    {
        const int n = RecoveryCodeCodec.SymbolCount;
        if (input.Length != n) { throw Fehler.Crypto("recovery.symbolCount"); }
        var unknownPositions = Enumerable.Range(0, n).Where(i => input[i] == RecoveryCodeCodec.UnknownSymbol).ToArray();
        var state = new SearchState();

        if (unknownPositions.Length > 0)
        {
            // Alle Belegungen der „?“ (≤ 32^4), in Blöcken parallel.
            var total = 1 << (5 * unknownPositions.Length);
            const int chunk = 4096;
            var chunks = (total + chunk - 1) / chunk;
            Parallel.For(0, chunks, c =>
            {
                if (state.Found) { return; }
                var d = new Sha3Digest(256);
                using var scratch = SecureBuffer.Scratch(RecoveryCodeCodec.PackedBytes + 1);
                using var w = scratch.BorrowWritable();
                var p = w.Span;
                FillPacked(p, input);
                for (var combo = c * chunk; combo < Math.Min(total, (c + 1) * chunk); combo++)
                {
                    var x = combo;
                    foreach (var pos in unknownPositions)
                    {
                        SetSymbol(p, pos, (byte)(x & 31));
                        x >>= 5;
                    }
                    if (Check(d, p, isMatch))
                    {
                        state.Offer(new Hit(SymbolsOf(p), unknownPositions));
                        return;
                    }
                }
            });
            return state.Result;
        }

        // 1 ersetztes Zeichen und vertauschte Nachbarn (billig, zuerst).
        Parallel.For(0, n, i =>
        {
            if (state.Found) { return; }
            var d = new Sha3Digest(256);
            using var scratch = SecureBuffer.Scratch(RecoveryCodeCodec.PackedBytes + 1);
            using var w = scratch.BorrowWritable();
            var p = w.Span;
            FillPacked(p, input);
            for (var v = 0; v < 32; v++)
            {
                if (v == input[i]) { continue; }
                SetSymbol(p, i, (byte)v);
                if (Check(d, p, isMatch))
                {
                    state.Offer(new Hit(SymbolsOf(p), [i]));
                    return;
                }
            }
            SetSymbol(p, i, input[i]);
            if (i + 1 < n && input[i] != input[i + 1])
            {
                SetSymbol(p, i, input[i + 1]);
                SetSymbol(p, i + 1, input[i]);
                if (Check(d, p, isMatch)) { state.Offer(new Hit(SymbolsOf(p), [i, i + 1])); }
            }
        });
        if (state.Result is { } single) { return single; }

        // 2 ersetzte Zeichen: alle Paare i < j, je 31 × 31 Werte.
        var pairs = new List<(int I, int J)>(n * (n - 1) / 2);
        for (var i = 0; i < n; i++)
        {
            for (var j = i + 1; j < n; j++) { pairs.Add((i, j)); }
        }
        Parallel.For(0, pairs.Count, idx =>
        {
            if (state.Found) { return; }
            var (i, j) = pairs[idx];
            var d = new Sha3Digest(256);
            using var scratch = SecureBuffer.Scratch(RecoveryCodeCodec.PackedBytes + 1);
            using var w = scratch.BorrowWritable();
            var p = w.Span;
            FillPacked(p, input);
            for (var vi = 0; vi < 32; vi++)
            {
                if (vi == input[i]) { continue; }
                SetSymbol(p, i, (byte)vi);
                for (var vj = 0; vj < 32; vj++)
                {
                    if (vj == input[j]) { continue; }
                    SetSymbol(p, j, (byte)vj);
                    if (Check(d, p, isMatch))
                    {
                        state.Offer(new Hit(SymbolsOf(p), [i, j]));
                        return;
                    }
                }
            }
        });
        return state.Result;
    }
}
