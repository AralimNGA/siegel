using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;

namespace Siegel.Core;

/// <summary>GF(2^8) mit Reduktionspolynom x^8 + x^4 + x^3 + x + 1 (0x11B), ohne Tabellen und ohne datenabhängige
/// Verzweigungen (SPEC §15).</summary>
internal static class Gf256
{
    internal static byte Mul(byte a, byte b)
    {
        var x = (uint)a;
        var y = (uint)b;
        uint r = 0;
        for (var i = 0; i < 8; i++)
        {
            r ^= x & (0u - (y & 1));
            var hi = x >> 7;
            x = ((x << 1) ^ (0x1Bu & (0u - hi))) & 0xFF;
            y >>= 1;
        }
        return (byte)r;
    }

    /// <summary>a^254 = a^-1 (für a = 0 ergibt sich 0). Feste Multiplikationsfolge.</summary>
    internal static byte Inv(byte a)
    {
        byte result = 1;
        var b = a;
        var e = 254u;
        for (var i = 0; i < 8; i++)
        {
            var m = Mul(result, b);
            var take = (byte)(0u - (e & 1));
            result = (byte)((m & take) | (result & ~take));
            b = Mul(b, b);
            e >>= 1;
        }
        return result;
    }
}

/// <summary>
/// Notfallcode geteilt, 2 aus 3 (SPEC §15): <c>share_x[i] = R[i] ⊕ a[i]·x</c> über GF(2^8), x ∈ {1, 2, 3}, a zufällig.
/// Ein Teil: x (1 B) ‖ share (32 B) ‖ Prüfsumme (2 B) = 35 Byte = 280 Bit → 56 Crockford-Base32-Zeichen (ohne Füllbits),
/// Gruppen à 5 (die letzte Gruppe hat 1 Zeichen). Prüfsumme = SHA3-256("Siegel v2 share checksum" ‖ x ‖ share)[0..&lt;2].
/// </summary>
internal static class Shamir
{
    internal const int ShareCount = 3;
    internal const int ShareBytes = 35;
    internal const int SymbolCount = 56;
    internal const int GroupSize = 5;

    /// <summary>Ganze Gruppen à 5 (0…10); zur Bestätigung wird nur eine davon verlangt.</summary>
    internal const int FullGroups = 11;

    internal static readonly byte[] ChecksumLabel = Bytes.Ascii("Siegel v2 share checksum");

    /// <summary>R → drei Teile (y-Werte; x = Index + 1).</summary>
    internal static SecureBuffer[] Split(SecureBuffer r)
    {
        using var a = SecureBuffer.Random(RecoveryKem.RBytes);
        return Split(r, a);
    }

    /// <summary>Mit festem a (Testvektoren).</summary>
    internal static SecureBuffer[] Split(SecureBuffer r, SecureBuffer coefficients)
    {
        if (r.Length != RecoveryKem.RBytes || coefficients.Length != RecoveryKem.RBytes) { throw Fehler.Crypto("shamir.rLength"); }
        var shares = new SecureBuffer[ShareCount];
        var made = 0;
        try
        {
            for (byte x = 1; x <= ShareCount; x++)
            {
                var y = SecureBuffer.Scratch(RecoveryKem.RBytes);
                shares[made++] = y;
                using (var o = y.BorrowWritable())
                using (var rb = r.Borrow())
                using (var ab = coefficients.Borrow())
                {
                    for (var i = 0; i < RecoveryKem.RBytes; i++) { o.Span[i] = (byte)(rb.Span[i] ^ Gf256.Mul(ab.Span[i], x)); }
                }
                y.Freeze();
            }
            return shares;
        }
        catch
        {
            for (var i = 0; i < made; i++) { shares[i].Dispose(); }
            throw;
        }
    }

    /// <summary>Lagrange in 0 aus zwei Teilen mit verschiedenen x: R = y1·x2/(x1⊕x2) ⊕ y2·x1/(x1⊕x2).</summary>
    internal static SecureBuffer Combine(byte x1, SecureBuffer y1, byte x2, SecureBuffer y2)
    {
        if (x1 is < 1 or > 3 || x2 is < 1 or > 3 || x1 == x2 || y1.Length != RecoveryKem.RBytes || y2.Length != RecoveryKem.RBytes)
        {
            throw Fehler.InvalidCodeFormat();
        }
        var dInv = Gf256.Inv((byte)(x1 ^ x2));
        var l1 = Gf256.Mul(x2, dInv);
        var l2 = Gf256.Mul(x1, dInv);
        var output = SecureBuffer.Scratch(RecoveryKem.RBytes);
        try
        {
            using (var o = output.BorrowWritable())
            using (var a = y1.Borrow())
            using (var b = y2.Borrow())
            {
                for (var i = 0; i < RecoveryKem.RBytes; i++) { o.Span[i] = (byte)(Gf256.Mul(a.Span[i], l1) ^ Gf256.Mul(b.Span[i], l2)); }
            }
            output.Freeze();
            return output;
        }
        catch
        {
            output.Dispose();
            throw;
        }
    }

    // MARK: Format

    internal static (byte A, byte B) Checksum(Sha3Digest d, byte x, ReadOnlySpan<byte> y)
    {
        Span<byte> h = stackalloc byte[32];
        d.BlockUpdate(ChecksumLabel);
        d.Update(x);
        d.BlockUpdate(y);
        d.DoFinal(h);
        var result = (h[0], h[1]);
        CryptographicOperations.ZeroMemory(h);
        return result;
    }

    /// <summary>Teil x mit y-Wert → „XXXXX-…-X“ (56 Zeichen in 12 Gruppen).</summary>
    internal static string Format(byte x, SecureBuffer y)
    {
        Span<byte> packed = stackalloc byte[ShareBytes];
        byte[]? symbols = null;
        try
        {
            packed[0] = x;
            using (var l = y.Borrow()) { l.Span.CopyTo(packed[1..33]); }
            (packed[33], packed[34]) = Checksum(new Sha3Digest(256), x, packed[1..33]);
            symbols = RecoveryCodeCodec.SymbolsFromBytes(packed);
            return RecoveryCodeCodec.FormatSymbols(symbols, GroupSize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(packed);
            if (symbols is not null) { CryptographicOperations.ZeroMemory(symbols); }
        }
    }

    /// <summary>Gepackter Teil (35 Byte) gültig? x ∈ {1, 2, 3} und Prüfsumme stimmt.</summary>
    internal static bool IsValid(Sha3Digest d, ReadOnlySpan<byte> p)
    {
        if (p.Length < ShareBytes || p[0] is < 1 or > 3) { return false; }
        var (a, b) = Checksum(d, p[0], p[1..33]);
        return a == p[33] && b == p[34];
    }

    /// <summary>Exakte Eingabe (ohne „?“) → (x, y). Formatfehler → <c>InvalidRecoveryCodeFormat</c>, Prüfsumme oder
    /// x ∉ 1…3 → <c>RecoveryCodeChecksum</c>.</summary>
    internal static (byte X, SecureBuffer Y) Decode(string input)
    {
        var symbols = RecoveryCodeCodec.ParseSymbols(input, allowUnknown: false, count: SymbolCount);
        try
        {
            using var packed = SecureBuffer.Scratch(ShareBytes);
            byte x;
            using (var w = packed.BorrowWritable())
            {
                RecoveryCodeCodec.Pack(symbols, w.Span, SymbolCount);
                // Ein ungültiges x ist (wie eine falsche Prüfsumme) meist ein Tippfehler in den ersten beiden Zeichen.
                if (!IsValid(new Sha3Digest(256), w.Span)) { throw Fehler.CodeChecksum(); }
                x = w.Span[0];
            }
            return (x, packed.Slice(1, 32));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(symbols);
        }
    }

    /// <summary>Index des Teils (1…3), wenn die Eingabe exakt gültig ist; sonst null.</summary>
    internal static int? IndexOf(string input)
    {
        try
        {
            var (x, y) = Decode(input);
            y.Dispose();
            return x;
        }
        catch (Siegel.Modell.SiegelException)
        {
            return null;
        }
    }

    // MARK: Fehlerkorrektur pro Teil

    /// <summary>Ein Kandidat für einen Teil: gepackte 35 Byte (sichere Fläche) und geänderte Positionen (0…55).</summary>
    internal sealed class Candidate(SecureBuffer packed, int[] changed) : IDisposable
    {
        internal SecureBuffer Packed { get; } = packed;
        internal int[] Changed { get; } = changed;

        internal byte X
        {
            get
            {
                using var l = Packed.Borrow();
                return l.Span[0];
            }
        }

        internal SecureBuffer Y() => Packed.Slice(1, 32);

        internal byte[] Symbols()
        {
            // Direkt ins Ergebnis: keine Vollkopie, die ungenullt liegen bliebe (Befund hygiene-6).
            var symbols = new byte[SymbolCount];
            using var l = Packed.Borrow();
            RecoveryCodeCodec.SymbolsFromBytes(l.Span, symbols);
            return symbols;
        }

        public void Dispose() => Packed.Dispose();
    }

    private sealed class Collector(int limit)
    {
        private readonly Lock gate = new();
        private readonly List<Candidate> items = [];

        internal void Add(ReadOnlySpan<byte> p, int[] changed)
        {
            var copy = SecureBuffer.Copy(p[..ShareBytes]);
            lock (gate)
            {
                if (items.Count < limit)
                {
                    items.Add(new Candidate(copy, changed));
                    return;
                }
            }
            copy.Dispose();
        }

        internal List<Candidate> All
        {
            get { lock (gate) { return [.. items]; } }
        }
    }

    private static void FillPacked(Span<byte> p, byte[] input)
    {
        for (var i = 0; i < input.Length; i++)
        {
            RecoveryCodeCorrection.SetSymbol(p, i, input[i] == RecoveryCodeCodec.UnknownSymbol ? (byte)0 : input[i]);
        }
    }

    /// <summary>Kandidaten einer Stufe (Prüfsumme und x gültig, noch ohne pk-Vergleich):
    /// Stufe 0: die Eingabe selbst bzw. alle Belegungen der „?“ (nur bei „?“ gibt es keine weiteren Stufen),
    /// Stufe 1: ein ersetztes Zeichen oder vertauschte Nachbarn, Stufe 2: zwei ersetzte Zeichen.
    /// Reihenfolge deterministisch: wenige Änderungen zuerst, dann nach Position.</summary>
    internal static List<Candidate> Candidates(byte[] input, int tier, int limit = 4096)
    {
        const int n = SymbolCount;
        if (input.Length != n) { throw Fehler.Crypto("shamir.symbolCount"); }
        var unknown = Enumerable.Range(0, n).Where(i => input[i] == RecoveryCodeCodec.UnknownSymbol).ToArray();
        var output = new Collector(limit);
        if (tier == 0 && unknown.Length > 0)
        {
            var total = 1 << (5 * unknown.Length);
            const int chunk = 4096;
            Parallel.For(0, (total + chunk - 1) / chunk, c =>
            {
                var d = new Sha3Digest(256);
                using var scratch = SecureBuffer.Scratch(ShareBytes + 1);
                using var w = scratch.BorrowWritable();
                var p = w.Span;
                FillPacked(p, input);
                for (var combo = c * chunk; combo < Math.Min(total, (c + 1) * chunk); combo++)
                {
                    var v = combo;
                    foreach (var pos in unknown)
                    {
                        RecoveryCodeCorrection.SetSymbol(p, pos, (byte)(v & 31));
                        v >>= 5;
                    }
                    if (IsValid(d, p)) { output.Add(p, unknown); }
                }
            });
        }
        else if (tier == 0)
        {
            using var scratch = SecureBuffer.Scratch(ShareBytes + 1);
            using var w = scratch.BorrowWritable();
            FillPacked(w.Span, input);
            if (IsValid(new Sha3Digest(256), w.Span)) { output.Add(w.Span, []); }
        }
        else if (tier == 1 && unknown.Length == 0)
        {
            Parallel.For(0, n, i =>
            {
                var d = new Sha3Digest(256);
                using var scratch = SecureBuffer.Scratch(ShareBytes + 1);
                using var w = scratch.BorrowWritable();
                var p = w.Span;
                FillPacked(p, input);
                for (var v = 0; v < 32; v++)
                {
                    if (v == input[i]) { continue; }
                    RecoveryCodeCorrection.SetSymbol(p, i, (byte)v);
                    if (IsValid(d, p)) { output.Add(p, [i]); }
                }
                RecoveryCodeCorrection.SetSymbol(p, i, input[i]);
                if (i + 1 < n && input[i] != input[i + 1])
                {
                    RecoveryCodeCorrection.SetSymbol(p, i, input[i + 1]);
                    RecoveryCodeCorrection.SetSymbol(p, i + 1, input[i]);
                    if (IsValid(d, p)) { output.Add(p, [i, i + 1]); }
                }
            });
        }
        else if (tier == 2 && unknown.Length == 0)
        {
            var pairs = new List<(int I, int J)>(n * (n - 1) / 2);
            for (var i = 0; i < n; i++)
            {
                for (var j = i + 1; j < n; j++) { pairs.Add((i, j)); }
            }
            Parallel.For(0, pairs.Count, idx =>
            {
                var (i, j) = pairs[idx];
                var d = new Sha3Digest(256);
                using var scratch = SecureBuffer.Scratch(ShareBytes + 1);
                using var w = scratch.BorrowWritable();
                var p = w.Span;
                FillPacked(p, input);
                for (var vi = 0; vi < 32; vi++)
                {
                    if (vi == input[i]) { continue; }
                    RecoveryCodeCorrection.SetSymbol(p, i, (byte)vi);
                    for (var vj = 0; vj < 32; vj++)
                    {
                        if (vj == input[j]) { continue; }
                        RecoveryCodeCorrection.SetSymbol(p, j, (byte)vj);
                        if (IsValid(d, p)) { output.Add(p, [i, j]); }
                    }
                }
            });
        }
        var all = output.All;
        all.Sort(static (a, b) =>
        {
            if (a.Changed.Length != b.Changed.Length) { return a.Changed.Length.CompareTo(b.Changed.Length); }
            for (var k = 0; k < a.Changed.Length; k++)
            {
                if (a.Changed[k] != b.Changed[k]) { return a.Changed[k].CompareTo(b.Changed[k]); }
            }
            return 0;
        });
        return all;
    }

    /// <summary>Sucht zwei Kandidaten (je einer pro Teil, verschiedene x), deren R die öffentlichen Schlüssel ergibt.
    /// Stufen werden in der Reihenfolge der Gesamtänderungen probiert und erst bei Bedarf berechnet. Der Aufrufer
    /// übernimmt die beiden Treffer (Dispose); alle übrigen Kandidaten werden hier freigegeben.</summary>
    internal static (Candidate A, Candidate B)? SearchPair(byte[] a, byte[] b, Func<SecureBuffer, bool> isMatch)
    {
        var cacheA = new Dictionary<int, List<Candidate>>();
        var cacheB = new Dictionary<int, List<Candidate>>();
        (Candidate, Candidate)? found = null;
        try
        {
            List<Candidate> ListOf(byte[] input, int tier, Dictionary<int, List<Candidate>> cache)
            {
                if (cache.TryGetValue(tier, out var c)) { return c; }
                c = Candidates(input, tier);
                cache[tier] = c;
                return c;
            }
            for (var total = 0; total <= 4 && found is null; total++)
            {
                for (var ta = 0; ta <= 2 && found is null; ta++)
                {
                    var tb = total - ta;
                    if (tb is < 0 or > 2) { continue; }
                    var la = ListOf(a, ta, cacheA);
                    if (la.Count == 0) { continue; }
                    var lb = ListOf(b, tb, cacheB);
                    foreach (var ca in la)
                    {
                        foreach (var cb in lb)
                        {
                            if (ca.X == cb.X) { continue; }
                            using var ya = ca.Y();
                            using var yb = cb.Y();
                            using var r = Combine(ca.X, ya, cb.X, yb);
                            if (isMatch(r))
                            {
                                found = (ca, cb);
                                break;
                            }
                        }
                        if (found is not null) { break; }
                    }
                }
            }
            return found;
        }
        finally
        {
            foreach (var list in cacheA.Values.Concat(cacheB.Values))
            {
                foreach (var c in list)
                {
                    if (found is { } f && (ReferenceEquals(c, f.Item1) || ReferenceEquals(c, f.Item2))) { continue; }
                    c.Dispose();
                }
            }
        }
    }
}
