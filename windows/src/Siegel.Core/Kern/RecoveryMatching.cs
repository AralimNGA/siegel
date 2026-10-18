using System.Security.Cryptography;

namespace Siegel.Core;

/// <summary>
/// Code bzw. zwei Teile gegen einen Kopf prüfen, mit Fehlerkorrektur (SPEC §1.5, §15) – der reine Kern von
/// <c>VaultStore.checkRecoveryCode</c>/<c>checkRecoveryShares</c> (VaultStore+Notfall.swift), ohne Datei-Zugriff.
/// Stufe B legt den Dateiteil darum (Prüfsumme der ganzen Datei bei einem Fehlschlag, Sicherungen).
/// </summary>
internal static class RecoveryMatching
{
    /// <summary>Hat die Eingabe die volle Form eines Notfallcodes (55 Zeichen aus dem Alphabet, höchstens 4 „?“)?</summary>
    internal static bool CodeInputIsComplete(string input) => Parses(input, RecoveryCodeCodec.SymbolCount);

    /// <summary>Wie <see cref="CodeInputIsComplete"/>, für einen Teil (56 Zeichen).</summary>
    internal static bool ShareInputIsComplete(string input) => Parses(input, Shamir.SymbolCount);

    private static bool Parses(string input, int count)
    {
        try
        {
            CryptographicOperations.ZeroMemory(RecoveryCodeCodec.ParseSymbols(input, allowUnknown: true, count));
            return true;
        }
        catch (Siegel.Modell.SiegelException)
        {
            return false;
        }
    }

    /// <summary>Code (Symbole, „?“ erlaubt) gegen den Kopf. Treffer → Exact/Corrected; sonst möglichst genauer Grund:
    /// „?“ → RecoveryCodeChecksum, Füllbits → InvalidRecoveryCodeFormat, Prüfsumme → RecoveryCodeChecksum, gültiger
    /// Code eines anderen Kits → WrongRecoveryCode (mit Kit-Kennungen).</summary>
    internal static RecoveryCodeMatch MatchRecoveryCode(byte[] input, VaultHeader header)
    {
        var symbols = (byte[])input.Clone();
        SecureBuffer? exactR = null;
        try
        {
            var vaultId = header.VaultId;
            var pk = header.Pk;
            var hasUnknown = symbols.Contains(RecoveryCodeCodec.UnknownSymbol);
            var paddingOk = false;
            var checksumOk = false;
            if (!hasUnknown)
            {
                using var packed = SecureBuffer.Scratch(RecoveryCodeCodec.PackedBytes);
                using (var w = packed.BorrowWritable())
                {
                    RecoveryCodeCodec.Pack(symbols, w.Span);
                    (paddingOk, checksumOk) = RecoveryCodeCodec.PackedIsValid(w.Span);
                }
                if (paddingOk && checksumOk)
                {
                    exactR = packed.Slice(0, RecoveryKem.RBytes);
                    if (RecoveryKem.Matches(exactR, vaultId, pk)) { return RecoveryCodeMatch.Exact; }
                }
            }
            var hit = RecoveryCodeCorrection.Search(symbols, r =>
            {
                using var rb = SecureBuffer.Copy(r);
                return RecoveryKem.Matches(rb, vaultId, pk);
            });
            if (hit is not null)
            {
                try
                {
                    return RecoveryCodeMatch.Corrected(RecoveryCodeCodec.FormatSymbols(hit.Symbols, RecoveryCodeCodec.GroupSize),
                        [.. hit.Changed.Order()]);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(hit.Symbols);
                }
            }
            if (hasUnknown) { throw Fehler.CodeChecksum(); }
            if (!paddingOk) { throw Fehler.InvalidCodeFormat(); }
            if (!checksumOk || exactR is null) { throw Fehler.CodeChecksum(); }
            var codeKit = RecoveryKem.DerivePublicKeys(exactR, vaultId).KitId;
            throw Fehler.WrongRecoveryCode(codeKit, pk.KitId);
        }
        finally
        {
            exactR?.Dispose();
            CryptographicOperations.ZeroMemory(symbols);
        }
    }

    /// <summary>Genau zwei Teil-Eingaben → Symbole („?“ erlaubt). Sonst InvalidRecoveryCodeFormat.</summary>
    internal static byte[][] ParseShareInputs(IReadOnlyList<string> inputs)
    {
        Fehler.NotNull(inputs);
        if (inputs.Count != 2) { throw Fehler.InvalidCodeFormat(); }
        return ParseAllOrWipe(inputs, i => RecoveryCodeCodec.ParseSymbols(i, allowUnknown: true, Shamir.SymbolCount));
    }

    /// <summary>Alle Eingaben oder keine: Scheitert eine, werden die schon erzeugten Symbolfelder genullt, bevor der Fehler
    /// weitergeht (der Aufrufer bekommt sie dann nie und kann sie nicht nullen, Befund hygiene-5).</summary>
    internal static byte[][] ParseAllOrWipe(IReadOnlyList<string> inputs, Func<string, byte[]> parse)
    {
        var output = new byte[inputs.Count][];
        var n = 0;
        try
        {
            for (; n < output.Length; n++) { output[n] = parse(inputs[n]); }
            return output;
        }
        catch
        {
            for (var i = 0; i < n; i++) { CryptographicOperations.ZeroMemory(output[i]); }
            throw;
        }
    }

    /// <summary>Zwei Teile (Shamir 2 aus 3) gegen den Kopf, mit Korrektur pro Teil: erst Teil-Prüfsumme, dann zusammen
    /// mit dem anderen Teil der pk-Vergleich. Ergebnis in der Reihenfolge der Eingaben. Zweimal derselbe Teil →
    /// InvalidRecoveryCodeFormat.</summary>
    internal static IReadOnlyList<RecoveryCodeMatch> MatchRecoveryShares(byte[][] inputs, VaultHeader header)
    {
        var vaultId = header.VaultId;
        var pk = header.Pk;
        var pair = Shamir.SearchPair(inputs[0], inputs[1], r => RecoveryKem.Matches(r, vaultId, pk));
        if (pair is { } p)
        {
            using (p.A)
            using (p.B)
            {
                return [ShareMatch(p.A), ShareMatch(p.B)];
            }
        }
        // Kein Treffer: möglichst genauer Grund.
        if (inputs.Any(i => i.Contains(RecoveryCodeCodec.UnknownSymbol))) { throw Fehler.CodeChecksum(); }
        var exactA = Shamir.Candidates(inputs[0], 0);
        var exactB = Shamir.Candidates(inputs[1], 0);
        try
        {
            if (exactA.Count == 0 || exactB.Count == 0) { throw Fehler.CodeChecksum(); }
            var a = exactA[0];
            var b = exactB[0];
            if (a.X == b.X) { throw Fehler.InvalidCodeFormat(); }
            using var ya = a.Y();
            using var yb = b.Y();
            using var r = Shamir.Combine(a.X, ya, b.X, yb);
            var codeKit = RecoveryKem.DerivePublicKeys(r, vaultId).KitId;
            throw Fehler.WrongRecoveryCode(codeKit, pk.KitId);
        }
        finally
        {
            foreach (var c in exactA.Concat(exactB)) { c.Dispose(); }
        }
    }

    private static RecoveryCodeMatch ShareMatch(Shamir.Candidate c)
    {
        if (c.Changed.Length == 0) { return RecoveryCodeMatch.Exact; }
        var symbols = c.Symbols();
        try
        {
            return RecoveryCodeMatch.Corrected(RecoveryCodeCodec.FormatSymbols(symbols, Shamir.GroupSize), [.. c.Changed.Order()]);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(symbols);
        }
    }

    /// <summary>Zwei exakte Teile → R. Gleiche Nummer oder nicht genau zwei → InvalidRecoveryCodeFormat.</summary>
    internal static SecureBuffer CombineShares(IReadOnlyList<string> shares)
    {
        Fehler.NotNull(shares);
        if (shares.Count != 2) { throw Fehler.InvalidCodeFormat(); }
        var (xa, ya) = Shamir.Decode(shares[0]);
        using (ya)
        {
            var (xb, yb) = Shamir.Decode(shares[1]);
            using (yb)
            {
                if (xa == xb) { throw Fehler.InvalidCodeFormat(); }
                return Shamir.Combine(xa, ya, xb, yb);
            }
        }
    }

    /// <summary>Formatierter Code samt Kit-Kennung zu R.</summary>
    internal static RecoveryCode CodeFor(SecureBuffer r, RecoveryPublicKeys pk) => new(RecoveryCodeCodec.Format(r), pk.KitId);

    /// <summary>Drei formatierte Teile zu R (zufällige Koeffizienten), mit Kit-Kennung.</summary>
    internal static IReadOnlyList<RecoveryShare> SharesFor(SecureBuffer r, RecoveryPublicKeys pk)
    {
        var ys = Shamir.Split(r);
        try
        {
            return [.. ys.Select((y, i) => new RecoveryShare(i + 1, Shamir.Format((byte)(i + 1), y), pk.KitId))];
        }
        finally
        {
            foreach (var y in ys) { y.Dispose(); }
        }
    }
}
