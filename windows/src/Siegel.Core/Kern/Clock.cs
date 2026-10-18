using System.Globalization;
using System.Numerics;

namespace Siegel.Core;

/// <summary>
/// Zeitquelle und Zeitdarstellung des Kerns. Im Inhalt stehen Zeitpunkte als Sekunden seit 1970 (double, wie Swift
/// <c>secondsSince1970</c>); im Speicher als <see cref="DateTimeOffset"/> (100-ns-Ticks, UTC). Die Umrechnung ist in
/// beide Richtungen exakt gerundet; für alle Zeitpunkte nach 1987 ist double → Ticks → double bitgenau (der Abstand
/// benachbarter doubles ist dort grösser als ein Tick). <see cref="Canonical"/> macht einen Zeitpunkt zum Fixpunkt des
/// JSON-Rundlaufs (Gegenstück zu Swift <c>Clock.canonical</c>).
/// </summary>
internal static class Clock
{
    private const long TicksPerSecond = TimeSpan.TicksPerSecond;
    private static readonly long EpochTicks = DateTimeOffset.UnixEpoch.UtcTicks;

    internal static DateTimeOffset Now()
    {
#if DEBUG
        if (TestHooks.Now is { } fixedNow) { return Canonical(fixedNow); }
#endif
        return Canonical(DateTimeOffset.UtcNow);
    }

    /// <summary>Nach einem Rundlauf über die double-Darstellung (gleich wie nach JSON-Kodieren). Am Rand des Bereichs
    /// (Jahr 9999) rundet das nächste double über das Ende hinaus; dann das nächste darstellbare darunter, damit jeder
    /// geschriebene Zeitpunkt wieder lesbar ist (Swift kennt diese Grenze nicht).</summary>
    internal static DateTimeOffset Canonical(DateTimeOffset d)
    {
        var x = ToSeconds(d);
        for (var i = 0; i < 4; i++)
        {
            if (FromSeconds(x) is { } c) { return c; }
            x = x > 0 ? Math.BitDecrement(x) : Math.BitIncrement(x);
        }
        return d.ToUniversalTime();
    }

    /// <summary><paramref name="d"/> + <paramref name="days"/> Tage, kanonisch; am Rand des Bereichs (Jahr 1 bzw. 9999)
    /// gesättigt statt <c>ArgumentOutOfRangeException</c> (Befund robust-3: eine fremde zustand.json mit letzter echter
    /// Entsperrung im Dezember 9999 liess die Totmann-Frist überlaufen; Swift rechnet mit Double und wirft nie).</summary>
    internal static DateTimeOffset AddDaysSaturating(DateTimeOffset d, int days)
    {
        var ticks = (Int128)d.UtcTicks + (Int128)days * TimeSpan.TicksPerDay;
        if (ticks > DateTimeOffset.MaxValue.UtcTicks) { return Canonical(DateTimeOffset.MaxValue); }
        if (ticks < DateTimeOffset.MinValue.UtcTicks) { return Canonical(DateTimeOffset.MinValue); }
        return Canonical(new DateTimeOffset((long)ticks, TimeSpan.Zero));
    }

    /// <summary>Nächstes double zu (Ticks seit 1970) / 10^7. Exakt über die korrekt rundende Zahl-Erkennung von .NET.</summary>
    internal static double ToSeconds(DateTimeOffset d)
    {
        var ticks = d.UtcTicks - EpochTicks;
        var negative = ticks < 0;
        var abs = negative ? -(BigInteger)ticks : ticks;
        var whole = BigInteger.DivRem(abs, TicksPerSecond, out var frac);
        var text = string.Create(CultureInfo.InvariantCulture, $"{(negative ? "-" : "")}{whole}.{(long)frac:D7}");
        return double.Parse(text, NumberStyles.AllowLeadingSign | NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture);
    }

    /// <summary>Nächster Tick zu x Sekunden (halbe Ticks zur geraden Zahl). null = nicht darstellbar (NaN, ∞,
    /// ausserhalb der Jahre 1–9999).</summary>
    internal static DateTimeOffset? FromSeconds(double x)
    {
        if (!double.IsFinite(x)) { return null; }
        if (x == 0) { return DateTimeOffset.UnixEpoch; }
        var bits = BitConverter.DoubleToInt64Bits(x);
        var negative = bits < 0;
        var exponent = (int)((bits >> 52) & 0x7FF);
        var mantissa = bits & 0xF_FFFF_FFFF_FFFFL;
        if (exponent == 0) { exponent = 1; } else { mantissa |= 1L << 52; }
        exponent -= 1075; // x = mantissa · 2^exponent
        BigInteger ticks;
        var scaled = new BigInteger(mantissa) * TicksPerSecond;
        if (exponent >= 0)
        {
            if (exponent > 64) { return null; }
            ticks = scaled << exponent;
        }
        else
        {
            var shift = -exponent;
            if (shift > 200) { return DateTimeOffset.UnixEpoch; }
            var q = scaled >> shift;
            var rem = scaled - (q << shift);
            var half = BigInteger.One << (shift - 1);
            if (rem > half || (rem == half && !q.IsEven)) { q += 1; }
            ticks = q;
        }
        if (negative) { ticks = -ticks; }
        var total = ticks + EpochTicks;
        if (total < DateTimeOffset.MinValue.UtcTicks || total > DateTimeOffset.MaxValue.UtcTicks) { return null; }
        return new DateTimeOffset((long)total, TimeSpan.Zero);
    }
}
