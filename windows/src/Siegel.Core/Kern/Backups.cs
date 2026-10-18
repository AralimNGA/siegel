using System.Globalization;

namespace Siegel.Core;

/// <summary>
/// Namensschema der Sicherungen (SPEC §4), wie Backups.swift:
/// <code>
///   lokal:      Sicherungen/&lt;vaultID&gt;/&lt;UTC JJJJMMTT-hhmmss&gt;-g&lt;generation&gt;-&lt;4 Zufallshex&gt;[-vor-&lt;anlass&gt;].siegel
///   extern:     Siegel-&lt;vaultID 8 hex&gt;-&lt;UTC JJJJMMTT-hhmmss&gt;.siegel
///   beschädigt: Sicherungen/beschaedigt-&lt;UTC JJJJMMTT-hhmmss&gt;[-&lt;4 hex&gt;].siegel
/// </code>
/// </summary>
internal static class BackupNaming
{
    internal const string FileExtension = "siegel";
    internal const string QuarantinePrefix = "beschaedigt-";
    internal const string ExternalPrefixText = "Siegel-";

    /// <summary>Anlässe angehefteter Sicherungen.</summary>
    internal static class Reason
    {
        internal const string ImportCsv = "import";
        internal const string PasswordChange = "passwortwechsel";
        internal const string Recovery = "notfall";
        internal const string NewKit = "neues-kit";
        internal const string Migration = "migration";

        /// <summary>Letzter Stand im Format v1 vor dem ersten Schreiben in Format v2 (SPEC §13.2).</summary>
        internal const string MigrationV1 = "migration-v1";
        internal const string Restore = "wiederherstellung";

        /// <summary>Vor einem Wechsel der Sicherheitsstufe (Zugangswechsel, SPEC §13).</summary>
        internal const string LevelChange = "stufenwechsel";
    }

    /// <summary>„JJJJMMTT-hhmmss“ in UTC (Sekunden abgeschnitten wie Swift <c>dateComponents</c>).</summary>
    internal static string Timestamp(DateTimeOffset date) =>
        date.UtcDateTime.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);

    /// <summary>Zeit aus „JJJJMMTT“ und „hhmmss“. Wie Foundations nachsichtiger Kalender werden übergrosse Felder
    /// übertragen (Monat 13 → Januar des Folgejahres, Tag 0 → letzter Tag des Vormonats). Jahr 0 kann .NET nicht
    /// darstellen → null (Swift: 1 v. Chr.; harmloser Randfall, kein echter Name).</summary>
    internal static DateTimeOffset? ParseTimestamp(string day, string time)
    {
        if (day.Length != 8 || time.Length != 6 || !day.All(char.IsAsciiDigit) || !time.All(char.IsAsciiDigit)) { return null; }
        static int N(string s) => int.Parse(s, NumberStyles.None, CultureInfo.InvariantCulture);
        var y = N(day[..4]);
        var mo = N(day[4..6]);
        var d = N(day[6..]);
        var h = N(time[..2]);
        var mi = N(time[2..4]);
        var s = N(time[4..]);
        try
        {
            var t = new DateTimeOffset(y, 1, 1, 0, 0, 0, TimeSpan.Zero).AddMonths(mo - 1).AddDays(d - 1).AddHours(h)
                .AddMinutes(mi).AddSeconds(s);
            return t;
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    internal static string RandomHex4() => Bytes.Hex(Zufall.Bytes(2));

    internal static string LocalName(DateTimeOffset date, ulong generation, string? reason)
    {
        var name = Timestamp(date) + "-g" + generation.ToString(CultureInfo.InvariantCulture) + "-" + RandomHex4();
        if (reason is not null) { name += "-vor-" + reason; }
        return name + "." + FileExtension;
    }

    internal sealed record LocalNameInfo(DateTimeOffset Date, ulong Generation, string? Reason);

    /// <summary>Zerlegt einen lokalen Sicherungsnamen; null, wenn er nicht dem Schema folgt.</summary>
    internal static LocalNameInfo? ParseLocal(string fileName)
    {
        var suffix = "." + FileExtension;
        if (!fileName.EndsWith(suffix, StringComparison.Ordinal)) { return null; }
        var stem = fileName[..^suffix.Length];
        var parts = stem.Split('-');
        if (parts.Length < 4 || ParseTimestamp(parts[0], parts[1]) is not { } date) { return null; }
        if (!parts[2].StartsWith('g') || !ulong.TryParse(parts[2].AsSpan(1), NumberStyles.AllowLeadingSign,
                CultureInfo.InvariantCulture, out var generation))
        {
            return null;
        }
        if (parts[3].Length != 4 || !parts[3].All(IsHexDigit)) { return null; }
        string? reason = null;
        if (parts.Length > 4)
        {
            if (parts[4] != "vor" || parts.Length <= 5) { return null; }
            reason = string.Join('-', parts[5..]);
        }
        return new LocalNameInfo(date, generation, reason);
    }

    /// <summary>Wie Swift <c>Character.isHexDigit</c>: ASCII- und Vollbreiten-Hexziffern.</summary>
    internal static bool IsHexDigit(char c) =>
        char.IsAsciiHexDigit(c) || c is >= '０' and <= '９' or >= 'Ａ' and <= 'Ｆ' or >= 'ａ' and <= 'ｆ';

    internal static string ExternalPrefix(Guid vaultId) => ExternalPrefixText + Bytes.Hex(Bytes.OfGuid(vaultId))[..8] + "-";

    internal static string ExternalName(Guid vaultId, DateTimeOffset date) =>
        ExternalPrefix(vaultId) + Timestamp(date) + "." + FileExtension;

    /// <summary>Zeit aus einem externen Namen (nur für das passende Präfix).</summary>
    internal static DateTimeOffset? ParseExternal(string fileName, string prefix)
    {
        var suffix = "." + FileExtension;
        if (!fileName.StartsWith(prefix, StringComparison.Ordinal) || !fileName.EndsWith(suffix, StringComparison.Ordinal)
            || fileName.Length < prefix.Length + suffix.Length)
        {
            return null;
        }
        var middle = fileName[prefix.Length..^suffix.Length];
        var parts = middle.Split('-');
        return parts.Length == 2 ? ParseTimestamp(parts[0], parts[1]) : null;
    }

    /// <summary>Externe Namen beliebiger Tresore: „Siegel-&lt;8 hex&gt;-JJJJMMTT-hhmmss.siegel“.</summary>
    internal static DateTimeOffset? ParseAnyExternal(string fileName)
    {
        if (!fileName.StartsWith(ExternalPrefixText, StringComparison.Ordinal)) { return null; }
        var rest = fileName[ExternalPrefixText.Length..];
        if (rest.Length <= 9 || !rest[..8].All(IsHexDigit) || rest[8] != '-') { return null; }
        return ParseExternal(fileName, ExternalPrefixText + rest[..8] + "-");
    }

    internal static string QuarantineName(DateTimeOffset date, string? suffix) =>
        QuarantinePrefix + Timestamp(date) + (suffix is null ? "" : "-" + suffix) + "." + FileExtension;
}

/// <summary>
/// Zeitliche Ausdünnung pro vaultID (SPEC §4): alles aus den letzten 48 h (max. 50), danach je die neueste pro Tag für
/// 30 Tage, pro Woche für 26 Wochen, pro Monat für 24 Monate. Nie gelöscht: angeheftete und die älteste.
/// </summary>
internal static class BackupThinning
{
    internal sealed record Item(string Path, DateTimeOffset Date, bool Pinned);

    internal static readonly TimeSpan RecentWindow = TimeSpan.FromHours(48);
    internal const int RecentMax = 50;

    internal static IReadOnlyList<string> SelectForDeletion(IReadOnlyList<Item> items, DateTimeOffset now)
    {
        if (items.Count == 0) { return []; }
        var oldest = items.MinBy(i => i.Date)!;
        var keep = new HashSet<string>(StringComparer.Ordinal) { oldest.Path };
        var unpinned = items.Where(i => !i.Pinned).OrderByDescending(i => i.Date).ToList();
        var recentKept = 0;
        foreach (var it in unpinned.Where(i => now - i.Date <= RecentWindow))
        {
            if (recentKept < RecentMax)
            {
                keep.Add(it.Path);
                recentKept++;
            }
        }
        void KeepNewestPerBucket(DateTimeOffset start, Func<DateTimeOffset, long> bucket)
        {
            var seen = new HashSet<long>();
            foreach (var it in unpinned.Where(i => i.Date >= start))
            {
                if (seen.Add(bucket(it.Date))) { keep.Add(it.Path); }
            }
        }
        static long Day(DateTimeOffset d) => (long)Math.Floor(Clock.ToSeconds(d) / 86_400);
        // Wochen ab Montag (1970-01-01 war ein Donnerstag)
        static long Week(DateTimeOffset d) => (long)Math.Floor((Clock.ToSeconds(d) / 86_400 + 3) / 7);
        static long Month(DateTimeOffset d) => (long)d.UtcDateTime.Year * 12 + d.UtcDateTime.Month;
        KeepNewestPerBucket(now.AddDays(-30), Day);
        KeepNewestPerBucket(now.AddDays(-26 * 7), Week);
        DateTimeOffset monthStart;
        try
        {
            monthStart = now.ToUniversalTime().AddMonths(-24);
        }
        catch (ArgumentOutOfRangeException)
        {
            monthStart = DateTimeOffset.MinValue;
        }
        KeepNewestPerBucket(monthStart, Month);
        return [.. unpinned.Where(i => !keep.Contains(i.Path)).Select(i => i.Path)];
    }
}
