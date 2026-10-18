using System.Text;
using Siegel.Modell;

namespace Siegel.Werkzeuge;

/// <summary>
/// CSV-Export im Chrome-Format (SPEC §7.9, §8), gleich wie Sources/SiegelCore/Werkzeuge/CSVExport.swift: Kopf
/// <c>name,url,username,password,note</c>, alle Felder (auch der Kopf) in Anführungszeichen, <c>"</c> verdoppelt,
/// CRLF nach jedem Datensatz, UTF-8 ohne BOM. Gelöschte Einträge, der Verlauf und 2FA-Geheimnisse werden nicht
/// exportiert; Werte bleiben roh (kein Formel-Präfix). Geheimteile kommen aus <see cref="EntrySecrets"/>; bei nicht
/// versiegelten Einträgen füllt der Eintrag selbst leere Felder (wie beim KeePass-Export). Die Ausgabe wird in einem
/// Zug in einen Puffer exakt passender Grösse geschrieben (keine Klartext-Kopien beim Wachsen).
/// </summary>
public static class CsvExport
{
    internal static readonly string[] Header = ["name", "url", "username", "password", "note"];

    public static byte[] Export(IEnumerable<(VaultEntry Entry, EntrySecrets Secrets)> items)
    {
        items ??= [];
        var rows = new List<string[]> { Header };
        foreach (var (entry, given) in items)
        {
            if (entry.DeletedAt is not null) { continue; }
            var secrets = KeePassExport.EffectiveSecrets(entry, given);
            rows.Add([entry.Title, entry.Url, entry.Username, secrets.Password, secrets.Notes]);
        }

        // Exakte Grösse: je Feld 2 Anführungszeichen + Bytes + verdoppelte ", dazu Kommas und CRLF.
        var size = 0;
        foreach (var row in rows)
        {
            foreach (var value in row) { size += 2 + Encoding.UTF8.GetByteCount(value) + value.Count(c => c == '"'); }
            size += Math.Max(row.Length - 1, 0) + 2;
        }

        var data = new byte[size];
        var offset = 0;
        var scratch = new byte[256];
        void Put(byte b)
        {
            if (offset < data.Length) { data[offset] = b; }
            offset++;
        }
        try
        {
            foreach (var row in rows)
            {
                for (var column = 0; column < row.Length; column++)
                {
                    if (column > 0) { Put(0x2C); }
                    Put(0x22);
                    var value = row[column];
                    var needed = Encoding.UTF8.GetMaxByteCount(value.Length);
                    if (scratch.Length < needed)
                    {
                        Sodium.Wipe(scratch);
                        scratch = new byte[needed];
                    }
                    var length = Encoding.UTF8.GetBytes(value, scratch);
                    for (var k = 0; k < length; k++)
                    {
                        Put(scratch[k]);
                        if (scratch[k] == 0x22) { Put(0x22); }
                    }
                    Sodium.Wipe(scratch.AsSpan(0, length));
                    Put(0x22);
                }
                Put(0x0D);
                Put(0x0A);
            }
        }
        finally
        {
            Sodium.Wipe(scratch);
        }
        return data;
    }
}
