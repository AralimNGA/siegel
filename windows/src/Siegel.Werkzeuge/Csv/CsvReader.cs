using System.Text;
using Siegel.Modell;

namespace Siegel.Werkzeuge;

/// <summary>
/// Strenger RFC-4180-Leser auf Byte-Ebene (SPEC §8 „CSV-Details“), gleich wie Sources/SiegelCore/Werkzeuge/CSVReader.swift:
/// Trenner <c>,</c>; Datensätze enden mit CRLF, LF oder CR; <c>"…"</c> darf Kommas, CR und LF enthalten, <c>""</c> = <c>"</c>.
/// <c>"</c> mitten in einem nicht zitierten Feld oder ein Zeichen nach dem schliessenden <c>"</c> → <c>csv.quote</c>;
/// offenes <c>"</c> am Ende → <c>csv.unterminatedQuote</c>. Leerzeilen (ein Feld, leer oder nur Leerzeichen/Tabs)
/// werden übersprungen. Feldinhalte byte-genau, gültiges UTF-8 (<c>csv.encoding</c>). Zeilennummern sind physische
/// Zeilen (1-basiert). Höchstens <see cref="MaxFields"/> Felder je Datensatz, geprüft während des Lesens (Befund #45).
/// </summary>
internal sealed class CsvReader
{
    internal readonly record struct Record(int Line, List<string> Fields);

    /// <summary>Obergrenze der Felder je Datensatz; <see cref="CsvImport"/> setzt nach der Kopfzeile deren Spaltenzahl.</summary>
    internal int MaxFields { get; set; } = 256;
    /// <summary>Code beim Überschreiten (Kopfzeile: csv.header.unknown, Datensätze: csv.fieldCount).</summary>
    internal string TooManyFieldsReason { get; set; } = "csv.header.unknown";

    private readonly byte[] bytes;
    private int index;
    private int line = 1;
    private byte[] field = new byte[4096];
    private int fieldLength;

    private const byte Quote = 0x22;
    private const byte Comma = 0x2C;
    private const byte Cr = 0x0D;
    private const byte Lf = 0x0A;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal CsvReader(byte[] bytes, int startIndex)
    {
        this.bytes = bytes;
        index = startIndex;
    }

    /// <summary>Best effort: Arbeitspuffer nullen.</summary>
    internal void Wipe()
    {
        Sodium.Wipe(field);
        fieldLength = 0;
    }

    private enum State { FieldStart, Unquoted, Quoted, QuoteInQuoted }

    /// <summary>Nächster nicht leerer Datensatz oder null am Dateiende.</summary>
    internal Record? Next()
    {
        while (true)
        {
            if (ReadRecord() is not { } record) { return null; }
            if (record.Fields.Count == 1 && record.Fields[0].All(c => c is ' ' or '\t')) { continue; }   // Leerzeile
            return record;
        }
    }

    private Record? ReadRecord()
    {
        var count = bytes.Length;
        if (index >= count) { return null; }
        var recordLine = line;
        var fields = new List<string>();
        var state = State.FieldStart;

        while (index < count)
        {
            var b = bytes[index];
            index++;
            switch (state)
            {
                case State.FieldStart:
                    if (b == Quote)
                    {
                        state = State.Quoted;
                    }
                    else if (b == Comma)
                    {
                        Append(TakeField(recordLine), fields, recordLine);
                    }
                    else if (b is Cr or Lf)
                    {
                        Append(TakeField(recordLine), fields, recordLine);
                        ConsumeLineBreak(b);
                        return new Record(recordLine, fields);
                    }
                    else
                    {
                        AddByte(b);
                        state = State.Unquoted;
                    }
                    break;
                case State.Unquoted:
                    if (b == Comma)
                    {
                        Append(TakeField(recordLine), fields, recordLine);
                        state = State.FieldStart;
                    }
                    else if (b is Cr or Lf)
                    {
                        Append(TakeField(recordLine), fields, recordLine);
                        ConsumeLineBreak(b);
                        return new Record(recordLine, fields);
                    }
                    else if (b == Quote)
                    {
                        throw Invalid(line, "csv.quote");
                    }
                    else
                    {
                        AddByte(b);
                    }
                    break;
                case State.Quoted:
                    if (b == Quote)
                    {
                        state = State.QuoteInQuoted;
                    }
                    else
                    {
                        AddByte(b);
                        if (b == Lf)
                        {
                            line++;
                        }
                        else if (b == Cr)
                        {
                            if (index < count && bytes[index] == Lf)
                            {
                                AddByte(Lf);
                                index++;
                            }
                            line++;
                        }
                    }
                    break;
                default:                                       // QuoteInQuoted
                    if (b == Quote)
                    {
                        AddByte(Quote);
                        state = State.Quoted;
                    }
                    else if (b == Comma)
                    {
                        Append(TakeField(recordLine), fields, recordLine);
                        state = State.FieldStart;
                    }
                    else if (b is Cr or Lf)
                    {
                        Append(TakeField(recordLine), fields, recordLine);
                        ConsumeLineBreak(b);
                        return new Record(recordLine, fields);
                    }
                    else
                    {
                        throw Invalid(line, "csv.quote");
                    }
                    break;
            }
        }

        // Dateiende ohne abschliessenden Umbruch
        if (state == State.Quoted) { throw Invalid(recordLine, "csv.unterminatedQuote"); }
        Append(TakeField(recordLine), fields, recordLine);
        return new Record(recordLine, fields);
    }

    internal static SiegelException Invalid(int line, string reason) => new(SiegelErrorCode.CsvInvalid, reason, line);

    private void Append(string value, List<string> fields, int recordLine)
    {
        if (fields.Count >= MaxFields) { throw Invalid(recordLine, TooManyFieldsReason); }
        fields.Add(value);
    }

    /// <summary>CRLF als ein Umbruch; einzelnes CR oder LF ebenso.</summary>
    private void ConsumeLineBreak(byte b)
    {
        if (b == Cr && index < bytes.Length && bytes[index] == Lf) { index++; }
        line++;
    }

    private void AddByte(byte b)
    {
        if (fieldLength == field.Length)
        {
            var groesser = new byte[field.Length * 2];
            field.AsSpan(0, fieldLength).CopyTo(groesser);
            Sodium.Wipe(field);
            field = groesser;
        }
        field[fieldLength++] = b;
    }

    private string TakeField(int recordLine)
    {
        try
        {
            return StrictUtf8.GetString(field, 0, fieldLength);
        }
        catch (DecoderFallbackException)
        {
            throw Invalid(recordLine, "csv.encoding");
        }
        finally
        {
            Sodium.Wipe(field.AsSpan(0, fieldLength));
            fieldLength = 0;
        }
    }
}
