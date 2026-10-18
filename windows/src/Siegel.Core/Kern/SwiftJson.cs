using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// JSON genau wie Swift Foundation (macOS 26, JSONEncoder mit .sortedKeys, gemessen 18.10.2026): keine Leerzeichen,
// Schlüssel ordinal sortiert (Byte-Reihenfolge), „/“ als „\/“, Steuerzeichen als \b \t \n \f \r bzw. \u00xx (klein),
// alles andere (auch DEL, U+2028/2029, Nicht-ASCII) roh in UTF-8, Zahlen wie Swift <c>description</c> ohne „.0“.
// Lesen wie Swift JSONDecoder: erster von doppelten Schlüsseln gilt, Int auch aus 1.0/1e0 (wenn exakt ganz), Data nur
// striktes Base64 mit Auffüllung, UUID nur 36 Zeichen.
namespace Siegel.Core;

/// <summary>Zahlenformat von Swift <c>Double.description</c> (kürzeste Rundlauf-Darstellung), wie JSONEncoder es
/// schreibt: „.0“ am Ende entfällt; Exponentialform für |x| &gt; 2^53 oder wenn die erste Ziffer erst nach 10^-4 kommt
/// (<c>1e-05</c>, <c>1e+16</c>, <c>9.007199254740994e+15</c>).</summary>
internal static class SwiftDouble
{
    private const double TwoPow53 = 9007199254740992.0;

    internal static string Format(double x)
    {
        if (!double.IsFinite(x)) { throw Fehler.Io("payload.encode"); }
        if (x == 0) { return double.IsNegative(x) ? "-0" : "0"; }
        var negative = x < 0;
        // Kürzeste Ziffern: "R" liefert sie (in wechselnder Form); daraus Ziffern + Exponent gewinnen.
        var (digits, exp10) = Decompose(Math.Abs(x).ToString("R", CultureInfo.InvariantCulture));
        // Wert = 0.digits × 10^exp10 (Swift: decimalExponent)
        var sb = new StringBuilder(32);
        if (negative) { sb.Append('-'); }
        if (exp10 < -3 || Math.Abs(x) > TwoPow53)
        {
            sb.Append(digits[0]);
            if (digits.Length > 1) { sb.Append('.').Append(digits, 1, digits.Length - 1); }
            var e = exp10 - 1;
            sb.Append('e').Append(e < 0 ? '-' : '+');
            var ae = Math.Abs(e);
            if (ae < 10) { sb.Append('0'); }
            sb.Append(ae.ToString(CultureInfo.InvariantCulture));
            return sb.ToString();
        }
        if (exp10 <= 0)
        {
            sb.Append("0.").Append('0', -exp10).Append(digits);
        }
        else if (exp10 >= digits.Length)
        {
            sb.Append(digits).Append('0', exp10 - digits.Length);
        }
        else
        {
            sb.Append(digits, 0, exp10).Append('.').Append(digits, exp10, digits.Length - exp10);
        }
        return sb.ToString();
    }

    /// <summary>"1.2345E+17" / "1792000000.123" / "1E-07" → (signifikante Ziffern ohne führende/abschliessende Nullen,
    /// Exponent e mit Wert = 0.Ziffern × 10^e).</summary>
    private static (string Digits, int Exp10) Decompose(string s)
    {
        var mantissa = s;
        var exp = 0;
        var ePos = s.IndexOfAny(['E', 'e']);
        if (ePos >= 0)
        {
            mantissa = s[..ePos];
            exp = int.Parse(s[(ePos + 1)..], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);
        }
        var dot = mantissa.IndexOf('.', StringComparison.Ordinal);
        var intPart = dot >= 0 ? mantissa[..dot] : mantissa;
        var fracPart = dot >= 0 ? mantissa[(dot + 1)..] : "";
        var all = intPart + fracPart;
        var pointPos = intPart.Length + exp; // Ziffern vor dem Komma
        var lead = 0;
        while (lead < all.Length - 1 && all[lead] == '0') { lead++; }
        all = all[lead..];
        pointPos -= lead;
        var trail = all.Length;
        while (trail > 1 && all[trail - 1] == '0') { trail--; }
        return (all[..trail], pointPos);
    }
}

/// <summary>
/// Schreibt JSON in eine wachsende sichere Rechenfläche (<see cref="SecureBuffer"/>): Klartext-Inhalt entsteht nie in
/// verwalteten Arrays (ausser den .NET-Strings der Einträge, ehrliche Grenze wie beim Mac). Die Aufrufer schreiben die
/// Schlüssel selbst in ordinaler Reihenfolge (ein Test prüft das für jedes Objekt).
/// </summary>
internal sealed class SecureJsonWriter : IDisposable
{
    private SecureBuffer buffer = SecureBuffer.Scratch(16 * 1024);
    private int length;

    internal int Length => length;

    public void Dispose() => buffer.Dispose();

    /// <summary>Das fertige JSON (Leihe auf die Rechenfläche).</summary>
    internal SecureBuffer.Lease Borrow(out int count)
    {
        count = length;
        return buffer.Borrow();
    }

    private void Ensure(int n)
    {
        if (length + n <= buffer.Length) { return; }
        var size = buffer.Length;
        while (size < length + n)
        {
            if (size > int.MaxValue / 2) { throw Fehler.Io("payload.tooLarge"); }
            size *= 2;
        }
        var bigger = SecureBuffer.Scratch(size);
        using (var src = buffer.Borrow())
        using (var dst = bigger.BorrowWritable())
        {
            src.Span[..length].CopyTo(dst.Span);
        }
        buffer.Dispose();
        buffer = bigger;
    }

    private void Raw(ReadOnlySpan<byte> bytes)
    {
        Ensure(bytes.Length);
        using var w = buffer.BorrowWritable();
        bytes.CopyTo(w.Span[length..]);
        length += bytes.Length;
    }

    private void Raw(byte b)
    {
        Ensure(1);
        using var w = buffer.BorrowWritable();
        w.Span[length++] = b;
    }

    private void RawAscii(string s)
    {
        Ensure(s.Length);
        using var w = buffer.BorrowWritable();
        for (var i = 0; i < s.Length; i++) { w.Span[length + i] = (byte)s[i]; }
        length += s.Length;
    }

    /// <summary>Verschachtelung: Art (Objekt/Array) und ob schon ein Element geschrieben wurde.</summary>
    private readonly Stack<(bool IsArray, bool First)> frames = new();

    private void BeforeValue()
    {
        // Werte in Arrays brauchen Kommas; in Objekten setzt Key() sie.
        if (frames.Count == 0 || !frames.Peek().IsArray) { return; }
        var f = frames.Pop();
        if (!f.First) { Raw((byte)','); }
        frames.Push((true, false));
    }

    internal void BeginObject()
    {
        BeforeValue();
        Raw((byte)'{');
        frames.Push((false, true));
    }

    internal void EndObject()
    {
        if (frames.Count == 0 || frames.Pop().IsArray) { throw Fehler.Io("payload.encode"); }
        Raw((byte)'}');
    }

    internal void BeginArray()
    {
        BeforeValue();
        Raw((byte)'[');
        frames.Push((true, true));
    }

    internal void EndArray()
    {
        if (frames.Count == 0 || !frames.Pop().IsArray) { throw Fehler.Io("payload.encode"); }
        Raw((byte)']');
    }

    /// <summary>Schlüssel (ASCII ohne Sonderzeichen) im aktuellen Objekt.</summary>
    internal void Key(string name)
    {
        if (frames.Count == 0 || frames.Peek().IsArray) { throw Fehler.Io("payload.encode"); }
        var f = frames.Pop();
        if (!f.First) { Raw((byte)','); }
        frames.Push((false, false));
        Raw((byte)'"');
        RawAscii(name);
        Raw((byte)'"');
        Raw((byte)':');
    }

    internal void Null()
    {
        BeforeValue();
        RawAscii("null");
    }

    internal void Bool(bool v)
    {
        BeforeValue();
        RawAscii(v ? "true" : "false");
    }

    internal void Integer(long v)
    {
        BeforeValue();
        RawAscii(v.ToString(CultureInfo.InvariantCulture));
    }

    internal void Double(double v)
    {
        BeforeValue();
        RawAscii(SwiftDouble.Format(v));
    }

    /// <summary>Zeitpunkt als Sekunden seit 1970 (<c>secondsSince1970</c>).</summary>
    internal void Date(DateTimeOffset d) => Double(Clock.ToSeconds(d));

    internal void Uuid(Guid id) => String(Bytes.GuidText(id));

    /// <summary>String mit Swift-Escapes; einzelne Surrogate werden U+FFFD (Swift-Strings kennen sie nicht).</summary>
    internal void String(string s)
    {
        BeforeValue();
        Raw((byte)'"');
        Span<byte> utf8 = stackalloc byte[4];
        foreach (var rune in s.EnumerateRunes())
        {
            var v = rune.Value;
            switch (v)
            {
                case '"': RawAscii("\\\""); break;
                case '\\': RawAscii("\\\\"); break;
                case '/': RawAscii("\\/"); break;
                case '\n': RawAscii("\\n"); break;
                case '\r': RawAscii("\\r"); break;
                case '\t': RawAscii("\\t"); break;
                case '\b': RawAscii("\\b"); break;
                case '\f': RawAscii("\\f"); break;
                case < 0x20: RawAscii("\\u00" + v.ToString("x2", CultureInfo.InvariantCulture)); break;
                default:
                    var n = rune.EncodeToUtf8(utf8);
                    Raw(utf8[..n]);
                    break;
            }
        }
        CryptographicOperations.ZeroMemory(utf8);
        Raw((byte)'"');
    }

    /// <summary>Data als Base64 (mit Auffüllung) in einem JSON-String; „/“ wird wie bei Swift zu „\/“.</summary>
    internal void Base64(ReadOnlySpan<byte> data)
    {
        BeforeValue();
        Raw((byte)'"');
        var chars = new char[(data.Length + 2) / 3 * 4];
        try
        {
            if (!Convert.TryToBase64Chars(data, chars, out var written)) { throw Fehler.Io("payload.encode"); }
            for (var i = 0; i < written; i++)
            {
                if (chars[i] == '/') { RawAscii("\\/"); } else { Raw((byte)chars[i]); }
            }
        }
        finally
        {
            Array.Clear(chars);
        }
        Raw((byte)'"');
    }
}

/// <summary>Kleiner JSON-Baum für das Dekodieren nach Swift-Regeln (Werte erst bei Bedarf typisiert).</summary>
internal abstract class JNode
{
    internal static JNode Parse(ReadOnlySpan<byte> utf8)
    {
        var reader = new Utf8JsonReader(utf8, new JsonReaderOptions { MaxDepth = 64 });
        try
        {
            if (!reader.Read()) { throw Fehler.Corrupt("payload.json"); }
            var node = ReadValue(ref reader);
            if (reader.Read()) { throw Fehler.Corrupt("payload.json"); }
            return node;
        }
        catch (JsonException)
        {
            throw Fehler.Corrupt("payload.json");
        }
        catch (InvalidOperationException)
        {
            throw Fehler.Corrupt("payload.json");
        }
    }

    private static JNode ReadValue(ref Utf8JsonReader reader)
    {
        switch (reader.TokenType)
        {
            case JsonTokenType.StartObject:
            {
                var obj = new JObject();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
                {
                    var key = reader.GetString() ?? throw Fehler.Corrupt("payload.json");
                    if (!reader.Read()) { throw Fehler.Corrupt("payload.json"); }
                    var value = ReadValue(ref reader);
                    // Swift JSONDecoder: der erste von doppelten Schlüsseln gilt (gemessen).
                    obj.Items.TryAdd(key, value);
                }
                return obj;
            }
            case JsonTokenType.StartArray:
            {
                var arr = new JArray();
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray) { arr.Items.Add(ReadValue(ref reader)); }
                return arr;
            }
            case JsonTokenType.String:
                return new JString(reader.GetString() ?? "");
            case JsonTokenType.Number:
                return new JNumber(Encoding.ASCII.GetString(reader.ValueSpan));
            case JsonTokenType.True:
                return JBool.True;
            case JsonTokenType.False:
                return JBool.False;
            case JsonTokenType.Null:
                return JNull.Instance;
            default:
                throw Fehler.Corrupt("payload.json");
        }
    }
}

internal sealed class JObject : JNode
{
    internal Dictionary<string, JNode> Items { get; } = new(StringComparer.Ordinal);

    /// <summary>Pflichtfeld (fehlt oder null → Fehler, wie Swift <c>decode</c>).</summary>
    internal JNode Required(string key) =>
        Items.TryGetValue(key, out var v) && v is not JNull ? v : throw Fehler.Corrupt("payload.json");

    /// <summary>Wahlfeld (fehlt oder null → null, wie Swift <c>decodeIfPresent</c>).</summary>
    internal JNode? Optional(string key) => Items.TryGetValue(key, out var v) && v is not JNull ? v : null;
}

internal sealed class JArray : JNode
{
    internal List<JNode> Items { get; } = [];
}

internal sealed class JString(string value) : JNode
{
    internal string Value { get; } = value;
}

internal sealed class JNumber(string text) : JNode
{
    internal string Text { get; } = text;
}

internal sealed class JBool : JNode
{
    private JBool(bool value) => Value = value;

    internal static JBool True { get; } = new(true);
    internal static JBool False { get; } = new(false);
    internal bool Value { get; }
}

internal sealed class JNull : JNode
{
    internal static JNull Instance { get; } = new();
}

/// <summary>Typisierte Lesehilfen mit Swift-Verhalten. Jeder Typfehler → <c>corruptFile("payload.json")</c>.</summary>
internal static class JRead
{
    private static Siegel.Modell.SiegelException Bad() => Fehler.Corrupt("payload.json");

    internal static JObject Obj(JNode n) => n as JObject ?? throw Bad();

    internal static List<JNode> Arr(JNode n) => (n as JArray)?.Items ?? throw Bad();

    internal static string Str(JNode n) => (n as JString)?.Value ?? throw Bad();

    internal static bool Bool(JNode n) => (n as JBool)?.Value ?? throw Bad();

    internal static double Double(JNode n)
    {
        if (n is not JNumber num) { throw Bad(); }
        if (!double.TryParse(num.Text, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) || !double.IsFinite(d))
        {
            throw Bad();
        }
        return d;
    }

    /// <summary>Swift Int (64 Bit): ganze Zahl, auch „1.0“ oder „1e0“, solange exakt darstellbar.</summary>
    internal static long Int(JNode n)
    {
        if (n is not JNumber num) { throw Bad(); }
        if (long.TryParse(num.Text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var v)) { return v; }
        var d = Double(n);
        if (d != Math.Floor(d) || d < -9.2233720368547758E18 || d >= 9.2233720368547758E18) { throw Bad(); }
        return (long)d;
    }

    internal static byte UInt8(JNode n)
    {
        var v = Int(n);
        return v is >= 0 and <= 255 ? (byte)v : throw Bad();
    }

    internal static DateTimeOffset Date(JNode n) => Clock.FromSeconds(Double(n)) ?? throw Bad();

    internal static Guid Uuid(JNode n)
    {
        var s = Str(n);
        if (s.Length != 36 || !Guid.TryParseExact(s, "D", out var g)) { throw Bad(); }
        return g;
    }

    /// <summary>Striktes Base64 wie Swift <c>Data(base64Encoded:)</c>: Länge Vielfaches von 4, nur Alphabet und
    /// abschliessendes „=“, kein Leerraum. Dekodiert in ein Array genau der Ergebnisgrösse: kein grösserer Zwischenpuffer,
    /// der als ungenullte Kopie liegen bliebe (Befund hygiene-3).</summary>
    internal static byte[] Data(JNode n)
    {
        var s = Str(n);
        var output = new byte[DecodedLength(s)];
        DecodeInto(s, output);
        return output;
    }

    /// <summary>Wie <see cref="Data"/>, aber direkt in sodium-Speicher (Rechenfläche → Freeze), ohne verwaltete Rohkopie –
    /// für Geheimnisse wie den Eintrags-Grundschlüssel. Die Base64-Form bleibt als .NET-String im JNode-Baum (ehrliche
    /// Grenze wie auf dem Mac).</summary>
    internal static SecureBuffer SecretData(JNode n)
    {
        var s = Str(n);
        var buffer = SecureBuffer.Scratch(DecodedLength(s));
        try
        {
            using (var w = buffer.BorrowWritable()) { DecodeInto(s, w.Span); }
            buffer.Freeze();
            return buffer;
        }
        catch
        {
            buffer.Dispose();
            throw;
        }
    }

    /// <summary>Prüft die strikte Form und liefert die Anzahl Byte.</summary>
    private static int DecodedLength(string s)
    {
        if (s.Length % 4 != 0) { throw Bad(); }
        var pad = s.EndsWith("==", StringComparison.Ordinal) ? 2 : s.EndsWith('=') ? 1 : 0;
        for (var i = 0; i < s.Length - pad; i++)
        {
            var c = s[i];
            if (!(c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '+' or '/')) { throw Bad(); }
        }
        return s.Length / 4 * 3 - pad;
    }

    /// <summary>Dekodiert in <paramref name="output"/> (genau <see cref="DecodedLength"/> Byte); bei einem Fehler genullt.</summary>
    private static void DecodeInto(string s, Span<byte> output)
    {
        if (!Convert.TryFromBase64String(s, output, out var written) || written != output.Length)
        {
            CryptographicOperations.ZeroMemory(output);
            throw Bad();
        }
    }
}
