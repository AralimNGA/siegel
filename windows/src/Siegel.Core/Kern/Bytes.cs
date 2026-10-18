using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Siegel.Core;

/// <summary>Hilfen für nicht geheime Bytefolgen (Kopf, Slots, Kennungen).</summary>
internal static class Bytes
{
    internal static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

    internal static byte[] Concat(params ReadOnlySpan<byte[]> parts)
    {
        var n = 0;
        foreach (var p in parts) { n += p.Length; }
        var result = new byte[n];
        var o = 0;
        foreach (var p in parts)
        {
            p.CopyTo(result, o);
            o += p.Length;
        }
        return result;
    }

    internal static bool AllZero(ReadOnlySpan<byte> b) => b.IndexOfAnyExcept((byte)0) < 0;

    /// <summary>Wertgleichheit zweier (optionaler) Bytefolgen (nicht zeitkonstant; nur für nicht geheime Werte).</summary>
    internal static bool Same(byte[]? a, byte[]? b) => a is null ? b is null : b is not null && a.AsSpan().SequenceEqual(b);

    /// <summary>Vergleich in konstanter Zeit (gleiche Länge vorausgesetzt, sonst false).</summary>
    internal static bool ConstantTimeEqual(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);

    /// <summary>Kleinbuchstaben-Hex (nur für nicht geheime Werte).</summary>
    internal static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexStringLower(b);

    /// <summary>UUID → 16 Byte in RFC-4122-Reihenfolge (wie Swift <c>uuid</c>-Tupel).</summary>
    internal static byte[] OfGuid(Guid id) => id.ToByteArray(bigEndian: true);

    /// <summary>16 Byte (RFC-4122-Reihenfolge) → UUID.</summary>
    internal static Guid ToGuid(ReadOnlySpan<byte> b) => new(b, bigEndian: true);

    /// <summary>UUID-Text wie Swift <c>uuidString</c> (Grossbuchstaben, mit Bindestrichen).</summary>
    internal static string GuidText(Guid id) => id.ToString("D").ToUpperInvariant();
}

/// <summary>Wachsender Puffer für nicht geheime Daten (Little-Endian).</summary>
internal sealed class ByteWriter(int capacity = 256)
{
    private byte[] buffer = new byte[Math.Max(capacity, 16)];

    internal int Length { get; private set; }

    private Span<byte> Reserve(int n)
    {
        if (Length + n > buffer.Length)
        {
            var bigger = new byte[Math.Max(buffer.Length * 2, Length + n)];
            buffer.AsSpan(0, Length).CopyTo(bigger);
            buffer = bigger;
        }
        var s = buffer.AsSpan(Length, n);
        Length += n;
        return s;
    }

    internal void Write(ReadOnlySpan<byte> b) => b.CopyTo(Reserve(b.Length));

    internal void WriteByte(byte b) => Reserve(1)[0] = b;

    internal void WriteZeros(int n) => Reserve(n).Clear();

    internal void WriteU16(ushort v) => BinaryPrimitives.WriteUInt16LittleEndian(Reserve(2), v);

    internal void WriteU32(uint v) => BinaryPrimitives.WriteUInt32LittleEndian(Reserve(4), v);

    internal void WriteU64(ulong v) => BinaryPrimitives.WriteUInt64LittleEndian(Reserve(8), v);

    internal ReadOnlySpan<byte> Written => buffer.AsSpan(0, Length);

    internal byte[] ToArray() => buffer.AsSpan(0, Length).ToArray();
}

/// <summary>Strenger Leser: zu wenig Bytes → <c>corruptFile(code)</c>.</summary>
internal sealed class ByteReader(byte[] bytes, int from = 0, int? to = null)
{
    private readonly int end = to ?? bytes.Length;

    internal byte[] Source { get; } = bytes;

    internal int Offset { get; private set; } = from;

    internal int Remaining => end - Offset;

    internal byte[] Take(int n, string code)
    {
        if (n < 0 || Remaining < n) { throw Fehler.Corrupt(code); }
        var r = Source.AsSpan(Offset, n).ToArray();
        Offset += n;
        return r;
    }

    internal byte ReadU8(string code)
    {
        if (Remaining < 1) { throw Fehler.Corrupt(code); }
        return Source[Offset++];
    }

    internal ushort ReadU16(string code)
    {
        if (Remaining < 2) { throw Fehler.Corrupt(code); }
        var v = BinaryPrimitives.ReadUInt16LittleEndian(Source.AsSpan(Offset, 2));
        Offset += 2;
        return v;
    }

    internal uint ReadU32(string code)
    {
        if (Remaining < 4) { throw Fehler.Corrupt(code); }
        var v = BinaryPrimitives.ReadUInt32LittleEndian(Source.AsSpan(Offset, 4));
        Offset += 4;
        return v;
    }

    internal ulong ReadU64(string code)
    {
        if (Remaining < 8) { throw Fehler.Corrupt(code); }
        var v = BinaryPrimitives.ReadUInt64LittleEndian(Source.AsSpan(Offset, 8));
        Offset += 8;
        return v;
    }
}
