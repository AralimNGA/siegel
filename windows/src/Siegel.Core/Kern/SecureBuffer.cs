using System.Runtime.InteropServices;
using Siegel.Core.Native;

namespace Siegel.Core;

/// <summary>
/// Geheimnis-Puffer in <c>sodium_malloc</c>-Speicher (Guard-Pages, mlock), Gegenstück zu <c>SecureBytes</c> (SPEC §5,
/// SPEC-WINDOWS W2). Standardmässig nach dem Befüllen schreibgeschützt (<c>sodium_mprotect_readonly</c>);
/// veränderliche Puffer nur als Rechenfläche (<see cref="Scratch"/>). Freigabe über <c>sodium_free</c> (nullt).
/// Zugriff nur über Leihen (<see cref="Borrow"/>, <see cref="BorrowWritable"/>) mit <c>using</c>: Die Leihe hält eine
/// Referenz auf das Handle, damit ein paralleles <see cref="SafeHandle.Dispose()"/> den Speicher nicht unter einem
/// laufenden Zugriff freigibt.
/// </summary>
internal sealed class SecureBuffer : SafeHandle
{
    /// <summary>Signatur des Befüllers (Span kann kein Typargument von Action sein).</summary>
    internal delegate void Filler(Span<byte> output);

    private readonly int length;
    private bool readOnly;

    private SecureBuffer(IntPtr pointer, int length, bool readOnly) : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(pointer);
        this.length = length;
        this.readOnly = readOnly;
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    /// <summary>Anzahl Byte (nicht geheim).</summary>
    internal int Length => length;

    internal bool IsReadOnly => readOnly;

    protected override bool ReleaseHandle()
    {
        // sodium_free hebt den Schreibschutz auf, nullt (sodium_munlock) und gibt frei.
        Libsodium.sodium_free(handle);
        return true;
    }

    /// <summary>Legt <paramref name="count"/> Byte an (genullt) und lässt sie von <paramref name="fill"/> beschreiben.
    /// Scheitert der Befüller, wird sofort freigegeben.</summary>
    internal static unsafe SecureBuffer Create(int count, Filler fill, bool readOnly = true)
    {
        Libsodium.EnsureReady();
        if (count < 0) { throw Fehler.Crypto("memory.alloc"); }
        var size = (nuint)Math.Max(count, 1);
        var p = Libsodium.sodium_malloc(size);
        if (p == IntPtr.Zero) { throw Fehler.Crypto("memory.alloc"); }
        Libsodium.sodium_memzero((byte*)p, size);
        var buffer = new SecureBuffer(p, count, readOnly);
        try
        {
            fill(new Span<byte>((void*)p, count));
        }
        catch
        {
            buffer.Dispose();
            throw;
        }
        if (readOnly) { _ = Libsodium.sodium_mprotect_readonly(p); }
        return buffer;
    }

    /// <summary>Kopie von Bytes (z. B. HKDF-Ausgaben, Passwort-UTF-8).</summary>
    internal static SecureBuffer Copy(ReadOnlySpan<byte> bytes)
    {
        // Span kann nicht in die Lambda-Hülle: über einen Zeiger auf den (vom Aufrufer gehaltenen) Speicher kopieren.
        unsafe
        {
            fixed (byte* src = bytes)
            {
                var s = (IntPtr)src;
                var n = bytes.Length;
                return Create(n, o => new ReadOnlySpan<byte>((void*)s, n).CopyTo(o));
            }
        }
    }

    /// <summary><paramref name="count"/> Zufallsbytes aus <c>randombytes_buf</c>.</summary>
    internal static SecureBuffer Random(int count) => Create(count, Zufall.Fill);

    /// <summary>Veränderliche, genullte Rechenfläche.</summary>
    internal static SecureBuffer Scratch(int count) => Create(count, static _ => { }, readOnly: false);

    /// <summary>Rechenfläche nach dem Befüllen schreibschützen (danach wie ein Puffer aus <see cref="Create"/>).</summary>
    internal void Freeze()
    {
        if (readOnly) { return; }
        using var l = Borrow();
        _ = Libsodium.sodium_mprotect_readonly(handle);
        readOnly = true;
    }

    /// <summary>Lesende Leihe. Immer mit <c>using</c>.</summary>
    internal Lease Borrow()
    {
        var added = false;
        try
        {
            DangerousAddRef(ref added);
        }
        catch (ObjectDisposedException)
        {
            throw Fehler.Crypto("secure.disposed");
        }
        return new Lease(this);
    }

    /// <summary>Schreibende Leihe, nur für Rechenflächen (<see cref="Scratch"/>).</summary>
    internal WritableLease BorrowWritable()
    {
        if (readOnly) { throw Fehler.Crypto("secure.readonly"); }
        var added = false;
        try
        {
            DangerousAddRef(ref added);
        }
        catch (ObjectDisposedException)
        {
            throw Fehler.Crypto("secure.disposed");
        }
        return new WritableLease(this);
    }

    /// <summary>Teilbereich als neuer (schreibgeschützter) Puffer.</summary>
    internal SecureBuffer Slice(int start, int count)
    {
        if (start < 0 || count < 0 || start + count > length) { throw Fehler.Crypto("secure.range"); }
        using var l = Borrow();
        return Copy(l.Span.Slice(start, count));
    }

    /// <summary>Vergleich in konstanter Zeit (<c>sodium_memcmp</c>).</summary>
    internal bool ConstantTimeEquals(SecureBuffer other)
    {
        if (other.length != length) { return false; }
        using var b = other.Borrow();
        return ConstantTimeEquals(b.Span);
    }

    internal unsafe bool ConstantTimeEquals(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != length) { return false; }
        if (length == 0) { return true; }
        using var a = Borrow();
        fixed (byte* pa = a.Span)
        fixed (byte* pb = bytes)
        {
            return Libsodium.sodium_memcmp(pa, pb, (nuint)length) == 0;
        }
    }

    /// <summary>Geschwärzt (SPEC §5).</summary>
    public override string ToString() => "SecureBuffer(redacted)";

#if DEBUG
    /// <summary>Nur Tests: Inhalt als Hex (Testvektoren).</summary>
    internal string HexForTesting()
    {
        using var l = Borrow();
        return Convert.ToHexStringLower(l.Span);
    }
#endif

    private unsafe ReadOnlySpan<byte> RawSpan => new((void*)handle, length);

    private unsafe Span<byte> RawWritableSpan => new((void*)handle, length);

    /// <summary>Lesender Zugriff, solange die Leihe lebt.</summary>
    internal readonly ref struct Lease
    {
        private readonly SecureBuffer owner;

        internal Lease(SecureBuffer owner)
        {
            this.owner = owner;
            Span = owner.RawSpan;
        }

        internal ReadOnlySpan<byte> Span { get; }

        public void Dispose() => owner.DangerousRelease();
    }

    /// <summary>Schreibender Zugriff auf eine Rechenfläche, solange die Leihe lebt.</summary>
    internal readonly ref struct WritableLease
    {
        private readonly SecureBuffer owner;

        internal WritableLease(SecureBuffer owner)
        {
            this.owner = owner;
            Span = owner.RawWritableSpan;
        }

        internal Span<byte> Span { get; }

        public void Dispose() => owner.DangerousRelease();
    }
}

/// <summary>Zufall aus libsodium (<c>randombytes_buf</c>, <c>randombytes_uniform</c>).</summary>
internal static class Zufall
{
    internal static unsafe void Fill(Span<byte> output)
    {
        Libsodium.EnsureReady();
        if (output.IsEmpty) { return; }
        fixed (byte* p = output)
        {
            Libsodium.randombytes_buf(p, (nuint)output.Length);
        }
    }

    /// <summary>Zufallsbytes für nicht geheime Werte (Nonces, Salze, Kennungen).</summary>
    internal static byte[] Bytes(int count)
    {
        var b = new byte[count];
        Fill(b);
        return b;
    }

    /// <summary>Gleichverteilt in 0..&lt;upper.</summary>
    internal static uint Uniform(uint upper)
    {
        Libsodium.EnsureReady();
        return Libsodium.randombytes_uniform(upper);
    }

    /// <summary>Zufällige UUID (Version 4, RFC 4122) aus libsodium.</summary>
    internal static Guid NewGuid()
    {
        Span<byte> b = stackalloc byte[16];
        Fill(b);
        b[6] = (byte)((b[6] & 0x0F) | 0x40);
        b[8] = (byte)((b[8] & 0x3F) | 0x80);
        return new Guid(b, bigEndian: true);
    }
}
