using System.Runtime.InteropServices;
using Siegel.Modell;

namespace Siegel.Werkzeuge;

/// <summary>Füllt einen frisch angelegten (genullten) Geheimpuffer.</summary>
internal delegate void GeheimpufferFuellen(Span<byte> ziel);

/// <summary>
/// Geheimnis-Puffer in <c>sodium_malloc</c>-Speicher (Guard-Pages, mlock), beim Freigeben genullt (<c>sodium_free</c>),
/// Gegenstück zu <c>SecureBytes</c> auf dem Mac (SPEC §5). Standardmässig nach dem Befüllen schreibgeschützt
/// (<c>sodium_mprotect_readonly</c>); veränderliche Puffer nur als Rechenfläche. Eigener Name, damit er nicht mit dem
/// <c>SecureBuffer</c> des Kerns zusammenstösst. Zugriff nur über Leihen (<see cref="Lesen"/>, <see cref="Schreiben"/>)
/// mit <c>using</c>, wie im Kern: Ohne Leihe könnte ein paralleles Dispose (z. B. Auto-Sperre während der TOTP-Anzeige)
/// den Speicher unter einem laufenden Zugriff freigeben (Befund hygiene-1: Absturz statt Ausnahme).
/// </summary>
internal sealed unsafe class Geheimpuffer : SafeHandle
{
    private readonly bool readOnly;

    private Geheimpuffer(int length, bool readOnly) : base(IntPtr.Zero, ownsHandle: true)
    {
        Length = length;
        this.readOnly = readOnly;
    }

    /// <summary>Anzahl Bytes.</summary>
    internal int Length { get; }

    public override bool IsInvalid => handle == IntPtr.Zero;

    /// <summary>Legt <paramref name="length"/> Byte an (genullt) und lässt sie von <paramref name="fill"/> beschreiben.
    /// Scheitert <paramref name="fill"/>, wird sofort freigegeben.</summary>
    internal static Geheimpuffer Neu(int length, GeheimpufferFuellen? fill = null, bool readOnly = true)
    {
        if (length < 0) { throw new SiegelException(SiegelErrorCode.Crypto, "memory.alloc"); }
        Sodium.EnsureReady();
        // Grösse auf 16 runden: sodium_malloc legt den Block ans Seitenende, so bleibt er ausgerichtet (Hash-Zustände).
        var size = Math.Max((length + 15) & ~15, 16);
        var p = Sodium.sodium_malloc((nuint)size);
        if (p == IntPtr.Zero) { throw new SiegelException(SiegelErrorCode.Crypto, "memory.alloc"); }
        Sodium.sodium_memzero((byte*)p, (nuint)size);
        var puffer = new Geheimpuffer(length, readOnly);
        puffer.SetHandle(p);
        try
        {
            fill?.Invoke(new Span<byte>((void*)p, length));
        }
        catch
        {
            puffer.Dispose();
            throw;
        }
        if (readOnly) { _ = Sodium.sodium_mprotect_readonly(p); }
        return puffer;
    }

    /// <summary>Kopie von Bytes (z. B. Passwort-UTF-8).</summary>
    internal static Geheimpuffer Kopie(ReadOnlySpan<byte> bytes)
    {
        fixed (byte* quelle = bytes)
        {
            var q = (IntPtr)quelle;
            var n = bytes.Length;
            return Neu(n, ziel => new ReadOnlySpan<byte>((void*)q, n).CopyTo(ziel));
        }
    }

    /// <summary><paramref name="count"/> Zufallsbytes.</summary>
    internal static Geheimpuffer Zufall(int count) =>
        Neu(count, ziel =>
        {
            if (ziel.IsEmpty) { return; }
            fixed (byte* p = ziel) { Sodium.randombytes_buf(p, (nuint)ziel.Length); }
        });

    /// <summary>Veränderliche, genullte Rechenfläche.</summary>
    internal static Geheimpuffer Rechenflaeche(int count) => Neu(count, null, readOnly: false);

    /// <summary>Lesende Leihe (<see cref="Leihe.Span"/>, <see cref="Leihe.Zeiger"/>). Immer mit <c>using</c>: Die Leihe hält
    /// eine Referenz auf das Handle, ein paralleles <see cref="SafeHandle.Dispose()"/> (oder der Finalizer) gibt den
    /// Speicher erst nach ihrem Ende frei. Schon freigegeben → <c>Crypto("secure.disposed")</c>.</summary>
    internal Leihe Lesen()
    {
        Ausleihen();
        return new Leihe(this);
    }

    /// <summary>Schreibende Leihe, nur für Rechenflächen (sonst <c>Crypto("secure.readonly")</c>). Immer mit <c>using</c>.</summary>
    internal SchreibLeihe Schreiben()
    {
        if (readOnly) { throw new SiegelException(SiegelErrorCode.Crypto, "secure.readonly"); }
        Ausleihen();
        return new SchreibLeihe(this);
    }

    private void Ausleihen()
    {
        var added = false;
        try
        {
            DangerousAddRef(ref added);
        }
        catch (ObjectDisposedException)
        {
            throw new SiegelException(SiegelErrorCode.Crypto, "secure.disposed");
        }
    }

    /// <summary>Vergleich in konstanter Zeit (<c>sodium_memcmp</c>).</summary>
    internal bool KonstantGleich(ReadOnlySpan<byte> other)
    {
        if (other.Length != Length) { return false; }
        using var l = Lesen();
        if (Length == 0) { return true; }
        fixed (byte* b = other) { return Sodium.sodium_memcmp(l.Zeiger, b, (nuint)Length) == 0; }
    }

    /// <summary>Vergleich zweier Puffer in konstanter Zeit, beide über Leihen.</summary>
    internal bool KonstantGleich(Geheimpuffer other)
    {
        if (other is null) { return false; }
        using var l = other.Lesen();
        return KonstantGleich(l.Span);
    }

    protected override bool ReleaseHandle()
    {
        Sodium.sodium_free(handle);
        return true;
    }

    public override string ToString() => "Geheimpuffer(redacted)";

    /// <summary>Lesender Zugriff, solange die Leihe lebt (Gegenstück zu <c>SecureBuffer.Lease</c> im Kern).</summary>
    internal readonly ref struct Leihe
    {
        private readonly Geheimpuffer owner;

        internal Leihe(Geheimpuffer owner)
        {
            this.owner = owner;
            Zeiger = (byte*)owner.handle;
            Span = new ReadOnlySpan<byte>(Zeiger, owner.Length);
        }

        internal ReadOnlySpan<byte> Span { get; }

        /// <summary>Für P/Invoke, nur innerhalb der Leihe gültig.</summary>
        internal byte* Zeiger { get; }

        public void Dispose() => owner.DangerousRelease();
    }

    /// <summary>Schreibender Zugriff auf eine Rechenfläche, solange die Leihe lebt.</summary>
    internal readonly ref struct SchreibLeihe
    {
        private readonly Geheimpuffer owner;

        internal SchreibLeihe(Geheimpuffer owner)
        {
            this.owner = owner;
            Zeiger = (byte*)owner.handle;
            Span = new Span<byte>(Zeiger, owner.Length);
        }

        internal Span<byte> Span { get; }

        /// <summary>Für P/Invoke, nur innerhalb der Leihe gültig.</summary>
        internal byte* Zeiger { get; }

        public void Dispose() => owner.DangerousRelease();
    }
}
