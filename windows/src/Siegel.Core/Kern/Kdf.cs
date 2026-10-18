using System.Text;
using Siegel.Core.Native;
using Siegel.Werkzeuge.Unicode;

namespace Siegel.Core;

/// <summary>Argon2id-Parameter (opslimit = Durchläufe t, memlimit = Speicher in Byte, Parallelität fest 1).</summary>
public readonly record struct KdfParameters(uint OpsLimit, ulong MemLimitBytes)
{
    /// <summary>1 GiB, t = 3.</summary>
    public static KdfParameters Standard { get; } = new(3, 1UL << 30);

    /// <summary>2 GiB, t = 4.</summary>
    public static KdfParameters Strong { get; } = new(4, 2UL << 30);
}

/// <summary>Umgebung des Kerns, die die App setzt (plattformneutral, ohne Windows-Abhängigkeit).</summary>
public static class CoreEnvironment
{
    /// <summary>Liefert true auf dem Oberflächen-Thread. Argon2-Pfade werfen dort <c>Crypto("kdf.uiThread")</c>
    /// (Gegenstück zu <c>dispatchPrecondition(.notOnQueue(.main))</c>, SPEC §1.1). Die WinUI-App setzt das beim Start
    /// (z. B. <c>() =&gt; DispatcherQueue.GetForCurrentThread() is not null</c>); ohne Wert keine Prüfung.</summary>
    public static Func<bool>? IsUiThread { get; set; }

    internal static void RequireBackgroundThread()
    {
        if (IsUiThread?.Invoke() == true) { throw Fehler.Crypto("kdf.uiThread"); }
    }
}

/// <summary>Erlaubter Bereich der Argon2id-Parameter (SPEC §1.1). Geprüft vor jedem Ableiten und vor jedem Schreiben.</summary>
internal sealed record KdfLimits(ulong MinMem, ulong MaxMem, uint MinOps, uint MaxOps)
{
    /// <summary>256 MiB ≤ m ≤ 4 GiB, 3 ≤ t ≤ 10.</summary>
    internal static KdfLimits Production { get; } = new(256UL << 20, 4UL << 30, 3, 10);

#if DEBUG
    /// <summary>Testschalter: verschiebt den Bereich auf 8 KiB ≤ m ≤ 1 MiB, 1 ≤ t ≤ 3 (weiterhin mit Grenzen).</summary>
    internal static KdfLimits Testing { get; } = new(8UL << 10, 1UL << 20, 1, 3);
#endif

    internal void Validate(KdfParameters p)
    {
        if (p.MemLimitBytes < MinMem || p.MemLimitBytes > MaxMem || p.MemLimitBytes % 1024 != 0
            || p.OpsLimit < MinOps || p.OpsLimit > MaxOps)
        {
            throw Fehler.KdfOutOfRange();
        }
    }

    /// <summary>KDF-Profil einer Stufe (§13: Standard für 1–2, Stark für 3–5). Unter dem Testschalter auf den
    /// Testbereich verschoben (Standard → 8 KiB/t 1, Stark → 16 KiB/t 2), damit Stufenwechsel testbar bleiben.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static",
        Justification = "Im DEBUG-Bau hängt das Profil von dieser Instanz ab (Testschalter); im Release-Bau nicht.")]
    internal KdfParameters Profile(SecurityLevel level)
    {
#if DEBUG
        if (TestHooks.LevelKdfOverride is { } fixedProfile) { return fixedProfile; }
        if (this == Testing)
        {
            return level.Kdf() == KdfParameters.Strong ? new KdfParameters(2, 16UL << 10) : new KdfParameters(1, 8UL << 10);
        }
#endif
        return level.Kdf();
    }

    /// <summary>Schwächer als das Profil der Stufe (weniger Speicher oder weniger Durchläufe)?</summary>
    internal bool IsWeaker(KdfParameters p, SecurityLevel level)
    {
        var min = Profile(level);
        return p.MemLimitBytes < min.MemLimitBytes || p.OpsLimit < min.OpsLimit;
    }
}

/// <summary>Master-Passwort → p bzw. KEK_pw (Argon2id v1.3, 32 Byte).</summary>
internal static class Kdf
{
    internal const int SaltBytes = 16;
    internal const int KeyBytes = 32;

    /// <summary><c>crypto_pwhash</c> ≠ 0 → <c>KdfFailed</c> (nie <c>WrongPassword</c>). Nie auf dem Oberflächen-Thread.</summary>
    internal static unsafe SecureBuffer DeriveKek(SecureBuffer password, ReadOnlySpan<byte> salt, KdfParameters p, KdfLimits limits)
    {
        CoreEnvironment.RequireBackgroundThread();
        Libsodium.EnsureReady();
        limits.Validate(p);
        if (salt.Length != SaltBytes) { throw Fehler.Corrupt("header.salt"); }
        ulong ops = p.OpsLimit;
#if DEBUG
        if (TestHooks.ForceKdfFailure) { ops = 0; }
        TestHooks.KdfCounter?.Increment();
        TestHooks.BeforeArgon();
#endif
        if (p.MemLimitBytes > nuint.MaxValue) { throw Fehler.KdfFailed(); }
        var mem = (nuint)p.MemLimitBytes;
        var output = SecureBuffer.Scratch(KeyBytes);
        try
        {
            int rc;
            using (var o = output.BorrowWritable())
            using (var pw = password.Borrow())
            {
                fixed (byte* op = o.Span)
                fixed (byte* pp = pw.Span)
                fixed (byte* sp = salt)
                {
                    rc = Libsodium.crypto_pwhash(op, KeyBytes, pp, (ulong)pw.Span.Length, sp, ops, mem,
                        Libsodium.crypto_pwhash_alg_argon2id13());
                }
            }
            if (rc != 0) { throw Fehler.KdfFailed(); }
            output.Freeze();
            return output;
        }
        catch
        {
            output.Dispose();
            throw;
        }
    }
}

/// <summary>RFC 8265 OpaqueString (SPEC §1.1): Zs ausser U+0020 → U+0020, dann NFC. Nichts trimmen.</summary>
/// <remarks>
/// NFC genau wie Foundation <c>precomposedStringWithCanonicalMapping</c> auf dem Mac, aus der von Swift gemessenen Tabelle
/// (<see cref="SwiftText"/>, <c>SwiftNormalisierung</c>) – nie über <c>string.Normalize</c>: das hängt an der ICU des
/// Betriebssystems (andere Argon2-Bytes je Windows-Version, Unicode 16) und wirft bei U+FFFE eine ArgumentException,
/// die Swift annimmt (Befunde krypto-1, krypto-2). Ausnahmefrei für jede Eingabe.
/// </remarks>
internal static class PasswordNormalizer
{
    /// <summary>Einzelne Surrogate (in Swift-Strings unmöglich) werden vorher zu U+FFFD, wie es auch UTF-8 täte.</summary>
    internal static string Normalize(string s)
    {
        Fehler.NotNull(s);
        return SwiftText.OpaqueString(s);
    }

    /// <summary>Nur NFC (Formel des reuseTag bis v4.3), einzelne Surrogate vorher U+FFFD wie in <see cref="Normalize"/>.</summary>
    internal static string NfcOnly(string s)
    {
        Fehler.NotNull(s);
        return SwiftText.Nfc(s);
    }

    /// <summary>Normalisierte UTF-8-Bytes in <see cref="SecureBuffer"/>.</summary>
    internal static SecureBuffer SecureBytes(string s) => Utf8(Normalize(s));

    /// <summary>UTF-8 eines (schon abgebildeten) Strings direkt in sicheren Speicher.</summary>
    internal static SecureBuffer Utf8(string s)
    {
        var n = Encoding.UTF8.GetByteCount(s);
        var b = SecureBuffer.Scratch(n);
        try
        {
            using (var w = b.BorrowWritable()) { _ = Encoding.UTF8.GetBytes(s, w.Span); }
            b.Freeze();
            return b;
        }
        catch
        {
            b.Dispose();
            throw;
        }
    }
}
