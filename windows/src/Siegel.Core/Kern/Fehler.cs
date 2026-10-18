using System.Globalization;
using Siegel.Modell;

namespace Siegel.Core;

/// <summary>
/// Fabrik für <see cref="SiegelException"/> mit festen Codes (SPEC §5, SPEC-WINDOWS W3). Detail-Codes sind dieselben
/// Zeichenketten wie im Swift-Kern (<c>"header.length"</c>, <c>"file.checksum"</c> …), nie Inhalte.
/// Swift-Fälle mit Nutzlast: <c>factorMissing(kind)</c> → Detail = <see cref="FactorKindExtensions.Code"/>
/// (<c>"secureEnclave"</c>, <c>"card"</c>, <c>"securityKey"</c>); <c>unsupportedVersion(n)</c> → Detail = Zahl.
/// </summary>
internal static class Fehler
{
    internal static SiegelException Corrupt(string code) => new(SiegelErrorCode.CorruptFile, code);

    internal static SiegelException Crypto(string code) => new(SiegelErrorCode.Crypto, code);

    internal static SiegelException Io(string code) => new(SiegelErrorCode.Io, code);

    internal static SiegelException WrongPassword() => new(SiegelErrorCode.WrongPassword);

    internal static SiegelException WrongCard() => new(SiegelErrorCode.WrongCard);

    internal static SiegelException KdfOutOfRange() => new(SiegelErrorCode.KdfParametersOutOfRange);

    internal static SiegelException KdfFailed() => new(SiegelErrorCode.KdfFailed);

    internal static SiegelException InvalidCodeFormat() => new(SiegelErrorCode.InvalidRecoveryCodeFormat);

    internal static SiegelException CodeChecksum() => new(SiegelErrorCode.RecoveryCodeChecksum);

    internal static SiegelException NotAllowedAtLevel() => new(SiegelErrorCode.NotAllowedAtLevel);

    internal static SiegelException FactorMissing(FactorKind kind) => new(SiegelErrorCode.FactorMissing, kind.Code());

    /// <summary>Faktor nicht nutzbar (Schlüssel fehlt, anderes Gerät, fremder Fehler des Anbieters); Detail = Art.</summary>
    internal static SiegelException FactorUnavailable(FactorKind kind) => new(SiegelErrorCode.FactorUnavailable, kind.Code());

    internal static SiegelException FactorCancelled() => new(SiegelErrorCode.FactorCancelled);

    internal static SiegelException PasswordTooWeak(double bits) => new(SiegelErrorCode.PasswordTooWeak) { Bits = bits };

    internal static SiegelException MasterPasswordReused() => new(SiegelErrorCode.MasterPasswordReused);

    internal static SiegelException ConfirmationMismatch() => new(SiegelErrorCode.RecoveryConfirmationMismatch);

    internal static SiegelException VaultMissing() => new(SiegelErrorCode.VaultMissing);

    internal static SiegelException VaultAlreadyExists() => new(SiegelErrorCode.VaultAlreadyExists);

    internal static SiegelException VaultChangedOnDisk() => new(SiegelErrorCode.VaultChangedOnDisk);

    internal static SiegelException NotEnoughDiskSpace() => new(SiegelErrorCode.NotEnoughDiskSpace);

    /// <summary>Exportziel abgelehnt (fester Code, z. B. <c>"icloud"</c>, <c>"onedrive"</c>).</summary>
    internal static SiegelException ExportLocationRejected(string code) => new(SiegelErrorCode.ExportLocationRejected, code);

    /// <summary>Gesperrt: nichts geschrieben (Befund datei-1).</summary>
    internal static SiegelException Locked() => Io("vault.locked");

    internal static SiegelException UnsupportedVersion(ushort version) =>
        new(SiegelErrorCode.UnsupportedVersion, version.ToString(CultureInfo.InvariantCulture));

    /// <summary>Formal gültiger Code eines anderen Kits; beide Kit-Kennungen sind nicht geheim.</summary>
    internal static SiegelException WrongRecoveryCode(string codeKit, string vaultKit) =>
        new(SiegelErrorCode.WrongRecoveryCode) { CodeKit = codeKit, VaultKit = vaultKit };

    /// <summary>Null-Argument an einer öffentlichen Schnittstelle (Programmfehler) → fester Code statt
    /// ArgumentNullException (nur SiegelException nach aussen, SPEC §5).</summary>
    internal static void NotNull([System.Diagnostics.CodeAnalysis.NotNull] object? value)
    {
        if (value is null) { throw Crypto("argument.null"); }
    }

    /// <summary>Gleicher Fehler wie Swift-<c>==</c>: Code, Detail und (bei WrongRecoveryCode) Kit-Kennungen.</summary>
    internal static bool SameAs(this SiegelException a, SiegelException b) =>
        a.Code == b.Code && a.Detail == b.Detail && a.CodeKit == b.CodeKit && a.VaultKit == b.VaultKit
        && a.Bits == b.Bits && a.Line == b.Line;
}
