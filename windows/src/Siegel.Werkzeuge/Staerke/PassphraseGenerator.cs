using Siegel.Werkzeuge.Staerke.Zxcvbn;

namespace Siegel.Werkzeuge;

/// <summary>
/// Schlägt eine Passphrase vor (SPEC §1.6): Wörter gleichverteilt per <c>randombytes_uniform</c> aus der gebündelten
/// deutschen Liste mit genau 2048 Wörtern (4–8 Kleinbuchstaben a–z), getrennt mit "-". 6 Wörter = 66 Bit.
/// Gleiche Liste und gleiche Regel wie Sources/SiegelCore/Staerke/PassphraseGenerator.swift.
/// </summary>
public static class PassphraseGenerator
{
    public const int WordListCount = 2048;

    /// <summary>Die Wortliste (genau <see cref="WordListCount"/> Einträge, siehe Tests).</summary>
    internal static readonly IReadOnlyList<string> Words = ZxcvbnListData.Lines(ZxcvbnListData.Lesen("passphraseWords"));

    /// <summary>Höchstens so oft neu ziehen, falls eine Passphrase trotz voller Entropie unter der Regel läge.</summary>
    internal const int MaximumDraws = 64;

    public static string Generate(int words = 6)
    {
        if (words <= 0 || Words.Count == 0) { return ""; }
        // Ab 6 Wörtern (≥ 60 Bit Entropie) soll der Vorschlag die Master-Passwort-Regel immer erfüllen. Sechs sehr
        // häufige Wörter lägen darunter (extrem selten), darum wird dann neu gezogen.
        var mustPass = EntropyBits(words) >= MasterPasswordPolicy.MinimumBits;
        var phrase = Draw(words);
        var attempts = 1;
        while (mustPass && attempts < MaximumDraws && PasswordStrength.Estimate(phrase).Bits < MasterPasswordPolicy.MinimumBits)
        {
            phrase = Draw(words);
            attempts++;
        }
        return phrase;
    }

    public static double EntropyBits(int words) => Math.Max(0, words) * Math.Log2(WordListCount);

    /// <summary><paramref name="count"/> Wörter gleichverteilt, mit "-" verbunden.</summary>
    internal static string Draw(int count)
    {
        var list = Words;
        var parts = new string[count];
        for (var i = 0; i < count; i++)
        {
            parts[i] = list[(int)Sodium.Uniform((uint)list.Count)];
        }
        return string.Join('-', parts);
    }
}
