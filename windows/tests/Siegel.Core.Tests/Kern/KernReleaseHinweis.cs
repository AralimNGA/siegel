#if !DEBUG
namespace Siegel.Core.Tests.Kern;

/// <summary>Im Release-Bau fehlen die Testschalter (KDF-Testbereich, Zähler, Testausgaben): die Kern-Tests laufen nur
/// mit <c>dotnet test</c> im Standard-Bau (Debug), wie die Swift-Tests.</summary>
public class KernReleaseHinweis
{
    [Fact(Skip = "Kern-Tests brauchen den DEBUG-Bau (Testschalter wie im Swift-Kern)")]
    public void Kern_Tests_nur_im_Debug_Bau() { }
}
#endif
