using System.Runtime.InteropServices;
using Siegel.Werkzeuge;

namespace Siegel.Core.Tests;

public class SodiumTests
{
    [Fact]
    public void LibsodiumStartetInVersion1_0_22()
    {
        Sodium.EnsureReady();
        Assert.Equal("1.0.22", Marshal.PtrToStringAnsi(Sodium.sodium_version_string()));
    }
}
