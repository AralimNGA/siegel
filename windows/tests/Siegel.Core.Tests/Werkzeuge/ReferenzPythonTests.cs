using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Siegel.Modell;
using Xunit.Abstractions;

namespace Siegel.Werkzeuge.Tests;

/// <summary>
/// Gegenprobe C# ↔ Python (SPEC §19/§21): Die unabhängige Python-Referenz referenz/siegel_referenz.py liest einen
/// KeePass-Export aus C# byte-genau. Läuft, wenn Python 3 (SIEGEL_PYTHON, Python.org 3.12 oder python3/python im PATH)
/// vorhanden ist; libsodium kommt aus SIEGEL_LIBSODIUM oder dem NuGet-Paket im Ausgabeordner. Sonst meldet der Test
/// nur, dass er nicht laufen konnte (Ausgabe), und gilt als bestanden – auf dem Mac läuft er immer.
/// </summary>
public class ReferenzPythonTests(ITestOutputHelper ausgabe)
{
    private static string? Python()
    {
        var kandidaten = new List<string>();
        if (Environment.GetEnvironmentVariable("SIEGEL_PYTHON") is { Length: > 0 } eigen) { kandidaten.Add(eigen); }
        kandidaten.Add("/Library/Frameworks/Python.framework/Versions/3.12/bin/python3");
        kandidaten.Add("python3");
        kandidaten.Add("python");
        foreach (var k in kandidaten)
        {
            if (Path.IsPathRooted(k) && !File.Exists(k)) { continue; }
            try
            {
                using var p = Process.Start(new ProcessStartInfo(k, "-c \"import sys; print(sys.version_info[0])\"")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                });
                if (p is null) { continue; }
                var text = p.StandardOutput.ReadToEnd().Trim();
                p.WaitForExit(10_000);
                if (p.ExitCode == 0 && text == "3") { return k; }
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // nicht vorhanden
            }
        }
        return null;
    }

    private static string? Libsodium()
    {
        if (Environment.GetEnvironmentVariable("SIEGEL_LIBSODIUM") is { Length: > 0 } eigen) { return eigen; }
        var name = OperatingSystem.IsWindows() ? "libsodium.dll" : OperatingSystem.IsMacOS() ? "libsodium.dylib" : "libsodium.so";
        var pfad = Path.Combine(AppContext.BaseDirectory, "runtimes", RuntimeInformation.RuntimeIdentifier, "native", name);
        return File.Exists(pfad) ? pfad : null;
    }

    private static (int Exit, string Stdout, string Stderr) Lauf(string python, string skript, string datei, string libsodium, string passwort)
    {
        var start = new ProcessStartInfo(python)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardOutputEncoding = Encoding.UTF8,
        };
        start.ArgumentList.Add("-I");
        start.ArgumentList.Add(skript);
        start.ArgumentList.Add("kdbx");
        start.ArgumentList.Add(datei);
        start.Environment["SIEGEL_LIBSODIUM"] = libsodium;
        start.Environment["PYTHONIOENCODING"] = "utf-8";
        using var p = Process.Start(start) ?? throw new InvalidOperationException("python");
        using (var stdin = p.StandardInput.BaseStream)
        {
            stdin.Write(Encoding.UTF8.GetBytes(passwort));
        }
        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();
        p.WaitForExit(120_000);
        return (p.ExitCode, stdout, stderr);
    }

    [Fact]
    public void PythonLiestKeePassExportAusCsharp()
    {
        var python = Python();
        var libsodium = Libsodium();
        var paket = Testdaten.Paket();
        var skript = paket is null ? null : Path.Combine(paket, "referenz", "siegel_referenz.py");
        if (python is null || libsodium is null || skript is null || !File.Exists(skript))
        {
            ausgabe.WriteLine("übersprungen: Python 3, libsodium oder referenz/siegel_referenz.py fehlt");
            return;
        }
        var items = KdbxHilfe.Beispiele();
        var datei = Path.Combine(Path.GetTempPath(), $"siegel-export-{Guid.NewGuid():N}.kdbx");
        File.WriteAllBytes(datei, KdbxHilfe.Export(items));
        try
        {
            var (exit, stdout, stderr) = Lauf(python, skript, datei, libsodium, KdbxHilfe.Passwort);
            Assert.True(exit == 0, stderr);
            using var json = JsonDocument.Parse(stdout);
            var wurzel = json.RootElement;
            Assert.Equal("4.1", wurzel.GetProperty("version").GetString());
            Assert.Equal("Siegel", wurzel.GetProperty("generator").GetString());
            var kdf = wurzel.GetProperty("kdf");
            Assert.Equal(64UL << 10, kdf.GetProperty("M").GetUInt64());
            Assert.Equal(1, kdf.GetProperty("P").GetInt32());
            Assert.Equal(16, kdf.GetProperty("salzLaenge").GetInt32());
            var gruppe = wurzel.GetProperty("gruppe");
            Assert.Equal("Siegel", gruppe.GetProperty("name").GetString());
            var eintraege = gruppe.GetProperty("eintraege").EnumerateArray().ToList();
            Assert.Equal(items.Count, eintraege.Count);
            for (var i = 0; i < items.Count; i++)
            {
                var (entry, secrets) = items[i];
                var py = eintraege[i];
                var werte = py.GetProperty("werte");
                string Wert(string name) => werte.TryGetProperty(name, out var w) ? w.GetString() ?? "-" : "-";
                Assert.Equal(entry.Id.ToString().ToUpperInvariant(), py.GetProperty("uuid").GetString());
                Assert.Equal(KdbxHilfe.Utf8(entry.Title), KdbxHilfe.Utf8(Wert("Title")));
                Assert.Equal(KdbxHilfe.Utf8(entry.Username), KdbxHilfe.Utf8(Wert("UserName")));
                Assert.Equal(KdbxHilfe.Utf8(secrets.Password), KdbxHilfe.Utf8(Wert("Password")));
                Assert.Equal(KdbxHilfe.Utf8(entry.Url), KdbxHilfe.Utf8(Wert("URL")));
                Assert.Equal(KdbxHilfe.Utf8(secrets.Notes), KdbxHilfe.Utf8(Wert("Notes")));
                var otp = KeePassExport.OtpValue(secrets.Totp, entry.Title);
                Assert.Equal(otp.Length == 0 ? "-" : otp, Wert("otp"));
                Assert.Contains("Password", py.GetProperty("geschuetzt").EnumerateArray().Select(e => e.GetString()));
                Assert.Equal(entry.Created.ToUnixTimeSeconds(), py.GetProperty("erstellt").GetInt64());
                Assert.Equal(entry.Modified.ToUnixTimeSeconds(), py.GetProperty("geaendert").GetInt64());
                Assert.Equal(0, py.GetProperty("verlauf").GetInt32());
            }
            // Falsches Passwort scheitert in Python am Kopf-HMAC
            var falsch = Lauf(python, skript, datei, libsodium, KdbxHilfe.Passwort + "x");
            Assert.NotEqual(0, falsch.Exit);
            Assert.Contains("kdbx.passwortOderKopf", falsch.Stderr, StringComparison.Ordinal);
            ausgabe.WriteLine($"Python-Referenz gelesen ({python})");
        }
        finally
        {
            File.Delete(datei);
        }
    }

    [Fact]
    public void VersiegelteEintraegeNurMitEntrySecrets()
    {
        // Ergänzung zur Python-Probe: Schutz 4/5 fehlt auch dann, wenn EntrySecrets mitgegeben werden.
        var maximal = KdbxHilfe.Eintrag("M", password: "x", protection: EntryProtection.Maximal);
        var datei = KdbxLeser.Lesen(KdbxHilfe.Export([(maximal, new EntrySecrets { Password = "x" })]), KdbxHilfe.Passwort);
        Assert.Empty(datei.Eintraege);
    }
}
