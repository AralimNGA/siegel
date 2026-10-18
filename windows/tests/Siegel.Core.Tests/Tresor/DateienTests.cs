#if DEBUG
using Siegel.Modell;

namespace Siegel.Core.Tests.Kern;

/// <summary>Dateiprimitive des Tresors (FileIO, SPEC §4/W3): exklusiv anlegen, Rechte, Links nie folgen, Ersetzen,
/// Klonen, Auflisten, Überschreiben-und-Löschen; dazu FileRollbackGuard über mehrere Instanzen.</summary>
public class DateienTests
{
    private static bool Unix => !OperatingSystem.IsWindows();

    private const UnixFileMode Rw = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode Rwx = Rw | UnixFileMode.UserExecute;

    /// <summary>Unix-Rechte prüfen (unter Windows regelt das die ACL, siehe FileIO).</summary>
    private static void Mode(string path, UnixFileMode expected)
    {
        if (OperatingSystem.IsWindows()) { return; }
        Assert.Equal(expected, File.GetUnixFileMode(path));
    }

    [Fact]
    public void Exklusiv_anlegen_0600_zweites_Mal_Exists_Lesen_mit_Grenze()
    {
        using var d = new KernTempDir();
        var p = Path.Combine(d.Path, "a.bin");
        FileIO.WriteExclusive(p, [1, 2, 3]);
        Mode(p, Rw);
        Assert.Throws<FileIO.ExistsException>(() => FileIO.WriteExclusive(p, [9]));
        Assert.Equal([1, 2, 3], FileIO.Read(p, 3));
        KT.Corrupt("file.length", () => FileIO.Read(p, 2));
        Assert.Equal([1, 2], FileIO.ReadPrefix(p, 2));
        Assert.Equal([1, 2, 3], FileIO.ReadPrefix(p, 10));
        KT.Throws(SiegelErrorCode.VaultMissing, () => FileIO.Read(Path.Combine(d.Path, "fehlt"), 10));
        KT.Throws(SiegelErrorCode.Io, "file.read", () => FileIO.Read(d.Path, 10));
        // Ordner fehlt → Anlegen scheitert mit festem Code.
        KT.Throws(SiegelErrorCode.Io, "file.create", () => FileIO.WriteExclusive(Path.Combine(d.Path, "x", "y.bin"), [1]));
    }

    [Fact]
    public void Links_werden_nie_gelesen_nicht_aufgelistet_und_nur_selbst_entfernt()
    {
        if (!Unix) { return; } // Symbolische Links brauchen unter Windows Rechte (Entwicklermodus).
        using var d = new KernTempDir();
        var ziel = Path.Combine(d.Path, "ziel.bin");
        File.WriteAllBytes(ziel, [7, 7, 7]);
        var link = Path.Combine(d.Path, "link.bin");
        File.CreateSymbolicLink(link, ziel);
        KT.Throws(SiegelErrorCode.Io, "file.read", () => FileIO.Read(link, 10));
        Assert.Equal([ziel], FileIO.ListFiles(d.Path));
        // Ein gebrochener Link zählt als vorhanden (nichts darf ihn überschreiben).
        var kaputt = Path.Combine(d.Path, "kaputt.bin");
        File.CreateSymbolicLink(kaputt, Path.Combine(d.Path, "gibt-es-nicht"));
        Assert.True(FileIO.Exists(kaputt));
        Assert.Throws<FileIO.ExistsException>(() => FileIO.WriteExclusive(kaputt, [1]));
        Assert.Throws<FileIO.ExistsException>(() => FileIO.Clone(ziel, kaputt));
        // Überschreiben-und-Löschen folgt dem Link nicht: der Link geht, das Ziel bleibt unverändert.
        Assert.True(FileIO.OverwriteAndRemove(link));
        Assert.False(FileIO.Exists(link));
        Assert.Equal([7, 7, 7], File.ReadAllBytes(ziel));
        KT.Throws(SiegelErrorCode.Io, "export.write", () => FileIO.WriteInPlace(kaputt, [1]));
    }

    [Fact]
    public void Ersetzen_Umbenennen_ohne_Ueberschreiben_Klonen()
    {
        using var d = new KernTempDir();
        var a = Path.Combine(d.Path, "a");
        var b = Path.Combine(d.Path, "b");
        File.WriteAllBytes(a, [1]);
        File.WriteAllBytes(b, [2]);
        Assert.Throws<FileIO.ExistsException>(() => FileIO.RenameExclusive(a, b));
        Assert.Equal([1], File.ReadAllBytes(a));
        FileIO.Rename(a, b);
        Assert.False(File.Exists(a));
        Assert.Equal([1], File.ReadAllBytes(b));
        KT.Throws(SiegelErrorCode.Io, "file.rename", () => FileIO.Rename(a, b));
        var c = Path.Combine(d.Path, "c");
        FileIO.RenameExclusive(b, c);
        Assert.Equal([1], File.ReadAllBytes(c));
        var k = Path.Combine(d.Path, "k");
        FileIO.Clone(c, k);
        Assert.Equal([1], File.ReadAllBytes(k));
        Mode(k, Rw);
        Assert.Throws<FileIO.ExistsException>(() => FileIO.Clone(c, k));
        KT.Throws(SiegelErrorCode.Io, "backup.clone", () => FileIO.Clone(Path.Combine(d.Path, "fehlt"), Path.Combine(d.Path, "k2")));
        FileIO.SyncDirectory(d.Path);
        FileIO.TrySyncDirectory(Path.Combine(d.Path, "fehlt"));
    }

    [Fact]
    public void Ordner_jede_neue_Ebene_nur_fuer_den_Benutzer_Datei_statt_Ordner_abgelehnt()
    {
        using var d = new KernTempDir();
        var tief = Path.Combine(d.Path, "eins", "zwei", "drei");
        FileIO.EnsureDirectory(tief);
        Assert.True(Directory.Exists(tief));
        foreach (var p in new[] { Path.Combine(d.Path, "eins"), Path.Combine(d.Path, "eins", "zwei"), tief }) { Mode(p, Rwx); }
        FileIO.EnsureDirectory(tief);
        var datei = Path.Combine(d.Path, "datei");
        File.WriteAllBytes(datei, [1]);
        KT.Throws(SiegelErrorCode.Io, "dir.notDirectory", () => FileIO.EnsureDirectory(datei));
        KT.Throws(SiegelErrorCode.Io, "dir.notDirectory", () => FileIO.EnsureDirectory(Path.Combine(datei, "unter")));
    }

    [Fact]
    public void Auflisten_sortiert_ohne_Ordner_fehlender_Ordner_leer_bzw_Io()
    {
        using var d = new KernTempDir();
        foreach (var n in new[] { "b", "a", "C", "ä" }) { File.WriteAllBytes(Path.Combine(d.Path, n), [1]); }
        d.Sub("ordner");
        Assert.Equal(["C", "a", "b", "ä"], FileIO.ListFiles(d.Path).Select(Path.GetFileName));
        Assert.Equal([Path.Combine(d.Path, "ordner")], FileIO.ListDirectories(d.Path));
        var fehlt = Path.Combine(d.Path, "fehlt");
        Assert.Empty(FileIO.ListFiles(fehlt));
        Assert.Empty(FileIO.ListDirectories(fehlt));
        KT.Throws(SiegelErrorCode.Io, "dir.read", () => FileIO.ListFilesChecked(fehlt));
        Assert.True(FileIO.RemoveChecked(fehlt));
        Assert.Null(FileIO.Age(fehlt, DateTimeOffset.UtcNow));
        var age = FileIO.Age(Path.Combine(d.Path, "a"), DateTimeOffset.UtcNow.AddMinutes(2));
        Assert.InRange(age!.Value, 60, 600);
    }

    [Fact]
    public void Ueberschreiben_und_Loeschen_und_an_Ort_schreiben()
    {
        using var d = new KernTempDir();
        var p = Path.Combine(d.Path, "v.siegelhw");
        File.WriteAllBytes(p, KT.Repeat(0x41, 32));
        Assert.True(FileIO.OverwriteAndRemove(p));
        Assert.False(File.Exists(p));
        Assert.True(FileIO.OverwriteAndRemove(p));
        var e = Path.Combine(d.Path, "export.siegel");
        FileIO.WriteInPlace(e, [1, 2]);
        FileIO.WriteInPlace(e, [3]);
        Assert.Equal([3], File.ReadAllBytes(e));
        Mode(e, Rw);
        Assert.NotNull(FileIO.FreeSpace(d.Path));
    }

    [Fact]
    public void FileRollbackGuard_ueber_Instanzen_nur_steigend_kaputte_Datei_vergisst_nichts_Fremdes()
    {
        using var d = new KernTempDir();
        var path = Path.Combine(d.Path, "Siegel", "generationen.txt");
        var a = Guid.NewGuid();
        var b = Guid.NewGuid();
        var g1 = new FileRollbackGuard(path);
        Assert.Null(g1.LastSeenGeneration(a));
        g1.Record(a, 5);
        g1.Record(b, 2);
        g1.Record(a, 3);
        var g2 = new FileRollbackGuard(path);
        Assert.Equal(5UL, g2.LastSeenGeneration(a));
        Assert.Equal(2UL, g2.LastSeenGeneration(b));
        g2.Record(b, 9);
        Assert.Equal(9UL, new FileRollbackGuard(path).LastSeenGeneration(b));
        Assert.Equal(5UL, new FileRollbackGuard(path).LastSeenGeneration(a));
        // Kaputte Zeilen zählen nicht, die übrigen bleiben.
        File.AppendAllText(path, "keine-uuid 7\n" + Bytes.GuidText(Guid.NewGuid()) + " -1\n");
        var g3 = new FileRollbackGuard(path);
        Assert.Equal(5UL, g3.LastSeenGeneration(a));
        Assert.Equal(9UL, g3.LastSeenGeneration(b));
    }
}
#endif
