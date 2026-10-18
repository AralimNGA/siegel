using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Siegel.Modell;

namespace Siegel.Core;

/// <summary>
/// Dateioperationen für das sichere Speichern (SPEC §4, SPEC-WINDOWS W3), Gegenstück zu FileIO.swift. Fehler nur als
/// feste Codes. Plattformteile:
/// <list type="bullet">
/// <item>Schreiben: <c>FileMode.CreateNew</c> + <c>FileOptions.WriteThrough</c> + <c>Flush(true)</c> (Windows
/// <c>FlushFileBuffers</c>, macOS <c>F_FULLFSYNC</c> über die .NET-Laufzeit), Unix-Rechte 0600 beim Anlegen.</item>
/// <item>Ersetzen: Windows <c>MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)</c> mit Pfaden wie .NET
/// (<see cref="ExtendedPath"/>) und kurzer Wiederholung bei fremden Sperren (<see cref="RetryTransient"/>), sonst
/// <c>File.Move(overwrite: true)</c> (= rename(2)).</item>
/// <item>Ordner: neu angelegte unter Windows mit geschützter ACL (Benutzer, eigene Paket-SID im AppContainer, SYSTEM),
/// Unix 0700; Ordner-fsync nur unter Unix (unter Windows deckt <c>MOVEFILE_WRITE_THROUGH</c> die Metadaten ab).</item>
/// </list>
/// Symbolische Links werden wie <c>O_NOFOLLOW</c> abgelehnt (<c>Io("file.read")</c>).
/// </summary>
internal static partial class FileIO
{
    /// <summary>Ziel existiert schon (exklusives Anlegen bzw. Umbenennen ohne Überschreiben).</summary>
    internal sealed class ExistsException : Exception
    {
        internal ExistsException() : base("exists")
        {
        }
    }

    private const UnixFileMode FileMode600 = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode DirMode700 = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

    // MARK: Ordner

    /// <summary>Legt Ordner (rekursiv) an. Jeder neu angelegte Ordner bekommt 0700 bzw. unter Windows eine geschützte ACL
    /// (<see cref="DirectoryAclSids"/>); bestehende Elternordner bleiben unberührt (wie im Swift-Kern). Ein bestehender
    /// Zielordner wird nur unter Unix auf 0700 gesetzt (Swift <c>chmod</c>); unter Windows bleibt seine ACL, wie sie ist
    /// (Befund robust-4: eine ACL nur für den Benutzer sperrte die App im AppContainer aus den eigenen Ordnern aus, und
    /// <c>SetAccessControl</c> verteilte sie bei jedem Speichern auf alle Dateien darin). <paramref name="restrictExisting"/>
    /// = false: einen bestehenden Ordner auf keinem System anfassen (Elternordner der Wächterdatei).</summary>
    internal static void EnsureDirectory(string path, bool restrictExisting = true)
    {
        if (File.Exists(path) && !Directory.Exists(path)) { throw Fehler.Io("dir.notDirectory"); }
        var created = false;
        try
        {
            var full = Path.GetFullPath(path);
            var missing = new Stack<string>();
            for (var p = full; p is not null && !Directory.Exists(p); p = Path.GetDirectoryName(p))
            {
                if (File.Exists(p)) { throw Fehler.Io("dir.notDirectory"); }
                missing.Push(p);
            }
            while (missing.TryPop(out var dir))
            {
                if (OperatingSystem.IsWindows())
                {
                    Directory.CreateDirectory(dir);
                }
                else
                {
                    Directory.CreateDirectory(dir, DirMode700);
                }
                RestrictDirectory(dir);
                created = true;
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw Fehler.Io("dir.create");
        }
        // Fehlte der Zielordner, ist er oben schon eingeschränkt (die Schleife legt ihn als letzten an).
        if (!created && restrictExisting && !OperatingSystem.IsWindows()) { RestrictDirectory(path); }
    }

    /// <summary>Kennung von SYSTEM (S-1-5-18): Dienste wie der AppX-Bereitstellungsdienst (Zurücksetzen, Deinstallation)
    /// laufen so.</summary>
    internal const string LocalSystemSid = "S-1-5-18";

    /// <summary>Wer in einem neu angelegten Ordner Vollzugriff bekommt (Windows, geschützte ACL, vererbt): der Benutzer,
    /// im AppContainer zusätzlich die eigene Paket-SID (ein AppContainer-Token braucht für jeden Zugriff beide), und
    /// SYSTEM. Andere Benutzer und Pakete nicht.</summary>
    internal static IReadOnlyList<string> DirectoryAclSids(string userSid, string? appContainerSid) =>
        appContainerSid is null ? [userSid, LocalSystemSid] : [userSid, appContainerSid, LocalSystemSid];

    /// <summary>Nur der Benutzer (und unter Windows die eigene App und SYSTEM, <see cref="DirectoryAclSids"/>) darf
    /// lesen/schreiben (bestes Bemühen wie <c>chmod</c> im Swift-Kern). Lässt sich unter Windows nicht feststellen, ob der
    /// Prozess in einem AppContainer läuft, bleibt die geerbte ACL (nie sich selbst aussperren).</summary>
    private static void RestrictDirectory(string path)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                RestrictDirectoryWindows(path);
            }
            else
            {
                File.SetUnixFileMode(path, DirMode700);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or SystemException)
        {
            // bestes Bemühen
        }
    }

    [SupportedOSPlatform("windows")]
    private static void RestrictDirectoryWindows(string path)
    {
        using var me = WindowsIdentity.GetCurrent();
        if (me.User is not { } user) { return; }
        if (!TryAppContainerSid(me, out var appContainer)) { return; }
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        foreach (var sid in DirectoryAclSids(user.Value, appContainer?.Value))
        {
            security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None,
                AccessControlType.Allow));
        }
        new DirectoryInfo(path).SetAccessControl(security);
    }

    /// <summary>Paket-SID des eigenen Tokens (<c>TokenIsAppContainer</c>, <c>TokenAppContainerSid</c>). true + null =
    /// kein AppContainer; false = nicht feststellbar.</summary>
    [SupportedOSPlatform("windows")]
    private static bool TryAppContainerSid(WindowsIdentity me, out SecurityIdentifier? appContainer)
    {
        appContainer = null;
        const int bufferBytes = 256; // TOKEN_APPCONTAINER_INFORMATION (Zeiger) + SID (höchstens 68 Byte)
        var buffer = Marshal.AllocHGlobal(bufferBytes);
        try
        {
            if (!GetTokenInformation(me.Token, TokenIsAppContainer, buffer, sizeof(int), out _)) { return false; }
            if (Marshal.ReadInt32(buffer) == 0) { return true; }
            if (!GetTokenInformation(me.Token, TokenAppContainerSid, buffer, bufferBytes, out _)) { return false; }
            var sid = Marshal.ReadIntPtr(buffer);
            if (sid == IntPtr.Zero) { return false; }
            appContainer = new SecurityIdentifier(sid);
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    internal static bool Exists(string path)
    {
        try
        {
            _ = File.GetAttributes(path);
            return true;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            // fehlt (FileNotFound/DirectoryNotFound) oder nicht prüfbar; ein gebrochener Link zählt als vorhanden
            return IsLink(path);
        }
    }

    private static bool IsLink(string path)
    {
        try
        {
            return new FileInfo(path).LinkTarget is not null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    // MARK: Lesen

    /// <summary>Liest eine ganze Datei (höchstens <paramref name="maxSize"/> Byte, sonst <c>CorruptFile("file.length")</c>).
    /// Fehlt sie → <c>VaultMissing</c>.</summary>
    internal static byte[] Read(string path, int maxSize)
    {
        using var stream = OpenForReading(path);
        long size;
        try
        {
            size = stream.Length;
        }
        catch (IOException)
        {
            throw Fehler.Io("file.read");
        }
        if (size > maxSize) { throw Fehler.Corrupt("file.length"); }
        var output = new byte[size];
        var done = 0;
        try
        {
            while (done < output.Length)
            {
                var n = stream.Read(output, done, output.Length - done);
                if (n == 0) { break; }
                done += n;
            }
            // Datei während des Lesens gekürzt → so viel wie gelesen; verlängert → Fehler (wie Swift).
            if (done != output.Length) { output = output[..done]; }
            if (stream.ReadByte() >= 0) { throw Fehler.Io("file.changedWhileReading"); }
        }
        catch (IOException)
        {
            throw Fehler.Io("file.read");
        }
        return output;
    }

    /// <summary>Höchstens <paramref name="count"/> Byte vom Dateianfang (Kopf).</summary>
    internal static byte[] ReadPrefix(string path, int count)
    {
        using var stream = OpenForReading(path);
        var output = new byte[count];
        var done = 0;
        try
        {
            while (done < count)
            {
                var n = stream.Read(output, done, count - done);
                if (n == 0) { break; }
                done += n;
            }
        }
        catch (IOException)
        {
            throw Fehler.Io("file.read");
        }
        return done == count ? output : output[..done];
    }

    private static FileStream OpenForReading(string path)
    {
        FileInfo info;
        try
        {
            info = new FileInfo(path);
            // O_NOFOLLOW: ein Link wird nie gelesen.
            if (info.LinkTarget is not null) { throw Fehler.Io("file.read"); }
            if (!info.Exists)
            {
                if (Directory.Exists(path)) { throw Fehler.Io("file.read"); }
                throw Fehler.VaultMissing();
            }
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or UnauthorizedAccessException or PathTooLongException)
        {
            throw Fehler.Io("file.read");
        }
        try
        {
            // Teilen mit Schreiben und Löschen: ein gleichzeitiges Ersetzen (rename) darf nicht am Lesen scheitern.
            return new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.Open,
                Access = FileAccess.Read,
                Share = FileShare.ReadWrite | FileShare.Delete,
                Options = FileOptions.SequentialScan,
            });
        }
        catch (Exception e) when (e is FileNotFoundException or DirectoryNotFoundException)
        {
            throw Fehler.VaultMissing();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw Fehler.Io("file.read");
        }
    }

    // MARK: Schreiben

    /// <summary>Neue Datei exklusiv (CreateNew, 0600), durchgeschrieben und synchronisiert. Existiert sie →
    /// <see cref="ExistsException"/>. Scheitert etwas, wird die halbe Datei entfernt.</summary>
    internal static void WriteExclusive(string path, ReadOnlySpan<byte> bytes)
    {
        var stream = CreateExclusive(path);
        var ok = false;
        try
        {
            try
            {
                stream.Write(bytes);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                throw Fehler.Io("file.write");
            }
            Sync(stream);
            ok = true;
        }
        finally
        {
            ok &= Close(stream);
            if (!ok) { RemoveTemp(path); }
        }
    }

    /// <summary>Optionen zum Schreiben (0600, durchschreibend, <b>ohne</b> FileStream-Puffer). <c>BufferSize = 0</c>: Sonst
    /// kopiert die BufferedFileStreamStrategy jedes Write unter 4 KiB zuerst in ihren eigenen verwalteten byte[], der beim
    /// Schliessen nicht genullt wird – beim CSV-Export lag so die ganze Klartext-Datei als UTF-8-Block im Heap (Befund
    /// hygiene-2), obwohl der Aufrufer seinen Puffer nullt. Ohne Puffer geht Write direkt ans Betriebssystem, wie
    /// Swift mit write(2).</summary>
    internal static FileStreamOptions WriteOptions(FileMode mode)
    {
        var options = new FileStreamOptions
        {
            Mode = mode,
            Access = FileAccess.Write,
            Share = FileShare.None,
            Options = FileOptions.WriteThrough,
            BufferSize = 0,
        };
        if (!OperatingSystem.IsWindows()) { options.UnixCreateMode = FileMode600; }
        return options;
    }

    /// <summary>Neue Datei exklusiv anlegen (CreateNew, 0600, durchschreibend, ungepuffert). Existiert sie →
    /// <see cref="ExistsException"/>, sonst <c>Io("file.create")</c>.</summary>
    internal static FileStream CreateExclusive(string path)
    {
        try
        {
            return new FileStream(path, WriteOptions(FileMode.CreateNew));
        }
        catch (IOException) when (Exists(path))
        {
            throw new ExistsException();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw Fehler.Io("file.create");
        }
    }

    private static void Sync(FileStream stream)
    {
        try
        {
            stream.Flush(flushToDisk: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw Fehler.Io("file.sync");
        }
    }

    /// <summary>Schliesst; false, wenn dabei noch ein Schreibfehler auftrat.</summary>
    private static bool Close(FileStream stream)
    {
        try
        {
            stream.Dispose();
            return true;
        }
        catch (IOException)
        {
            return false;
        }
    }

    /// <summary>Gestreamte Kopie ohne Grössengrenze, exklusiv angelegt wie <see cref="WriteExclusive"/> (0600 bzw. ACL des
    /// Ordners, durchgeschrieben, synchronisiert; nie überschreiben → <see cref="ExistsException"/>). Für die Sicherung
    /// einer unlesbaren Tresordatei als „beschaedigt-…“ (Befund robust-5): Swift klont sie per <c>clonefile</c> ohne
    /// Grenze, <see cref="Clone"/> liest höchstens <see cref="FileFormat.MaxFileBytes"/>. Die Quelle wird ohne Links
    /// geöffnet (<c>O_NOFOLLOW</c>); fehlt sie → <c>Io("backup.clone")</c>. Bleiben danach weniger als
    /// <paramref name="keepFree"/> Byte frei → <c>NotEnoughDiskSpace</c> (vor dem Schreiben). Scheitert etwas, wird die
    /// halbe Kopie entfernt.</summary>
    internal static void CopyExclusiveStreamed(string source, string destination, ulong keepFree)
    {
        if (Exists(destination)) { throw new ExistsException(); }
        FileStream input;
        try
        {
            input = OpenForReading(source);
        }
        catch (SiegelException e) when (e.Code == SiegelErrorCode.VaultMissing)
        {
            throw Fehler.Io("backup.clone");
        }
        using (input)
        {
            long length;
            try
            {
                length = input.Length;
            }
            catch (IOException)
            {
                throw Fehler.Io("file.read");
            }
            var folder = Path.GetDirectoryName(destination) is { Length: > 0 } d ? d : ".";
            if (FreeSpace(folder) is { } free && (ulong)length > free - Math.Min(free, keepFree)) { throw Fehler.NotEnoughDiskSpace(); }
            var output = CreateExclusive(destination);
            var ok = false;
            try
            {
                var buffer = new byte[1 << 20];
                while (true)
                {
                    int n;
                    try
                    {
                        n = input.Read(buffer, 0, buffer.Length);
                    }
                    catch (IOException)
                    {
                        throw Fehler.Io("file.read");
                    }
                    if (n == 0) { break; }
                    try
                    {
                        output.Write(buffer, 0, n);
                    }
                    catch (Exception e) when (e is IOException or UnauthorizedAccessException)
                    {
                        throw Fehler.Io("file.write");
                    }
                }
                Sync(output);
                ok = true;
            }
            finally
            {
                ok &= Close(output);
                if (!ok) { RemoveTemp(destination); }
            }
        }
    }

    /// <summary>Genau diese Datei schreiben (anlegen oder kürzen, 0600, ungepuffert) ohne Nachbardatei, synchronisiert. Nicht atomar:
    /// der Aufrufer liest zurück und vergleicht. Fehler → <c>Io("export.write")</c>.</summary>
    internal static void WriteInPlace(string path, ReadOnlySpan<byte> bytes)
    {
        try
        {
            if (IsLink(path)) { throw Fehler.Io("export.write"); }
            using var stream = new FileStream(path, WriteOptions(FileMode.Create));
            stream.Write(bytes);
            stream.Flush(flushToDisk: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw Fehler.Io("export.write");
        }
    }

    /// <summary>Kopie als Sicherung; scheitert bei vorhandenem Ziel (<see cref="ExistsException"/>), nie überschreiben.
    /// (APFS-Klone gibt es unter Windows nicht; gelesen wird mit derselben Grössengrenze wie die Tresordatei – nur für
    /// lesbare Tresordateien. Unlesbare sichert <see cref="CopyExclusiveStreamed"/> ohne Grenze.)</summary>
    internal static void Clone(string source, string destination)
    {
        if (Exists(destination)) { throw new ExistsException(); }
        byte[] bytes;
        try
        {
            bytes = Read(source, FileFormat.MaxFileBytes);
        }
        catch (SiegelException e) when (e.Code is SiegelErrorCode.VaultMissing or SiegelErrorCode.CorruptFile)
        {
            throw Fehler.Io("backup.clone");
        }
        WriteExclusive(destination, bytes);
    }

    /// <summary>Ersetzt das Ziel atomar (rename). Fehler → <c>Io("file.rename")</c>.</summary>
    internal static void Rename(string source, string destination)
    {
        if (OperatingSystem.IsWindows())
        {
            var src = ExtendedPath(source);
            var dst = ExtendedPath(destination);
            var error = RetryTransient(() => MoveFileEx(src, dst, MoveFileReplaceExisting | MoveFileWriteThrough) ? 0 : LastWin32Error());
            if (error != 0) { throw Fehler.Io("file.rename"); }
            return;
        }
        try
        {
            File.Move(source, destination, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw Fehler.Io("file.rename");
        }
    }

    /// <summary>Umbenennen ohne Überschreiben; existiert das Ziel → <see cref="ExistsException"/>.</summary>
    internal static void RenameExclusive(string source, string destination)
    {
        if (Exists(destination)) { throw new ExistsException(); }
        if (OperatingSystem.IsWindows())
        {
            var src = ExtendedPath(source);
            var dst = ExtendedPath(destination);
            // Vor jedem weiteren Versuch erneut prüfen: das Ziel kann inzwischen entstanden sein.
            var error = RetryTransient(() => Exists(destination) ? ErrorFileExists
                : MoveFileEx(src, dst, MoveFileWriteThrough) ? 0 : LastWin32Error());
            if (error == 0) { return; }
            if (error is ErrorFileExists or ErrorAlreadyExists) { throw new ExistsException(); }
            throw Fehler.Io("file.rename");
        }
        try
        {
            File.Move(source, destination, overwrite: false);
        }
        catch (IOException) when (Exists(destination))
        {
            throw new ExistsException();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw Fehler.Io("file.rename");
        }
    }

    /// <summary>Ordner synchronisieren (nach rename). Unix: <c>open</c> + <c>F_FULLFSYNC</c> bzw. <c>fsync</c>; Windows:
    /// nichts (die Metadaten schreibt <c>MOVEFILE_WRITE_THROUGH</c>). Fehler → <c>Io("dir.sync")</c>.</summary>
    internal static void SyncDirectory(string path)
    {
        if (OperatingSystem.IsWindows()) { return; }
        int fd;
        try
        {
            fd = PosixOpen(path, 0);
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException)
        {
            return;
        }
        if (fd < 0) { throw Fehler.Io("dir.sync"); }
        try
        {
            var rc = OperatingSystem.IsMacOS() ? PosixFcntl(fd, FFullFsync) : -1;
            if (rc != 0 && PosixFsync(fd) != 0) { throw Fehler.Io("dir.sync"); }
        }
        finally
        {
            _ = PosixClose(fd);
        }
    }

    /// <summary><see cref="SyncDirectory"/> ohne Fehler (wie <c>try?</c> im Swift-Kern).</summary>
    internal static void TrySyncDirectory(string path)
    {
        try
        {
            SyncDirectory(path);
        }
        catch (SiegelException)
        {
            // bestes Bemühen
        }
    }

    /// <summary>Freier Platz in Byte; null = unbekannt.</summary>
    internal static ulong? FreeSpace(string path)
    {
#if DEBUG
        if (TestHooks.FreeSpaceOverride is { } o) { return o; }
#endif
        try
        {
            var full = Path.GetFullPath(path);
            var drive = OperatingSystem.IsWindows() ? new DriveInfo(Path.GetPathRoot(full) ?? full) : new DriveInfo(full);
            return (ulong)Math.Max(0, drive.AvailableFreeSpace);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    // MARK: Entfernen, Auflisten

    internal static void Remove(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            // wie unlink ohne Prüfung
        }
    }

    /// <summary>Wie <see cref="Remove"/>, für Temp-Dateien und halbe Kopien eben gescheiterter Schreibvorgänge: unter
    /// Windows bei einer fremden Sperre (5/32) kurz wiederholt (<see cref="RetryTransient"/>, Befund robust-1), damit keine
    /// Reste liegen bleiben (im Hardware-Ordner räumt sie niemand auf).</summary>
    internal static void RemoveTemp(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            Remove(path);
            return;
        }
        _ = RetryTransient(() =>
        {
            try
            {
                File.Delete(path);
                return 0;
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                return Win32ErrorOf(e);
            }
            catch (Exception e) when (e is ArgumentException or NotSupportedException)
            {
                return -1;
            }
        });
    }

    // MARK: Windows: fremde Sperren und lange Pfade

    internal const int ErrorAccessDenied = 5;
    internal const int ErrorSharingViolation = 32;

    /// <summary>Gesamtdauer der Wiederholung bei fremden Sperren (wie Go <c>cmd/go/internal/robustio</c>).</summary>
    internal static readonly TimeSpan TransientRetryLimit = TimeSpan.FromSeconds(2);

    /// <summary>Vorübergehend? Defender, die Windows-Suche, Sicherungs-Agenten und die Explorer-Vorschau öffnen frisch
    /// geschriebene oder eben gelesene Dateien kurz ohne <c>FILE_SHARE_DELETE</c>; <c>MoveFileEx</c>/<c>DeleteFile</c>
    /// scheitern dann mit <c>ERROR_ACCESS_DENIED</c> (5) oder <c>ERROR_SHARING_VIOLATION</c> (32). rename(2) auf dem Mac
    /// kennt das nicht (Befund robust-1; Go, npm/graceful-fs, Git für Windows wiederholen deshalb).</summary>
    internal static bool IsTransientSharingError(int win32) => win32 is ErrorAccessDenied or ErrorSharingViolation;

    /// <summary>Ruft <paramref name="attempt"/> (0 = Erfolg, sonst Win32-Fehler) erneut auf, solange der Fehler
    /// vorübergehend ist (<see cref="IsTransientSharingError"/>) und <see cref="TransientRetryLimit"/> nicht um ist; Pause
    /// 10, 20, 40 … ms (höchstens 500). Liefert den letzten Fehler bzw. 0. <paramref name="sleep"/>/<paramref name="elapsed"/>
    /// nur für Tests.</summary>
    internal static int RetryTransient(Func<int> attempt, Action<int>? sleep = null, Func<TimeSpan>? elapsed = null)
    {
        var watch = elapsed is null ? Stopwatch.StartNew() : null;
        var pause = 10;
        while (true)
        {
            var error = attempt();
            if (error == 0 || !IsTransientSharingError(error)) { return error; }
            var left = TransientRetryLimit - (elapsed?.Invoke() ?? watch!.Elapsed);
            if (left <= TimeSpan.Zero) { return error; }
            var wait = (int)Math.Min(pause, Math.Ceiling(left.TotalMilliseconds));
            if (sleep is null) { Thread.Sleep(wait); } else { sleep(wait); }
            pause = Math.Min(pause * 2, 500);
        }
    }

    /// <summary>Win32-Fehler einer .NET-Dateiausnahme (HRESULT <c>0x8007xxxx</c>), sonst -1.</summary>
    internal static int Win32ErrorOf(Exception e) => ((uint)e.HResult & 0xFFFF_0000) == 0x8007_0000 ? e.HResult & 0xFFFF : -1;

    /// <summary>Letzter Fehler des eigenen P/Invoke (nie 0, damit ein Fehlschlag nie als Erfolg zählt).</summary>
    private static int LastWin32Error()
    {
        var error = Marshal.GetLastPInvokeError();
        return error == 0 ? -1 : error;
    }

    private const int MaxShortPath = 260;

    /// <summary>Pfad für eigene Win32-Aufrufe (<c>MoveFileExW</c>), so aufbereitet wie .NET es für FileStream, File.Delete
    /// und Co. selbst tut (<c>Path.GetFullPath</c>, dann <c>PathInternal.EnsureExtendedPrefixIfNeeded</c>). Ohne Präfix
    /// gälte für MoveFileExW die alte MAX_PATH-Grenze (<c>longPathAware</c> und <c>LongPathsEnabled</c> sind standardmässig
    /// aus), während WriteExclusive auf demselben Pfad gelingt (Befund robust-6).</summary>
    internal static string ExtendedPath(string path)
    {
        try
        {
            return ExtendedPathOf(Path.GetFullPath(path));
        }
        catch (Exception e) when (e is ArgumentException or NotSupportedException or IOException)
        {
            // ungültiger Pfad: unverändert, MoveFileExW meldet den Fehler selbst (nie eine fremde Ausnahme)
            return path;
        }
    }

    /// <summary>Für einen vollen Windows-Pfad: ab 260 Zeichen oder mit Punkt/Leerzeichen am Ende <c>\\?\</c> davor
    /// (<c>\\server\freigabe</c> → <c>\\?\UNC\server\freigabe</c>); Gerätepfade (<c>\\?\</c>, <c>\\.\</c>, <c>\??\</c>)
    /// und kürzere Pfade unverändert – wie .NET, damit beide Wege dieselbe Datei meinen.</summary>
    internal static string ExtendedPathOf(string full)
    {
        if (full.Length < MaxShortPath && !full.EndsWith('.') && !full.EndsWith(' ')) { return full; }
        if (IsDevicePath(full)) { return full; }
        if (full.StartsWith(@"\\", StringComparison.Ordinal)) { return @"\\?\UNC\" + full[2..]; }
        return @"\\?\" + full;
    }

    private static bool IsDevicePath(string p)
    {
        if (p.StartsWith(@"\??\", StringComparison.Ordinal)) { return true; }
        static bool Separator(char c) => c is '\\' or '/';
        return p.Length >= 4 && Separator(p[0]) && Separator(p[1]) && (p[2] is '.' or '?') && Separator(p[3]);
    }

    /// <summary>Entfernt eine Datei; true, wenn sie danach nicht mehr da ist (fehlte sie schon, zählt das als Erfolg).</summary>
    internal static bool RemoveChecked(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return !Exists(path);
        }
        return !Exists(path);
    }

    /// <summary>Dateien (keine Ordner, keine Links) eines Ordners, ordinal nach Namen sortiert. Fehlt der Ordner oder
    /// ist er nicht lesbar, leer.</summary>
    internal static IReadOnlyList<string> ListFiles(string directory)
    {
        try
        {
            return ListFilesChecked(directory);
        }
        catch (SiegelException)
        {
            return [];
        }
    }

    /// <summary>Wie <see cref="ListFiles"/>, wirft aber <c>Io("dir.read")</c>, wenn der Ordner nicht lesbar ist.</summary>
    internal static IReadOnlyList<string> ListFilesChecked(string directory)
    {
        try
        {
            var dir = new DirectoryInfo(directory);
            if (!dir.Exists) { throw Fehler.Io("dir.read"); }
            return [.. dir.EnumerateFiles()
                .Where(f => f.LinkTarget is null && (f.Attributes & FileAttributes.ReparsePoint) == 0)
                .Select(f => f.Name)
                .Order(StringComparer.Ordinal)
                .Select(n => Path.Combine(directory, n))];
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException
                                      or System.Security.SecurityException)
        {
            throw Fehler.Io("dir.read");
        }
    }

    internal static IReadOnlyList<string> ListDirectories(string directory)
    {
        try
        {
            var dir = new DirectoryInfo(directory);
            if (!dir.Exists) { return []; }
            return [.. dir.EnumerateDirectories()
                .Where(d => d.LinkTarget is null && (d.Attributes & FileAttributes.ReparsePoint) == 0)
                .Select(d => d.Name)
                .Order(StringComparer.Ordinal)
                .Select(n => Path.Combine(directory, n))];
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException
                                      or System.Security.SecurityException)
        {
            return [];
        }
    }

    /// <summary>Alter einer Datei in Sekunden (Änderungszeit); null, wenn nicht lesbar.</summary>
    internal static double? Age(string path, DateTimeOffset now)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) { return null; }
            return (now - new DateTimeOffset(info.LastWriteTimeUtc, TimeSpan.Zero)).TotalSeconds;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            return null;
        }
    }

    /// <summary>Von der Indizierung ausnehmen (Windows: <c>NotContentIndexed</c>, Gegenstück zu „.noindex“ und
    /// <c>isExcludedFromBackup</c> auf dem Mac). Unter anderen Systemen nichts. Fehler → <c>Io("export.excludeFromBackup")</c>.</summary>
    internal static void ExcludeFromIndexing(string path)
    {
        if (!OperatingSystem.IsWindows()) { return; }
        try
        {
            var attributes = File.GetAttributes(path);
            File.SetAttributes(path, attributes | FileAttributes.NotContentIndexed);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw Fehler.Io("export.excludeFromBackup");
        }
    }

    /// <summary>Datei mit Zufallsbytes gleicher Länge überschreiben, synchronisieren, löschen (Vernichten §23.1).
    /// true = danach weg.</summary>
    internal static bool OverwriteAndRemove(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (info.Exists && info.LinkTarget is null && info.Length > 0 && info.Length <= int.MaxValue)
            {
                // Rauschen (nicht geheim): Systemzufall genügt.
                var noise = RandomNumberGenerator.GetBytes((int)info.Length);
                using var stream = new FileStream(path, new FileStreamOptions
                {
                    Mode = FileMode.Open,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                    Options = FileOptions.WriteThrough,
                });
                stream.Write(noise);
                stream.Flush(flushToDisk: true);
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            // trotzdem löschen
        }
        return RemoveChecked(path);
    }

    // MARK: Plattform

    private const uint MoveFileReplaceExisting = 0x1;
    private const uint MoveFileWriteThrough = 0x8;
    private const int ErrorFileExists = 80;
    private const int ErrorAlreadyExists = 183;
    private const int FFullFsync = 51;

    [LibraryImport("kernel32.dll", EntryPoint = "MoveFileExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool MoveFileEx(string existingFileName, string newFileName, uint flags);

    private const int TokenIsAppContainer = 29;
    private const int TokenAppContainerSid = 31;

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTokenInformation(IntPtr token, int informationClass, IntPtr information, int length, out int returnLength);

    [LibraryImport("libc", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int PosixOpen(string path, int flags);

    [LibraryImport("libc", EntryPoint = "fcntl", SetLastError = true)]
    private static partial int PosixFcntl(int fd, int command);

    [LibraryImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static partial int PosixFsync(int fd);

    [LibraryImport("libc", EntryPoint = "close", SetLastError = true)]
    private static partial int PosixClose(int fd);
}
