using System.Globalization;
using System.Security.Cryptography;
using Siegel.Modell;

namespace Siegel.Core;

/// <summary>
/// Tresordatei, Sicherungen und alle Wege, einen Tresor zu öffnen oder zu ersetzen (SPEC §4, §8, §22, §23.3) –
/// C#-Gegenstück zu VaultStore.swift (+Zugang, +Notfall, +Vernichtung). Threadsicher; schwere Aufrufe (Argon2,
/// Code-Korrektur) sind synchron und gehören nicht auf den Oberflächen-Thread (die App ruft sie über <c>Task.Run</c>).
/// </summary>
public sealed partial class VaultStore
{
    internal const string VaultFileName = "Tresor.siegel";
    internal const string BackupFolderName = "Sicherungen";
    internal const string HardwareFolderName = "Hardware";
    internal const string HardwareKeyExtension = "siegelhw";
    internal const ulong MinimumFreeSpace = 64UL << 20;
    internal static readonly TimeSpan ExternalInterval = TimeSpan.FromHours(1);

    private readonly Lock secondaryGate = new();
    private string? secondary;
    private SecondaryBackupResult? secondaryResult;
    private IDestructionKeyEraser eraser = new FileDestructionKeyEraser();

    /// <summary>Temp-Reste im Datenordner werden beim ersten Schreiben dieser Instanz aufgeräumt.</summary>
    private bool tempsCleaned;

    /// <summary>Serialisiert alle Schreibvorgänge dieses Stores (Schritte 0–7).</summary>
    private readonly Lock writeLock = new();

    /// <summary>Serialisiert Lesen-Ändern-Schreiben von <c>Hardware/zustand.json</c> und das Vernichten (§23).</summary>
    internal readonly Lock DestructionLock = new();

    /// <param name="directory">Datenordner (Windows: <c>ApplicationData.LocalFolder\Siegel</c>, W8).</param>
    /// <param name="rollbackGuard">Stolperdraht (§4); Tests: <see cref="InMemoryRollbackGuard"/>.</param>
    public VaultStore(string directory, IRollbackGuard rollbackGuard)
        : this(directory, rollbackGuard, KdfLimits.Production, TimeSpan.FromSeconds(2))
    {
    }

    internal VaultStore(string directory, IRollbackGuard rollbackGuard, KdfLimits limits, TimeSpan corruptRetryDelay)
    {
        Fehler.NotNull(directory);
        Fehler.NotNull(rollbackGuard);
        DirectoryPath = Path.GetFullPath(directory);
        RollbackGuard = rollbackGuard;
        Limits = limits;
        CorruptRetryDelay = corruptRetryDelay;
    }

#if DEBUG
    /// <summary>Nur Tests: <paramref name="testKdf"/> verschiebt den KDF-Bereich (8 KiB…1 MiB, t 1…3).</summary>
    internal static VaultStore ForTesting(string directory, IRollbackGuard rollbackGuard, bool testKdf = true,
        TimeSpan? corruptRetryDelay = null) =>
        new(directory, rollbackGuard, testKdf ? KdfLimits.Testing : KdfLimits.Production, corruptRetryDelay ?? TimeSpan.Zero);
#endif

    internal string DirectoryPath { get; }
    internal IRollbackGuard RollbackGuard { get; }
    internal KdfLimits Limits { get; }

    /// <summary>Wartezeit vor dem einmaligen Neu-Lesen bei beschädigter Datei (§4 „Beschädigt“).</summary>
    internal TimeSpan CorruptRetryDelay { get; }

    /// <summary>Schicht, die V vernichtet (§23.1). Die Windows-App setzt die Windows-Hello-Umsetzung; Standard ist
    /// <see cref="FileDestructionKeyEraser"/>.</summary>
    public IDestructionKeyEraser DestructionKeyEraser
    {
        get { lock (secondaryGate) { return eraser; } }
        set
        {
            Fehler.NotNull(value);
            lock (secondaryGate) { eraser = value; }
        }
    }

    public string VaultPath => Path.Combine(DirectoryPath, VaultFileName);

    public bool VaultExists => FileIO.Exists(VaultPath);

    /// <summary>Zweiter Sicherungsort (die App löst den Ordner auf und gibt den Pfad).</summary>
    public string? SecondaryBackupDirectory
    {
        get { lock (secondaryGate) { return secondary; } }
        set { lock (secondaryGate) { secondary = value; } }
    }

    /// <summary>Vergleicht Master-Passwort und Wiederholung nach der Abbildung aus §1.1 (Zs → U+0020, NFC).</summary>
    public static bool PasswordsMatch(string a, string b)
    {
        Fehler.NotNull(a);
        Fehler.NotNull(b);
        using var x = PasswordNormalizer.SecureBytes(a);
        using var y = PasswordNormalizer.SecureBytes(b);
        return x.ConstantTimeEquals(y);
    }

    internal string BackupRoot => Path.Combine(DirectoryPath, BackupFolderName);

    /// <summary>Ordner der lokalen Sicherungen (je vaultID ein Unterordner).</summary>
    public string BackupsDirectory => BackupRoot;

    /// <summary>Ablage der Gerätefaktor-Schlüssel und des Zustands der Selbstvernichtung (nicht in der Tresordatei).</summary>
    public string HardwareDirectory => Path.Combine(DirectoryPath, HardwareFolderName);

    internal string BackupDirectory(Guid id) => Path.Combine(BackupRoot, Bytes.GuidText(id));

    /// <summary>Entfernt die Ablage eines nicht mehr gebrauchten Gerätefaktor-Schlüssels (nach erfolgreichem Schreiben).</summary>
    internal void RemoveHardwareKey(Guid keyId)
    {
        var wanted = Bytes.GuidText(keyId) + "." + HardwareKeyExtension;
        foreach (var f in FileIO.ListFiles(HardwareDirectory))
        {
            if (string.Equals(Path.GetFileName(f), wanted, StringComparison.OrdinalIgnoreCase)) { FileIO.Remove(f); }
        }
    }

    // MARK: Sicherungen

    /// <summary>Alle Sicherungen (lokal, alle vaultIDs, und am zweiten Ort), neueste zuerst. Liest jede Datei ganz
    /// (Prüfsumme) – nicht auf dem Oberflächen-Thread.</summary>
    public IReadOnlyList<BackupInfo> Backups()
    {
        var output = new List<BackupInfo>();
        foreach (var dir in FileIO.ListDirectories(BackupRoot))
        {
            if (!Guid.TryParseExact(Path.GetFileName(dir), "D", out _)) { continue; }
            foreach (var f in FileIO.ListFiles(dir))
            {
                if (BackupNaming.ParseLocal(Path.GetFileName(f)) is not { } name) { continue; }
                var info = ReadInfo(f);
                output.Add(new BackupInfo(f, name.Date, info?.Generation ?? name.Generation, info?.VaultId, name.Reason, false));
            }
        }
        if (SecondaryBackupDirectory is { } ext)
        {
            foreach (var f in FileIO.ListFiles(ext))
            {
                if (BackupNaming.ParseAnyExternal(Path.GetFileName(f)) is not { } date) { continue; }
                var info = ReadInfo(f);
                output.Add(new BackupInfo(f, date, info?.Generation ?? 0, info?.VaultId, null, true));
            }
        }
        output.Sort((a, b) =>
        {
            if (a.Date != b.Date) { return b.Date.CompareTo(a.Date); }
            if (a.Generation != b.Generation) { return b.Generation.CompareTo(a.Generation); }
            return string.CompareOrdinal(Path.GetFileName(b.Path), Path.GetFileName(a.Path));
        });
        return output;
    }

    /// <summary>Angaben zu einer gewählten Sicherungsdatei (Stand, vaultID, Änderungsdatum), ohne Schlüssel. Fehlt sie →
    /// <c>Io("backup.missing")</c>; unlesbar → <c>CorruptFile</c>.</summary>
    public static BackupInfo ReadBackupInfo(string path)
    {
        Fehler.NotNull(path);
        byte[] bytes;
        try
        {
            bytes = FileIO.Read(path, FileFormat.MaxFileBytes);
        }
        catch (SiegelException e) when (e.Code == SiegelErrorCode.VaultMissing)
        {
            throw Fehler.Io("backup.missing");
        }
        var file = VaultFile.Parse(bytes);
        DateTimeOffset date;
        try
        {
            date = new DateTimeOffset(File.GetLastWriteTimeUtc(path), TimeSpan.Zero);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            date = Clock.Now();
        }
        return new BackupInfo(path, date, file.Generation, file.Header.Uuid, null, true);
    }

    private static (Guid VaultId, ulong Generation)? ReadInfo(string path)
    {
        try
        {
            var file = VaultFile.Parse(FileIO.Read(path, FileFormat.MaxFileBytes));
            return (file.Header.Uuid, file.Generation);
        }
        catch (SiegelException)
        {
            return null;
        }
    }

    /// <summary>Verschiebt die (beschädigte) Tresordatei nach <c>Sicherungen/beschaedigt-&lt;Zeit&gt;.siegel</c>, nie löschen.</summary>
    public string QuarantineCorruptVault()
    {
        lock (writeLock)
        {
            if (!VaultExists) { throw Fehler.VaultMissing(); }
            FileIO.EnsureDirectory(BackupRoot);
            for (var attempt = 0; attempt < 32; attempt++)
            {
                var name = BackupNaming.QuarantineName(Clock.Now(), attempt == 0 ? null : BackupNaming.RandomHex4());
                var dst = Path.Combine(BackupRoot, name);
                try
                {
                    FileIO.RenameExclusive(VaultPath, dst);
                    FileIO.TrySyncDirectory(DirectoryPath);
                    FileIO.TrySyncDirectory(BackupRoot);
                    return dst;
                }
                catch (FileIO.ExistsException)
                {
                    // nächster Name
                }
            }
            throw Fehler.Io("quarantine.name");
        }
    }

    /// <summary>Verschlüsselte Kopie der aktuellen Datei (nur unbeschädigt) an <paramref name="path"/>, danach
    /// zurückgelesen und Byte für Byte verglichen (<c>Io("export.verify")</c>).</summary>
    public void ExportBackup(string path)
    {
        Fehler.NotNull(path);
        var bytes = FileIO.Read(VaultPath, FileFormat.MaxFileBytes);
        _ = VaultFile.Parse(bytes);
        WriteVerified(bytes, path);
    }

    /// <summary>Schreibt an die gewählte Datei (ersetzt sie) und prüft sie: zuerst atomar über eine Temp-Datei daneben;
    /// geht das nicht (Ordner nicht beschreibbar), direkt in genau diese Datei.</summary>
    internal static void WriteVerified(byte[] bytes, string path)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".";
        var tmp = Path.Combine(dir, "." + Path.GetFileName(path) + "." + BackupNaming.RandomHex4() + ".tmp");
        var atomic = false;
        try
        {
            FileIO.WriteExclusive(tmp, bytes);
            FileIO.Rename(tmp, path);
            atomic = true;
        }
        catch (Exception e) when (e is SiegelException or FileIO.ExistsException)
        {
            FileIO.RemoveTemp(tmp);
        }
        if (!atomic) { FileIO.WriteInPlace(path, bytes); }
        byte[] back;
        try
        {
            back = FileIO.Read(path, FileFormat.MaxFileBytes);
        }
        catch (SiegelException)
        {
            throw Fehler.Io("export.verify");
        }
        if (!back.AsSpan().SequenceEqual(bytes)) { throw Fehler.Io("export.verify"); }
        try
        {
            _ = VaultFile.Parse(back);
        }
        catch (SiegelException)
        {
            throw Fehler.Io("export.verify");
        }
    }

    // MARK: Interna: Speichern

    /// <summary>Was auf der Platte erwartet wird (Schritt 1).</summary>
    internal abstract record DiskExpectation
    {
        /// <summary>Neuer Tresor: es darf keine Datei geben.</summary>
        internal sealed record Absent : DiskExpectation;

        /// <summary>Normales Speichern: Datei hat diese vaultID und Generation (fehlt sie, wird neu geschrieben).</summary>
        internal sealed record Generation(Guid VaultId, ulong Value) : DiskExpectation;

        /// <summary>Ersetzen: Datei ist bytegleich wie beobachtet (SHA-256; null = fehlte).</summary>
        internal sealed record Observed(byte[]? Digest) : DiskExpectation;
    }

    internal sealed record DiskState(byte[] Digest, VaultFile? File, ushort? NewerVersion);

    internal DiskState? ObserveDisk()
    {
        byte[] bytes;
        try
        {
            bytes = FileIO.Read(VaultPath, FileFormat.MaxFileBytes);
        }
        catch (SiegelException e) when (e.Code == SiegelErrorCode.VaultMissing)
        {
            return null;
        }
        catch (SiegelException e) when (e.Code == SiegelErrorCode.CorruptFile)
        {
            // zu gross zum Lesen
            return new DiskState([], null, null);
        }
        var digest = SHA256.HashData(bytes);
        try
        {
            return new DiskState(digest, VaultFile.Parse(bytes), null);
        }
        catch (SiegelException e) when (e.Code == SiegelErrorCode.UnsupportedVersion)
        {
            return new DiskState(digest, null, ushort.Parse(e.Detail, NumberStyles.None, CultureInfo.InvariantCulture));
        }
        catch (SiegelException)
        {
            return new DiskState(digest, null, null);
        }
    }

    internal ulong NextGeneration(Guid vaultId, ulong baseGeneration)
    {
        var seen = RollbackGuard.LastSeenGeneration(vaultId) ?? 0;
        var m = Math.Max(baseGeneration, seen);
        if (m == ulong.MaxValue) { throw Fehler.Corrupt("payload.generation"); }
        return m + 1;
    }

    /// <summary>
    /// Inhalt vorbereiten, Datei bauen und nach §4 speichern. Arbeitet auf einer Kopie von <paramref name="content"/>
    /// und liefert die gespeicherte Fassung (gehört dem Aufrufer). <paramref name="duressBinding"/> = F (§23.2 Nr. 3);
    /// Pflicht, sobald der Inhalt ein Vernichtungs-Passwort hat (<c>Crypto("duress.binding")</c>, vor dem Schreiben).
    /// <paramref name="newDek"/>: die Datei trägt einen neuen DEK (Zugangswechsel).
    /// </summary>
    internal (ulong Generation, VaultContent Content) Persist(VaultHeader header, VaultSlots slots, SecureBuffer dek, VaultContent content,
        ulong baseGeneration, DiskExpectation expectation, string? reason, SecureBuffer? duressBinding = null, bool newDek = false)
    {
        Limits.Validate(header.Kdf);
        // Geschrieben wird nur das aktuelle Format, und Stufe (Inhalt) und Faktoren (Kopf) passen immer zusammen.
        if (header.FormatVersion != FileFormat.CurrentVersion) { throw Fehler.Crypto("format.version"); }
        if (content.Level.Factors() != header.Factors) { throw Fehler.Crypto("level.mismatch"); }
        if (!content.DestructionKeysAvoid(header)) { throw Fehler.Crypto("payload.destruction"); }
        var c = content.Clone();
        try
        {
            var now = Clock.Now();
            c.PrepareForSave(now);
            c.PrepareEntryData(now);
            if (c.Destruction?.Duress is not null && duressBinding is null) { throw Fehler.Crypto("duress.binding"); }
            var generation = NextGeneration(header.Uuid, baseGeneration);
            var (bytes, digest) = VaultCrypto.BuildFile(header, slots, generation, dek, c);
            CommitWrite(bytes, header, slots, generation, dek, digest, expectation, reason);
            // Selbstvernichtung (§23): Umschlag des Vernichtungs-Passworts an diesen DEK (und F), Zustand nachführen.
            SyncDestructionAfterWrite(c, header, dek, duressBinding, newDek);
            return (generation, c);
        }
        catch
        {
            c.Dispose();
            throw;
        }
    }

    /// <summary>Speichern in genau dieser Reihenfolge (§4): (0) Platz (1) Generation auf der Platte (2) Temp +
    /// Durchschreiben (3) Rücklese-Prüfung (4) Sicherung der bisherigen Datei (5) ersetzen (6) Ordner (7) ausdünnen.
    /// Scheitert 1–4: alte Datei unverändert, Temp entfernt.</summary>
    private void CommitWrite(byte[] bytes, VaultHeader header, VaultSlots slots, ulong generation, SecureBuffer dek, byte[] digest,
        DiskExpectation expectation, string? reason)
    {
        lock (writeLock)
        {
            FileIO.EnsureDirectory(DirectoryPath);
            if (!tempsCleaned)
            {
                tempsCleaned = true;
                RemoveStaleTemps(FileIO.ListFiles(DirectoryPath), "." + VaultFileName + ".", Clock.Now());
            }
            // (0)
            if (FileIO.FreeSpace(DirectoryPath) is { } free && free < MinimumFreeSpace) { throw Fehler.NotEnoughDiskSpace(); }
            // (1)
            var existing = ObserveDisk();
            switch (expectation)
            {
                case DiskExpectation.Absent:
                    if (existing is not null) { throw Fehler.VaultAlreadyExists(); }
                    break;
                case DiskExpectation.Generation g:
                    if (existing is not null && (existing.File is not { } f || f.Header.Uuid != g.VaultId || f.Generation != g.Value))
                    {
                        throw Fehler.VaultChangedOnDisk();
                    }
                    break;
                case DiskExpectation.Observed o:
                    if (!Bytes.Same(existing?.Digest, o.Digest)) { throw Fehler.VaultChangedOnDisk(); }
                    // Eine Datei mit höherer Formatversion wird nie überschrieben.
                    if (existing?.NewerVersion is { } v) { throw Fehler.UnsupportedVersion(v); }
                    break;
            }
            // Der letzte Stand im Format v1 wird vor dem ersten v2-Schreiben angeheftet gesichert (§13.2).
            if (existing?.File?.Header.FormatVersion == 1) { reason = BackupNaming.Reason.MigrationV1; }
            // (2)
            var tmp = WriteTemp(bytes);
            try
            {
#if DEBUG
                if (TestHooks.CorruptTempBeforeVerify) { FlipByteForTesting(tmp); }
#endif
                // (3)
                VerifyTemp(tmp, header, slots, generation, dek, digest);
                // (4)
                if (existing is not null) { BackupCurrent(existing, reason); }
            }
            catch
            {
                FileIO.RemoveTemp(tmp);
                throw;
            }
            // (5)
            try
            {
                FileIO.Rename(tmp, VaultPath);
            }
            catch
            {
                FileIO.RemoveTemp(tmp);
                throw;
            }
            // (6) Die Datei ist ersetzt; ein Fehler hier darf den Erfolg nicht mehr umkehren.
            FileIO.TrySyncDirectory(DirectoryPath);
            RollbackGuard.Record(header.Uuid, generation);
            // (7)
            ThinLocalBackups(header.Uuid);
            WriteSecondaryBackup(header.Uuid, bytes, force: false);
        }
    }

    private string WriteTemp(byte[] bytes)
    {
        for (var i = 0; i < 16; i++)
        {
            var tmp = Path.Combine(DirectoryPath, "." + VaultFileName + "." + Bytes.Hex(Zufall.Bytes(4)) + ".tmp");
            try
            {
                FileIO.WriteExclusive(tmp, bytes);
                return tmp;
            }
            catch (FileIO.ExistsException)
            {
                // nächster Name
            }
        }
        throw Fehler.Io("file.create");
    }

    /// <summary>(3) Temp neu lesen, Prüfsumme, Kopf/Slots/Generation, mit dem DEK entschlüsseln, SHA-256 vergleichen.</summary>
    private static void VerifyTemp(string tmp, VaultHeader header, VaultSlots slots, ulong generation, SecureBuffer dek, byte[] digest)
    {
        try
        {
            var back = FileIO.Read(tmp, FileFormat.MaxFileBytes);
            var file = VaultFile.Parse(back);
            if (!file.Header.Equals(header) || !file.Slots.Equals(slots) || file.Generation != generation)
            {
                throw Fehler.Io("save.verify");
            }
            var (content, backDigest) = VaultCrypto.DecryptPayload(file, dek);
            content.Dispose();
            if (!backDigest.AsSpan().SequenceEqual(digest)) { throw Fehler.Io("save.verify"); }
        }
        catch (SiegelException)
        {
            throw Fehler.Io("save.verify");
        }
    }

    /// <summary>(4) Bisherige Datei als Sicherung kopieren (nie überschreiben). Unlesbare Datei → „beschaedigt-…“, gestreamt
    /// und ohne Grössengrenze wie Swift <c>clonefile</c> (Befund robust-5: auch eine über 64 MiB gewachsene Datei lässt
    /// sich so beim Wiederherstellen beiseitelegen); dabei bleiben mindestens <see cref="MinimumFreeSpace"/> frei.</summary>
    private void BackupCurrent(DiskState e, string? reason)
    {
        if (e.File is { } f)
        {
            var dir = BackupDirectory(f.Header.Uuid);
            FileIO.EnsureDirectory(dir);
            for (var i = 0; i < 32; i++)
            {
                var name = BackupNaming.LocalName(Clock.Now(), f.Generation, reason);
                try
                {
                    FileIO.Clone(VaultPath, Path.Combine(dir, name));
                    FileIO.TrySyncDirectory(dir);
                    return;
                }
                catch (FileIO.ExistsException)
                {
                    // nächster Name
                }
            }
            throw Fehler.Io("backup.name");
        }
        FileIO.EnsureDirectory(BackupRoot);
        for (var attempt = 0; attempt < 32; attempt++)
        {
            var name = BackupNaming.QuarantineName(Clock.Now(), attempt == 0 ? null : BackupNaming.RandomHex4());
            try
            {
                FileIO.CopyExclusiveStreamed(VaultPath, Path.Combine(BackupRoot, name), MinimumFreeSpace);
                FileIO.TrySyncDirectory(BackupRoot);
                return;
            }
            catch (FileIO.ExistsException)
            {
                // nächster Name
            }
        }
        throw Fehler.Io("backup.name");
    }

    /// <summary>(7) Ausdünnen pro vaultID; nur Dateien nach dem Namensschema werden angefasst.</summary>
    internal void ThinLocalBackups(Guid vaultId)
    {
        var items = new List<BackupThinning.Item>();
        foreach (var f in FileIO.ListFiles(BackupDirectory(vaultId)))
        {
            if (BackupNaming.ParseLocal(Path.GetFileName(f)) is { } n) { items.Add(new BackupThinning.Item(f, n.Date, n.Reason is not null)); }
        }
        foreach (var u in BackupThinning.SelectForDeletion(items, Clock.Now())) { FileIO.Remove(u); }
    }

    /// <summary>Ergebnis des letzten Versuchs am zweiten Sicherungsort (nur dieser Prozess); null = noch keiner.</summary>
    public SecondaryBackupResult? LastSecondaryBackupResult
    {
        get { lock (secondaryGate) { return secondaryResult; } }
    }

    /// <summary>Zweiter Sicherungsort: höchstens 1× pro Stunde, atomar, gleiche Ausdünnung. Fehler brechen nichts ab.</summary>
    internal SecondaryBackupResult WriteSecondaryBackup(Guid vaultId, byte[] bytes, bool force)
    {
        var result = WriteSecondaryBackupUnrecorded(vaultId, bytes, force);
        lock (secondaryGate) { secondaryResult = result; }
        return result;
    }

    private SecondaryBackupResult WriteSecondaryBackupUnrecorded(Guid vaultId, byte[] bytes, bool force)
    {
        if (SecondaryBackupDirectory is not { } dir) { return SecondaryBackupResult.Unreachable; }
        IReadOnlyList<string> files;
        try
        {
            files = FileIO.ListFilesChecked(dir);
        }
        catch (SiegelException)
        {
            return SecondaryBackupResult.Unreachable;
        }
        var prefix = BackupNaming.ExternalPrefix(vaultId);
        var now = Clock.Now();
        RemoveStaleTemps(files, "." + prefix, now);
        var items = new List<BackupThinning.Item>();
        foreach (var f in files)
        {
            if (BackupNaming.ParseExternal(Path.GetFileName(f), prefix) is { } d) { items.Add(new BackupThinning.Item(f, d, false)); }
        }
        if (!force && items.Count > 0)
        {
            var age = now - items.Max(i => i.Date);
            if (age >= TimeSpan.Zero && age < ExternalInterval) { return SecondaryBackupResult.NotDue; }
        }
        var name = BackupNaming.ExternalName(vaultId, now);
        var dst = Path.Combine(dir, name);
        var tmp = Path.Combine(dir, "." + name + "." + BackupNaming.RandomHex4() + ".tmp");
        try
        {
            FileIO.WriteExclusive(tmp, bytes);
        }
        catch (Exception e) when (e is SiegelException or FileIO.ExistsException)
        {
            return SecondaryBackupResult.Failed;
        }
        try
        {
            FileIO.RenameExclusive(tmp, dst);
        }
        catch (FileIO.ExistsException) when (force)
        {
            // Gleiche Sekunde wie eine eben geschriebene Kopie derselben vaultID: durch den aktuellen Stand ersetzen.
            try
            {
                FileIO.Rename(tmp, dst);
            }
            catch (SiegelException)
            {
                FileIO.RemoveTemp(tmp);
                return SecondaryBackupResult.Failed;
            }
        }
        catch (Exception e) when (e is SiegelException or FileIO.ExistsException)
        {
            FileIO.RemoveTemp(tmp);
            return SecondaryBackupResult.Failed;
        }
        FileIO.TrySyncDirectory(dir);
        if (!items.Any(i => Path.GetFileName(i.Path) == name)) { items.Add(new BackupThinning.Item(dst, now, false)); }
        foreach (var u in BackupThinning.SelectForDeletion(items, now))
        {
            if (Path.GetFileName(u) != name) { FileIO.Remove(u); }
        }
        return SecondaryBackupResult.Written(now);
    }

    /// <summary>Reste abgebrochener Schreibvorgänge entfernen (nur ältere als eine Minute).</summary>
    internal static void RemoveStaleTemps(IEnumerable<string> files, string prefix, DateTimeOffset now)
    {
        foreach (var f in files)
        {
            var name = Path.GetFileName(f);
            if (!name.StartsWith(prefix, StringComparison.Ordinal) || !name.EndsWith(".tmp", StringComparison.Ordinal)) { continue; }
            if (FileIO.Age(f, now) is { } age && age > 60) { FileIO.Remove(f); }
        }
    }

    /// <summary>Alle Sicherungen dieser vaultID entfernen (auch angeheftete, auch am zweiten Ort) und sofort eine
    /// Sicherung des aktuellen Stands anlegen. Der Bericht nennt, was übrig blieb.</summary>
    internal PurgeReport PurgeBackups(Guid vaultId, ulong generation)
    {
        lock (writeLock)
        {
            if (ObserveDisk() is not { File: { } f } disk || f.Header.Uuid != vaultId || f.Generation != generation)
            {
                throw Fehler.VaultChangedOnDisk();
            }
#if DEBUG
            if (TestHooks.FailPurgeBackups) { throw Fehler.Io("test.purge"); }
#endif
            var report = new PurgeReport();
            var now = Clock.Now();
            RemoveStaleTemps(FileIO.ListFiles(DirectoryPath), "." + VaultFileName + ".", now);
            foreach (var u in FileIO.ListFiles(BackupDirectory(vaultId)))
            {
                if (Path.GetExtension(u) != "." + BackupNaming.FileExtension) { continue; }
                if (FileIO.RemoveChecked(u)) { report.Removed++; } else { report.Failed++; }
            }
            if (SecondaryBackupDirectory is { } ext)
            {
                var prefix = BackupNaming.ExternalPrefix(vaultId);
                try
                {
                    foreach (var u in FileIO.ListFilesChecked(ext))
                    {
                        if (BackupNaming.ParseExternal(Path.GetFileName(u), prefix) is null) { continue; }
                        if (FileIO.RemoveChecked(u)) { report.Removed++; } else { report.Failed++; }
                    }
                }
                catch (SiegelException)
                {
                    report.SecondaryUnreachable = true;
                }
            }
            BackupCurrent(disk, reason: null);
            var bytes = FileIO.Read(VaultPath, FileFormat.MaxFileBytes);
            if (!report.SecondaryUnreachable && SecondaryBackupDirectory is not null
                && WriteSecondaryBackup(vaultId, bytes, force: true).Kind == SecondaryBackupKind.Failed)
            {
                report.Failed++;
            }
            return report;
        }
    }

    /// <summary>Holt das Entfernen am zweiten Ort nach: entfernt dort alle Sicherungen dieser vaultID, die vor
    /// <paramref name="before"/> entstanden sind, und legt eine frische Kopie an (wenn die Tresordatei zu dieser vaultID
    /// gehört). Braucht keinen entsperrten Tresor.</summary>
    public PurgeReport PurgeSecondaryBackups(Guid vaultId, DateTimeOffset before)
    {
        lock (writeLock)
        {
            var report = new PurgeReport();
            IReadOnlyList<string> files;
            if (SecondaryBackupDirectory is not { } ext)
            {
                report.SecondaryUnreachable = true;
                return report;
            }
            try
            {
                files = FileIO.ListFilesChecked(ext);
            }
            catch (SiegelException)
            {
                report.SecondaryUnreachable = true;
                return report;
            }
            var prefix = BackupNaming.ExternalPrefix(vaultId);
            RemoveStaleTemps(files, "." + prefix, Clock.Now());
            foreach (var u in files)
            {
                if (BackupNaming.ParseExternal(Path.GetFileName(u), prefix) is not { } date || date >= before) { continue; }
                if (FileIO.RemoveChecked(u)) { report.Removed++; } else { report.Failed++; }
            }
            try
            {
                var bytes = FileIO.Read(VaultPath, FileFormat.MaxFileBytes);
                var file = VaultFile.Parse(bytes);
                if (file.Header.Uuid == vaultId && WriteSecondaryBackup(vaultId, bytes, force: true).Kind == SecondaryBackupKind.Failed)
                {
                    report.Failed++;
                }
            }
            catch (SiegelException)
            {
                // keine passende Tresordatei: nichts nachzuschreiben
            }
            return report;
        }
    }

    /// <summary>Zwei verschiedene Gruppenindizes 0…10, sortiert.</summary>
    internal static IReadOnlyList<int> RandomConfirmationGroups()
    {
        var a = (int)Zufall.Uniform(RecoveryCodeCodec.GroupCount);
        var b = (int)Zufall.Uniform(RecoveryCodeCodec.GroupCount - 1);
        if (b >= a) { b++; }
        return [Math.Min(a, b), Math.Max(a, b)];
    }

#if DEBUG
    /// <summary>Nur Tests: aktuelle Datei sofort sichern (gleiche Generation beliebig oft).</summary>
    internal void BackupNowForTesting(string? reason)
    {
        lock (writeLock)
        {
            var disk = ObserveDisk() ?? throw Fehler.VaultMissing();
            BackupCurrent(disk, reason);
        }
    }

    internal static void FlipByteForTesting(string path)
    {
        var bytes = FileIO.Read(path, FileFormat.MaxFileBytes);
        bytes[bytes.Length / 2] ^= 0x01;
        FileIO.Remove(path);
        FileIO.WriteExclusive(path, bytes);
    }
#endif
}
