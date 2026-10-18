using Siegel.Modell;

namespace Siegel.Core;

// Selbstvernichtung im Store (SPEC §23), wie VaultStore+Vernichtung.swift: Zustand im gesperrten Zustand,
// Totmann-Schalter, Fehlversuch-Zähler, Vernichten über die austauschbare Schicht, Entsperren mit Vernichtungs-Passwort
// (beide Argon2 parallel). Alles im Hardware-Ordner, nie in der Tresordatei:
// - Echtes Entsperren: zustand.json (Fehlversuche 0, letzte echte Entsperrung, Einstellungen aus dem Inhalt) und die
//   Ablage des Vernichtungs-Passworts frisch gekapselt (an DEK und Faktoren gebunden, v4.4).
// - Vernichtungs-Passwort: V überschreiben + löschen, dann zustand.json (Fehlversuche 0, destroyed, rekeyPending).
// - Falsches Passwort (Zähler an): zustand.json (Fehlversuche + 1), bei N zusätzlich V vernichten.
// - Jedes Speichern mit eingerichteter Selbstvernichtung: Ablage neu und zustand.json, falls sich etwas geändert hat.
// Ohne eingerichtete Selbstvernichtung entsteht keine dieser Dateien.
public sealed partial class VaultStore
{
    /// <summary>Toleranz der Uhr (§23.2: „jetzt &lt; letztes Entsperren − 1 Tag“ gilt als rückwärts).</summary>
    internal static readonly TimeSpan ClockTolerance = TimeSpan.FromDays(1);

    // MARK: Öffentlich (§23.3)

    /// <summary>Zustand im gesperrten Zustand (aus <c>Hardware/zustand.json</c>). Fehlt die Datei oder gehört sie zu
    /// einem anderen Tresor: alles aus. (Swift: <c>destructionStatus()</c>.)</summary>
    public DestructionStatus GetDestructionStatus()
    {
        lock (DestructionLock)
        {
            return CurrentState()?.Status ?? DestructionStatus.Off;
        }
    }

    /// <summary>Darf die Oberfläche ein eben angelegtes V nach einem gescheiterten <c>ConfigureDestruction</c> wieder
    /// vernichten? Nur wenn sicher nichts es nennt: zustand.json nennt es weder als V noch als vernichtet, und die
    /// Tresordatei ist noch genau der Stand <paramref name="generation"/> dieses Tresors (v4.4, Befund datei-1).</summary>
    public bool DestructionKeyIsUnused(Guid keyId, Guid vaultId, ulong generation)
    {
        bool named;
        lock (DestructionLock)
        {
            var st = DestructionState.Read(HardwareDirectory);
            named = st is null ? FileIO.Exists(DestructionState.PathIn(HardwareDirectory)) : st.VKeyId == keyId || st.DestroyedInfo?.KeyId == keyId;
        }
        if (named) { return false; }
        try
        {
            return ObserveDisk() is { File: { } file } && file.Header.Uuid == vaultId && file.Generation == generation;
        }
        catch (SiegelException)
        {
            return false;
        }
    }

    /// <summary>Totmann-Schalter (§23.2 Nr. 1): ist die Frist seit der letzten echten Entsperrung abgelaufen, wird V
    /// vernichtet (true = gerade vernichtet). Uhr rückwärts → nichts. Schon vernichtet → nur das Löschen wiederholen.
    /// Geht auch gesperrt. Fehler beim Vermerken → <c>Io("destruction.write")</c> (V ist dann trotzdem vernichtet).</summary>
    public bool CheckDeadman(DateTimeOffset now)
    {
        lock (DestructionLock)
        {
            if (CurrentState() is not { } st) { return false; }
            if (st.DestroyedInfo is { } d)
            {
                if (HardwareKeyExists(d.KeyId)) { EraseDestructionKey(d.KeyId); }
                return false;
            }
            if (st.Settings.DeadmanDays is not { } days || st.LastGenuineUnlock is not { } last || st.VKeyId is null) { return false; }
            var t = Clock.Canonical(now);
            DateTimeOffset deadline;
            try
            {
                // Uhr rückwärts (§23.2) bzw. Frist noch nicht erreicht.
                if (t < last - ClockTolerance) { return false; }
                deadline = last.AddDays(days);
            }
            catch (ArgumentOutOfRangeException)
            {
                // unbrauchbare Uhr: nichts (wie Fuzz-Befund vernichtung-3)
                return false;
            }
            if (t < deadline) { return false; }
            DestroyLocked(st, DestructionTrigger.Deadman, t);
            return true;
        }
    }

    /// <summary><see cref="CheckDeadman"/> ohne Fehler (wie <c>try?</c> beim Entsperren).</summary>
    private void TryCheckDeadman()
    {
        try
        {
            CheckDeadman(Clock.Now());
        }
        catch (SiegelException)
        {
            // V ist vernichtet; der Vermerk folgt bei der nächsten Prüfung
        }
    }

    // MARK: Zustand lesen

    /// <summary>Zustand, sofern er zu dieser Tresordatei gehört (bei unlesbarem Kopf trotzdem). Nennt er den
    /// Entsperr-Gerätefaktor des Kopfes (bzw. ohne Kopf den einer eigenen Sicherung), gilt er nicht (vernichtung-1/-6).
    /// Nur unter <see cref="DestructionLock"/>.</summary>
    internal DestructionState? CurrentState()
    {
        if (DestructionState.Read(HardwareDirectory) is not { } st) { return null; }
        if (CurrentHeader() is not { } header)
        {
            return BackupUnlockKeyIds(st.VaultId).Any(st.Names) ? null : st;
        }
        if (header.Uuid != st.VaultId) { return null; }
        if (header.FactorFields.SeKeyId is { } se && st.Names(se)) { return null; }
        return st;
    }

    /// <summary>Entsperr-Gerätefaktoren aus den Köpfen der lokalen Sicherungen dieses Tresors und der beiseitegelegten
    /// beschädigten Tresordateien (nur Kopf, ohne Prüfsumme).</summary>
    internal HashSet<Guid> BackupUnlockKeyIds(Guid vaultId)
    {
        var output = new HashSet<Guid>();
        foreach (var f in FileIO.ListFiles(BackupDirectory(vaultId)).Concat(FileIO.ListFiles(BackupRoot)))
        {
            if (Path.GetExtension(f) != "." + BackupNaming.FileExtension) { continue; }
            if (ReadHeader(f) is { } h && h.Uuid == vaultId && h.FactorFields.SeKeyId is { } se) { output.Add(se); }
        }
        return output;
    }

    internal VaultHeader? CurrentHeader() => ReadHeader(VaultPath);

    internal string HardwareKeyPath(Guid id) => Path.Combine(HardwareDirectory, Bytes.GuidText(id) + "." + HardwareKeyExtension);

    /// <summary>Liegt <c>&lt;id&gt;.siegelhw</c> im Hardware-Ordner (Gross-/Kleinschreibung egal)?</summary>
    internal bool HardwareKeyExists(Guid id)
    {
        var wanted = Bytes.GuidText(id) + "." + HardwareKeyExtension;
        return FileIO.ListFiles(HardwareDirectory).Any(f => string.Equals(Path.GetFileName(f), wanted, StringComparison.OrdinalIgnoreCase));
    }

    // MARK: Vernichten

    /// <summary>V vernichten und vermerken (nur unter <see cref="DestructionLock"/>). Schon vernichtet oder kein V → nichts.</summary>
    internal void DestroyLocked(DestructionState st, DestructionTrigger trigger, DateTimeOffset at)
    {
        if (st.DestroyedInfo is not null || st.VKeyId is not { } v) { return; }
        EraseDestructionKey(v);
        st.DestroyedInfo = new DestructionState.Destroyed(v, trigger, Clock.Canonical(at));
        DestructionState.Write(st, HardwareDirectory);
    }

    /// <summary>Über die austauschbare Schicht; liegt die Datei danach noch da, selbst überschreiben und löschen. Fehler
    /// brechen nichts ab (die nächste Prüfung versucht es erneut).</summary>
    internal void EraseDestructionKey(Guid id)
    {
        try
        {
            DestructionKeyEraser.Destroy(id, HardwareDirectory);
        }
#pragma warning disable CA1031 // Die Schicht stammt von der App; jeder Fehler fällt auf den Rückfall des Kerns zurück.
        catch (Exception)
#pragma warning restore CA1031
        {
            // Rückfall unten
        }
        if (!HardwareKeyExists(id)) { return; }
        try
        {
            new FileDestructionKeyEraser().Destroy(id, HardwareDirectory);
        }
        catch (SiegelException)
        {
            // nächste Prüfung
        }
    }

    // MARK: Fehlversuche und Entsperrungen

    /// <summary>Ein falsches Passwort (nur <c>WrongPassword</c>, §23.2 Nr. 2). Zähler aus oder schon vernichtet → nichts.</summary>
    internal void RecordFailedAttempt()
    {
        lock (DestructionLock)
        {
            if (CurrentState() is not { } st || st.Settings.MaxFailedAttempts is not { } n || st.DestroyedInfo is not null) { return; }
            st.FailedAttempts = Math.Min(st.FailedAttempts + 1, DestructionState.MaxCounter);
            try
            {
                if (st.FailedAttempts >= n && st.VKeyId is not null)
                {
                    DestroyLocked(st, DestructionTrigger.FailedAttempts, Clock.Now());
                    return;
                }
                DestructionState.Write(st, HardwareDirectory);
            }
            catch (SiegelException)
            {
                // bestes Bemühen
            }
        }
    }

    /// <summary>Echtes Entsperren (oder Einsetzen einer Sicherung): Zähler 0, letzte echte Entsperrung nachführen (nie
    /// rückwärts), Einstellungen aus dem Inhalt, Ablage des Vernichtungs-Passworts frisch kapseln (<paramref name="binding"/>
    /// = F dieses Entsperrens). Immer neu, damit auch Ablagen aus v4.3 ersetzt werden.</summary>
    internal void RecordGenuineUnlock(VaultContent content, VaultHeader header, SecureBuffer dek, SecureBuffer? binding)
    {
        lock (DestructionLock)
        {
            var existing = DestructionState.Read(HardwareDirectory);
            if (content.Destruction is null && existing is null) { return; }
            var st = existing is not null && existing.VaultId == header.Uuid ? existing.Copy() : new DestructionState(header.Uuid);
            Apply(content, st);
            st.FailedAttempts = 0;
            if (content.Destruction is not null)
            {
                var now = Clock.Now();
                st.LastGenuineUnlock = st.LastGenuineUnlock is { } old && old > now ? old : now;
            }
            if (content.Destruction?.Duress is { } d && binding is not null) { TryWriteDuressFile(d, dek, binding, header.VaultId); }
            RemoveStaleDuressFile(existing?.DuressFileId, st.DuressFileId, content, header);
            Store(st, existing);
        }
    }

    /// <summary>Vernichtungs-Passwort erkannt (§23.2 Nr. 3): zuerst V vernichten, Zähler 0, letzte echte Entsperrung
    /// bleibt, Vermerk <c>rekeyPending</c>. Liest über <see cref="CurrentState"/> (vernichtung-4).</summary>
    internal void RecordDuressUnlock(DateTimeOffset now)
    {
        lock (DestructionLock)
        {
            if (CurrentState() is not { } st) { return; }
            st.FailedAttempts = 0;
            st.RekeyPending = true;
            try
            {
                if (st.DestroyedInfo is { } d)
                {
                    if (HardwareKeyExists(d.KeyId)) { EraseDestructionKey(d.KeyId); }
                    DestructionState.Write(st, HardwareDirectory);
                }
                else if (st.VKeyId is not null)
                {
                    DestroyLocked(st, DestructionTrigger.DuressPassword, now);
                }
                else
                {
                    DestructionState.Write(st, HardwareDirectory);
                }
            }
            catch (SiegelException)
            {
                // bestes Bemühen
            }
        }
    }

    /// <summary>Nach jedem erfolgreichen Schreiben: Ablage an den DEK dieser Datei (an F gebunden), Einstellungen
    /// nachführen, veraltete Ablagen entfernen. <paramref name="newDek"/> erledigt eine ausstehende Rotation.</summary>
    internal void SyncDestructionAfterWrite(VaultContent content, VaultHeader header, SecureBuffer dek, SecureBuffer? binding, bool newDek)
    {
        lock (DestructionLock)
        {
            var existing = DestructionState.Read(HardwareDirectory);
            if (content.Destruction is null && existing is null) { return; }
            var st = existing is not null && existing.VaultId == header.Uuid ? existing.Copy() : new DestructionState(header.Uuid);
            Apply(content, st);
            if (newDek) { st.RekeyPending = false; }
            if (st.Settings.AnyTriggerEnabled && st.LastGenuineUnlock is null) { st.LastGenuineUnlock = Clock.Now(); }
            if (content.Destruction?.Duress is { } d && binding is not null) { TryWriteDuressFile(d, dek, binding, header.VaultId); }
            RemoveStaleDuressFile(existing?.DuressFileId, st.DuressFileId, content, header);
            Store(st, existing);
        }
    }

    /// <summary>Einstellungen, V und Ablage aus dem (massgeblichen) Inhalt; ein Vermerk gilt nur, solange der Inhalt genau
    /// dieses V nennt; ohne Zähler kein Zählerstand.</summary>
    private static void Apply(VaultContent content, DestructionState st)
    {
        var cfg = content.Destruction;
        st.Settings = cfg?.Settings ?? DestructionSettings.Off;
        st.VKeyId = cfg?.VKey?.KeyId;
        st.DuressFileId = cfg?.Duress?.FileId;
        if (st.DestroyedInfo is { } d && d.KeyId != st.VKeyId) { st.DestroyedInfo = null; }
        if (st.Settings.MaxFailedAttempts is null) { st.FailedAttempts = 0; }
        if (cfg is null) { st.LastGenuineUnlock = null; }
    }

    /// <summary>Schreiben, wenn sich etwas geändert hat; nichts mehr zu merken → Datei entfernen.</summary>
    private void Store(DestructionState st, DestructionState? previous)
    {
        if (st.IsEmpty)
        {
            if (previous is not null || FileIO.Exists(DestructionState.PathIn(HardwareDirectory))) { DestructionState.Remove(HardwareDirectory); }
            return;
        }
        if (st.Equals(previous)) { return; }
        try
        {
            DestructionState.Write(st, HardwareDirectory);
        }
        catch (SiegelException)
        {
            // bestes Bemühen
        }
    }

    // MARK: Ablage des Vernichtungs-Passworts

    /// <summary>Ablage frisch kapseln. Ersetzt wird nur eine Datei mit der Form einer Ablage; liegt unter diesem Namen eine
    /// andere Datei, bleibt sie unberührt → <c>Io("destruction.write")</c> (vernichtung-8).</summary>
    internal void WriteDuressFile(DestructionConfig.DuressInfo d, SecureBuffer dek, SecureBuffer binding, byte[] vaultId)
    {
        var path = HardwareKeyPath(d.FileId);
        if (FileIO.Exists(path))
        {
            byte[]? old;
            try
            {
                old = FileIO.Read(path, DuressFile.FileLength);
            }
            catch (SiegelException)
            {
                old = null;
            }
            if (old is null || !DuressFile.HasShape(old)) { throw Fehler.Io("destruction.write"); }
        }
        var file = DuressCrypto.Seal(dek, d, binding, vaultId);
        try
        {
            FileIO.EnsureDirectory(HardwareDirectory);
        }
        catch (SiegelException)
        {
            throw Fehler.Io("destruction.write");
        }
        DestructionState.WriteAtomically(file.Encoded(), path, HardwareDirectory);
    }

    private void TryWriteDuressFile(DestructionConfig.DuressInfo d, SecureBuffer dek, SecureBuffer binding, byte[] vaultId)
    {
        try
        {
            WriteDuressFile(d, dek, binding, vaultId);
        }
        catch (SiegelException)
        {
            // das nächste echte Entsperren repariert
        }
    }

    internal DuressFile? ReadDuressFile(Guid id)
    {
        try
        {
            return DuressFile.Decode(FileIO.Read(HardwareKeyPath(id), DuressFile.FileLength), id);
        }
        catch (SiegelException)
        {
            return null;
        }
    }

    /// <summary>Ablage eines ersetzten oder entfernten Vernichtungs-Passworts löschen – nie eine Datei, die der Tresor noch
    /// braucht (vernichtung-2), und nur eine echte Ablage mit dieser Kennung (vernichtung-7).</summary>
    private void RemoveStaleDuressFile(Guid? old, Guid? keep, VaultContent content, VaultHeader header)
    {
        if (old is not { } id || id == keep) { return; }
        Guid?[] inUse = [header.FactorFields.SeKeyId, content.EntryFactors.DeviceKeyId, content.Destruction?.VKey?.KeyId];
        if (inUse.Contains(id) || ReadDuressFile(id) is null) { return; }
        _ = FileIO.OverwriteAndRemove(HardwareKeyPath(id));
        FileIO.TrySyncDirectory(HardwareDirectory);
    }

    // MARK: Entsperren mit Vernichtungs-Passwort

    /// <summary>Was das Entsperren über das Vernichtungs-Passwort wissen muss. <see cref="File"/> fehlt, wenn der Zustand
    /// es eingeschaltet nennt, die Ablage aber fehlt oder beschädigt ist: dann läuft das zweite Argon2 mit einem
    /// Wegwerf-Salz (gleiche Dauer), erkennen kann es nichts.</summary>
    internal sealed record DuressProbe(DuressFile? File, byte[] Salt);

    /// <summary>Steht nach einer Vernichtungs-Sitzung die DEK-Rotation noch aus (v4.4)?</summary>
    internal bool RekeyPending()
    {
        lock (DestructionLock)
        {
            return CurrentState()?.RekeyPending ?? false;
        }
    }

    /// <summary>null = Vernichtungs-Passwort nicht eingeschaltet (dann nur ein Argon2).</summary>
    internal DuressProbe? ReadDuressProbe()
    {
        lock (DestructionLock)
        {
            if (CurrentState() is not { } st || !st.Settings.DuressEnabled || st.DuressFileId is not { } id) { return null; }
            var file = ReadDuressFile(id);
            return new DuressProbe(file, file?.Salt ?? Zufall.Bytes(DuressCrypto.SaltBytes));
        }
    }

    /// <summary>Argon2 für das Master-Passwort (über den Cache, der p besitzt) und für das Vernichtungs-Passwort
    /// <b>gleichzeitig</b> (§23.2). Scheitert einer mit <c>KdfFailed</c> (Speicher), einmal nacheinander. d gehört danach
    /// <paramref name="duressCache"/>.</summary>
    internal (SecureBuffer P, SecureBuffer D) BothArgon(VaultHeader header, SecureBuffer password, KekCache cache, byte[] duressSalt,
        SecretCache duressCache)
    {
        var limits = Limits;
        var kdf = header.Kdf;
        var cached = duressCache.Value;
        var (ra, rb) = ParallelKdf.Run(() => cache.Argon(header, password, limits),
            () => cached ?? DuressCrypto.Derive(password, duressSalt, kdf, limits));
        try
        {
            var p = ParallelKdf.Get(ra, () => cache.Argon(header, password, limits));
            var d = ParallelKdf.Get(rb, () => DuressCrypto.Derive(password, duressSalt, kdf, limits));
            duressCache.Value = d;
            return (p, d);
        }
        catch
        {
            if (rb.Value is { } v && !ReferenceEquals(v, cached)) { v.Dispose(); }
            throw;
        }
    }

    /// <summary>Kennung des als vernichtet vermerkten V (aus dem Zustand dieses Tresors), sonst null.</summary>
    internal Guid? DestroyedKeyId()
    {
        lock (DestructionLock)
        {
            return CurrentState()?.DestroyedInfo?.KeyId;
        }
    }
}

/// <summary>Merkt sich ein Geheimnis für die Dauer eines Aufrufs (z. B. d über den einmaligen Neu-Lese-Versuch); besitzt es.</summary>
internal sealed class SecretCache : IDisposable
{
    private readonly Lock gate = new();
    private SecureBuffer? stored;

    internal SecureBuffer? Value
    {
        get { lock (gate) { return stored; } }
        set
        {
            lock (gate)
            {
                if (!ReferenceEquals(stored, value)) { stored?.Dispose(); }
                stored = value;
            }
        }
    }

    public void Dispose() => Value = null;
}

/// <summary>Zwei Argon2-Läufe gleichzeitig: <c>a</c> auf diesem Thread, <c>b</c> auf einem eigenen (Testschalter fliessen
/// über den ExecutionContext mit).</summary>
internal static class ParallelKdf
{
    internal readonly record struct Result(SecureBuffer? Value, SiegelException? Error);

    internal static (Result A, Result B) Run(Func<SecureBuffer> a, Func<SecureBuffer> b)
    {
        var rb = new Result(null, Fehler.KdfFailed());
        var thread = new Thread(() => rb = Capture(b)) { IsBackground = true, Name = "Siegel-Argon2" };
        thread.Start();
        var ra = Capture(a);
        thread.Join();
        return (ra, rb);
    }

    private static Result Capture(Func<SecureBuffer> body)
    {
        try
        {
            return new Result(body(), null);
        }
        catch (SiegelException e)
        {
            return new Result(null, e);
        }
#pragma warning disable CA1031 // Wie Swift: alles andere gilt als kdfFailed (fester Code, nie ein fremder Text).
        catch (Exception)
#pragma warning restore CA1031
        {
            return new Result(null, Fehler.KdfFailed());
        }
    }

    /// <summary>Erfolg, sonst <paramref name="retry"/> (nur bei <c>KdfFailed</c>; andere Fehler gelten sofort).</summary>
    internal static SecureBuffer Get(Result r, Func<SecureBuffer> retry)
    {
        if (r.Value is { } v) { return v; }
        if (r.Error is { Code: SiegelErrorCode.KdfFailed }) { return retry(); }
        throw r.Error ?? Fehler.KdfFailed();
    }
}
