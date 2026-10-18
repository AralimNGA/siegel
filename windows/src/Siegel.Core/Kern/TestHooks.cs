#if DEBUG
using Siegel.Modell;

namespace Siegel.Core;

/// <summary>
/// Testschalter, nur in DEBUG-Bauten und nur über InternalsVisibleTo erreichbar (Gegenstück zu Swift
/// <c>TestHooks</c> mit <c>@TaskLocal</c>). Sie gelten pro asynchronem Ablauf (<see cref="AsyncLocal{T}"/>, fliesst in
/// Task.Run, Parallel.For und neu gestartete Threads mit) und beeinflussen parallel laufende Tests nicht. Keiner hebt
/// eine Prüfung auf.
/// </summary>
internal static class TestHooks
{
    private static readonly AsyncLocal<bool> forceKdfFailure = new();
    private static readonly AsyncLocal<Counter?> kdfCounter = new();
    private static readonly AsyncLocal<DateTimeOffset?> now = new();
    private static readonly AsyncLocal<KdfParameters?> levelKdfOverride = new();
    private static readonly AsyncLocal<bool> corruptTempBeforeVerify = new();
    private static readonly AsyncLocal<ulong?> freeSpaceOverride = new();
    private static readonly AsyncLocal<bool> failPurgeBackups = new();
    private static readonly AsyncLocal<Action?> afterDuressArgon = new();
    private static readonly AsyncLocal<KdfObserver?> kdfObserver = new();
    private static readonly AsyncLocal<Rendezvous?> kdfRendezvous = new();
    private static readonly AsyncLocal<Func<IReadOnlyList<(VaultEntry Entry, EntrySecrets Secrets)>, string, byte[]>?> keePassExporter = new();
    private static readonly AsyncLocal<Func<IReadOnlyList<(VaultEntry Entry, EntrySecrets Secrets)>, byte[]>?> csvExporter = new();

    /// <summary>Erzwingt einen echten <c>crypto_pwhash</c>-Fehler (opslimit 0 → libsodium lehnt ab).</summary>
    internal static bool ForceKdfFailure { get => forceKdfFailure.Value; set => forceKdfFailure.Value = value; }

    /// <summary>Zählt Argon2-Läufe (KEK-Wiederverwendung, „ohne Argon2“).</summary>
    internal static Counter? KdfCounter { get => kdfCounter.Value; set => kdfCounter.Value = value; }

    /// <summary>Feste Uhrzeit für Verlauf/Zuletzt-gelöscht/Sicherungsnamen.</summary>
    internal static DateTimeOffset? Now { get => now.Value; set => now.Value = value; }

    /// <summary>Ersetzt das KDF-Profil aller Stufen (Fixture-Erzeugung mit 256 MiB, t = 3).</summary>
    internal static KdfParameters? LevelKdfOverride { get => levelKdfOverride.Value; set => levelKdfOverride.Value = value; }

    /// <summary>Kippt nach dem Schreiben ein Byte der Temp-Datei, damit die Rücklese-Prüfung scheitert.</summary>
    internal static bool CorruptTempBeforeVerify { get => corruptTempBeforeVerify.Value; set => corruptTempBeforeVerify.Value = value; }

    /// <summary>Ersetzt den gemessenen freien Platz (Byte).</summary>
    internal static ulong? FreeSpaceOverride { get => freeSpaceOverride.Value; set => freeSpaceOverride.Value = value; }

    /// <summary><c>PurgeBackups</c> scheitert (nach dem Schreiben der Tresordatei, Befund datei-1).</summary>
    internal static bool FailPurgeBackups { get => failPurgeBackups.Value; set => failPurgeBackups.Value = value; }

    /// <summary>Beim Entsperren nach erkanntem Vernichtungs-Passwort (nach beiden Argon2, vor dem Vermerk).</summary>
    internal static Action? AfterDuressArgon { get => afterDuressArgon.Value; set => afterDuressArgon.Value = value; }

    /// <summary>Wird vor jedem Argon2-Lauf mit dessen Nummer (ab 1) gerufen, z. B. um während einer Rechnung zu sperren.</summary>
    internal static KdfObserver? KdfObserverHook { get => kdfObserver.Value; set => kdfObserver.Value = value; }

    /// <summary>Jeder Argon2-Lauf wartet hier, bis alle Teilnehmer da sind (belegt gleichzeitige Läufe, §23.2).</summary>
    internal static Rendezvous? KdfRendezvous { get => kdfRendezvous.Value; set => kdfRendezvous.Value = value; }

    /// <summary>Ersetzt <c>KeePassExport.Kdbx</c> (Tests sehen, was exportiert würde).</summary>
    internal static Func<IReadOnlyList<(VaultEntry Entry, EntrySecrets Secrets)>, string, byte[]>? KeePassExporter
    {
        get => keePassExporter.Value;
        set => keePassExporter.Value = value;
    }

    /// <summary>Ersetzt <c>CsvExport.Export</c> (Tests sehen, was exportiert würde; der echte Export ist in
    /// <c>WerkzeugeImKernTests</c> geprüft).</summary>
    internal static Func<IReadOnlyList<(VaultEntry Entry, EntrySecrets Secrets)>, byte[]>? CsvExporter
    {
        get => csvExporter.Value;
        set => csvExporter.Value = value;
    }

    /// <summary>Vor jedem Argon2-Lauf (aus <c>Kdf.DeriveKek</c>).</summary>
    internal static void BeforeArgon()
    {
        KdfRendezvous?.Arrive();
        KdfObserverHook?.Observe();
    }

    internal sealed class Counter
    {
        private int n;

        internal void Increment() => Interlocked.Increment(ref n);

        internal int Value => Volatile.Read(ref n);
    }

    /// <summary>Zählt die Argon2-Läufe und ruft <c>action</c> mit der Nummer des Laufs auf (vor der Rechnung).</summary>
    internal sealed class KdfObserver(Action<int> action)
    {
        private int n;

        internal int Runs => Volatile.Read(ref n);

        internal void Observe() => action(Interlocked.Increment(ref n));
    }

    /// <summary>Treffpunkt für <c>parties</c> Argon2-Läufe. Kommt einer allein an, wartet er höchstens
    /// <c>timeout</c> und zählt das als verpasst.</summary>
    internal sealed class Rendezvous(int parties = 2, double timeoutSeconds = 5)
    {
        // Monitor statt Lock: Wait/PulseAll brauchen einen Monitor-Riegel.
        private readonly object gate = new();
        private int waiting;
        private int round;
        private int arrivals;
        private int missed;

        internal int Arrivals { get { lock (gate) { return arrivals; } } }

        internal int Missed { get { lock (gate) { return missed; } } }

        internal void Arrive()
        {
            lock (gate)
            {
                arrivals++;
                waiting++;
                if (waiting == parties)
                {
                    waiting = 0;
                    round++;
                    Monitor.PulseAll(gate);
                    return;
                }
                var myRound = round;
                var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
                while (round == myRound)
                {
                    var left = deadline - DateTime.UtcNow;
                    if (left <= TimeSpan.Zero || !Monitor.Wait(gate, left))
                    {
                        if (round == myRound)
                        {
                            waiting--;
                            missed++;
                        }
                        return;
                    }
                }
            }
        }
    }
}
#endif
