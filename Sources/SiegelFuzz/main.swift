// SiegelFuzz (SPEC §21): mutationsbasierter, strukturbewusster Fuzzer für die Parser und Abläufe von Siegel.
// Gebaut und gefahren über skripte/fuzz.sh (Debug-Bau mit Address-Sanitizer). Ausgabe nur Zähler, Codes und
// Prüfsummen – nie Eingaben oder Geheimnisse; Funde landen als Datei im Fundordner.
//
// Aufruf: SiegelFuzz --ziel <name|alle> --sekunden N --saat S [--fundordner P] [--arbeitsordner P] [--wurzel P]
//                    [--weiter] [--neue-saat] [--max-eingaben N]
//         SiegelFuzz --wiederholen <datei> --ziel <name>      eine gesicherte Eingabe erneut einspielen
//         SiegelFuzz --liste                                  Ziele ausgeben

#if DEBUG
import Foundation

// Eigener Arbeits-Thread: Der Kern verlangt Argon2- und Speicherpfade ausserhalb des Main-Threads
// (dispatchPrecondition), und grosse Eingaben brauchen einen grossen Stapel.
let arbeit = Thread {
    FuzzHaupt.start(Array(CommandLine.arguments.dropFirst()))
    exit(0)
}
arbeit.stackSize = 256 << 20
arbeit.start()
dispatchMain()
#else
import Foundation

FileHandle.standardError.write(Data("SiegelFuzz läuft nur im Debug-Bau (skripte/fuzz.sh).\n".utf8))
exit(2)
#endif
