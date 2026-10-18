import Foundation
import Testing
@testable import SiegelCore

@Suite("Import/Export im Kern")
struct KernImportExportTests {
    @Test("Host-Schlüssel: klein, IDNA, ohne Schema, ohne Pfad")
    func hostKey() {
        #expect(UnlockedVault.hostKey("HTTPS://Example.COM:8080/a") == "example.com")
        #expect(UnlockedVault.hostKey("example.com/login") == "example.com")
        #expect(UnlockedVault.hostKey("https://bücher.de") == "xn--bcher-kva.de")
        #expect(UnlockedVault.hostKey("xn--bcher-kva.de") == "xn--bcher-kva.de")
        #expect(UnlockedVault.hostKey("  example.com.  ") == "example.com")
        #expect(UnlockedVault.hostKey("") == "")
        #expect(UnlockedVault.importTitle("") == "(Import)")
        #expect(UnlockedVault.importTitle("Bank") == "Bank (Import)")
        #expect(UnlockedVault.importTitle(String(repeating: "x", count: 2048)).utf8.count == 2048)
    }

    @Test("importEntries: nur anhängen, Dubletten, Konflikte mit „(Import)“, Sicherung „vor-import“")
    func importieren() throws {
        let f = try KernVault.make()
        let existing = kernEntry("Beispiel", user: "alice", password: "Alt-Passwort-1", url: "https://example.com/login")
        try f.vault.upsert(existing)
        let stored = try #require(f.vault.entries.first)
        let items = [
            kernEntry("Dublette", user: "alice", password: "Alt-Passwort-1", url: "EXAMPLE.com"),
            kernEntry("Konflikt", user: "alice", password: "Anders-2", url: "https://example.com/other"),
            kernEntry("Neu", user: "bob", password: "x", url: "https://bücher.de"),
            kernEntry("IDN-Dublette", user: "bob", password: "x", url: "https://xn--bcher-kva.de/"),
            kernEntry("Leer", user: "", password: "", url: ""),
            kernEntry("", user: "carol", password: "y", url: "example.com"),
            kernEntry("", user: "alice", password: "Anders-3", url: "example.com"),
        ]
        let report = try f.vault.importEntries(items)
        #expect(report.added == 5)
        #expect(report.skippedDuplicates == 2)
        #expect(report.conflicts == 2)
        #expect(f.vault.generation == 3)
        // Bestand unverändert
        #expect(f.vault.entries.first { $0.id == existing.id } == stored)
        let titles = f.vault.entries.map(\.title)
        #expect(titles == ["Beispiel", "Konflikt (Import)", "Neu", "Leer", "", "(Import)"])
        // angeheftete Sicherung vor dem Import
        let pinned = f.localBackups().filter { $0.reason == "import" }
        #expect(pinned.count == 1)
        #expect(pinned.first?.generation == 2)
        // nur Dubletten → nichts geschrieben
        let again = try f.vault.importEntries([items[0], items[2]])
        #expect(again.added == 0)
        #expect(again.skippedDuplicates == 2)
        #expect(f.vault.generation == 3)
        // gleiche ID wie Bestand → neue ID, Bestand bleibt
        var sameID = kernEntry("Andere Seite", user: "zoe", password: "z", url: "zoe.example")
        sameID.id = existing.id
        _ = try f.vault.importEntries([sameID])
        #expect(f.vault.entries.first { $0.id == existing.id } == stored)
        #expect(f.vault.entries.contains { $0.title == "Andere Seite" && $0.id != existing.id })
        // gelöschte Einträge zählen nicht als Dublette
        try f.vault.delete(id: existing.id)
        let r3 = try f.vault.importEntries([kernEntry("Wieder da", user: "alice", password: "Alt-Passwort-1", url: "example.com")])
        #expect(r3.added == 1)
        #expect(r3.skippedDuplicates == 0)
        #expect(r3.conflicts == 1)   // die beiden „(Import)“-Einträge von alice sind noch aktiv
    }

    @Test("exportCSV: .noindex-Ordner 0700, Datei 0600, vom Backup ausgenommen, iCloud abgelehnt")
    func exportieren() throws {
        let f = try KernVault.make()
        try f.vault.upsert(kernEntry("A", user: "anna", password: "=SUMME(1;2)", url: "https://a.example", notes: "Zeile\n\"zitiert\""))
        let b = kernEntry("B")
        try f.vault.upsert(b)
        try f.vault.delete(id: b.id)
        let parent = f.dir.sub("Export")
        #expect(throws: SiegelError.wrongPassword) { try f.vault.exportCSV(toParent: parent, masterPassword: KT.pw2) }
        #expect(((try? FileManager.default.contentsOfDirectory(atPath: parent.path)) ?? ["x"]).isEmpty)

        let url = try f.vault.exportCSV(toParent: parent, masterPassword: KT.pw1)
        let folder = url.deletingLastPathComponent()
        let c = Calendar(identifier: .gregorian).dateComponents([.year, .month, .day], from: Date())
        let day = String(format: "%04d-%02d-%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0)
        #expect(folder.lastPathComponent == "Siegel-Export-\(day).noindex")
        #expect(url.lastPathComponent == "Siegel-Export.csv")
        func mode(_ u: URL) -> Int {
            ((try? FileManager.default.attributesOfItem(atPath: u.path)[.posixPermissions]) as? Int) ?? -1
        }
        #expect(mode(folder) == 0o700)
        #expect(mode(url) == 0o600)
        #expect(try folder.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true)
        #expect(try url.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup == true)
        // Inhalt = CSVExport der nicht gelöschten Einträge (ohne Verlauf)
        #expect(try Data(contentsOf: url) == CSVExport.export(f.vault.entries))
        // zweiter Export am selben Tag → eigener Ordner
        let second = try f.vault.exportCSV(toParent: parent, masterPassword: KT.pw1)
        #expect(second.deletingLastPathComponent().lastPathComponent == "Siegel-Export-\(day)-2.noindex")

        // iCloud Drive wird abgelehnt
        let icloud = f.dir.url.appendingPathComponent("Library/Mobile Documents/com~apple~CloudDocs", isDirectory: true)
        try FileManager.default.createDirectory(at: icloud, withIntermediateDirectories: true)
        #expect(throws: SiegelError.exportLocationRejected("icloud")) {
            try f.vault.exportCSV(toParent: icloud, masterPassword: KT.pw1)
        }
        #expect(((try? FileManager.default.contentsOfDirectory(atPath: icloud.path)) ?? ["x"]).isEmpty)
        #expect(throws: SiegelError.io("export.directory")) {
            try f.vault.exportCSV(toParent: f.dir.url.appendingPathComponent("gibtsnicht"), masterPassword: KT.pw1)
        }
    }
}
