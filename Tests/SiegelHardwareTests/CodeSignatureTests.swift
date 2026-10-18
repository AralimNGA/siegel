import Foundation
import Testing
@testable import SiegelHardware

@Suite("Signatur-Selbstprüfung")
struct CodeSignatureTests {
    static let codesign = URL(fileURLWithPath: "/usr/bin/codesign")
    static let executable = URL(fileURLWithPath: "/usr/bin/true")
    static var toolsPresent: Bool {
        FileManager.default.isExecutableFile(atPath: codesign.path) && FileManager.default.fileExists(atPath: executable.path)
    }

    /// Kleines Bündel, ad-hoc signiert wie build.sh (`--options runtime`, ohne Zeitstempel).
    func signedBundle() throws -> (dir: URL, app: URL) {
        let dir = tempDirectory("siegel-sig")
        let app = dir.appendingPathComponent("Probe.app", isDirectory: true)
        let macos = app.appendingPathComponent("Contents/MacOS", isDirectory: true)
        let resources = app.appendingPathComponent("Contents/Resources", isDirectory: true)
        try FileManager.default.createDirectory(at: macos, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: resources, withIntermediateDirectories: true)
        try FileManager.default.copyItem(at: Self.executable, to: macos.appendingPathComponent("Probe"))
        let plist: [String: Any] = ["CFBundleExecutable": "Probe", "CFBundleIdentifier": "ch.siegel.probe",
                                    "CFBundlePackageType": "APPL"]
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            .write(to: app.appendingPathComponent("Contents/Info.plist"))
        try Data("Ressource".utf8).write(to: resources.appendingPathComponent("text.txt"))
        let p = Process()
        p.executableURL = Self.codesign
        p.arguments = ["--force", "--options", "runtime", "--timestamp=none", "--sign", "-", app.path]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        p.waitUntilExit()
        try #require(p.terminationStatus == 0)
        return (dir, app)
    }

    @Test func ausserhalbEinesBuendelsGueltig() {
        // swift test läuft nicht aus einem .app-Bündel.
        #expect(Bundle.main.bundleURL.pathExtension != "app")
        #expect(CodeSignatureCheck.mainBundleIsValid())
    }

    @Test(.enabled(if: toolsPresent))
    func signiertGueltigVeraendertUngueltig() throws {
        let (dir, app) = try signedBundle()
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(CodeSignatureCheck.bundleIsValid(at: app))
        let resource = app.appendingPathComponent("Contents/Resources/text.txt")
        try Data("Ressource!".utf8).write(to: resource)
        #expect(!CodeSignatureCheck.bundleIsValid(at: app))
    }

    @Test(.enabled(if: toolsPresent))
    func zusaetzlicheOderFehlendeDatei() throws {
        do {
            let (dir, app) = try signedBundle()
            defer { try? FileManager.default.removeItem(at: dir) }
            try Data("fremd".utf8).write(to: app.appendingPathComponent("Contents/Resources/fremd.txt"))
            #expect(!CodeSignatureCheck.bundleIsValid(at: app))
        }
        do {
            let (dir, app) = try signedBundle()
            defer { try? FileManager.default.removeItem(at: dir) }
            try FileManager.default.removeItem(at: app.appendingPathComponent("Contents/Resources/text.txt"))
            #expect(!CodeSignatureCheck.bundleIsValid(at: app))
        }
    }

    @Test(.enabled(if: toolsPresent))
    func veraendertesProgramm() throws {
        let (dir, app) = try signedBundle()
        defer { try? FileManager.default.removeItem(at: dir) }
        let binary = app.appendingPathComponent("Contents/MacOS/Probe")
        var bytes = try Data(contentsOf: binary)
        let middle = bytes.count / 2
        bytes[middle] ^= 0xFF
        try bytes.write(to: binary)
        #expect(!CodeSignatureCheck.bundleIsValid(at: app))
    }

    @Test func unsigniertOderFehlend() throws {
        let dir = tempDirectory("siegel-sig")
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(!CodeSignatureCheck.bundleIsValid(at: dir.appendingPathComponent("Fehlt.app")))
        let fake = dir.appendingPathComponent("Leer.app/Contents/MacOS", isDirectory: true)
        try FileManager.default.createDirectory(at: fake, withIntermediateDirectories: true)
        try Data("#!/bin/sh\n".utf8).write(to: fake.appendingPathComponent("Leer"))
        #expect(!CodeSignatureCheck.bundleIsValid(at: dir.appendingPathComponent("Leer.app")))
    }

    @Test func laufenderProzessGueltig() {
        #expect(CodeSignatureCheck.runningCodeIsValid())
    }
}
