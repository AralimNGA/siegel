import Testing
@testable import SiegelCore

@Test func sodiumInitialisiert() { #expect(Sodium.ready) }

@Test("SecureBytes: Zufall, Vergleich in konstanter Zeit, Teilbereich, geschwärzt")
func kernSecureBytesGrundlagen() throws {
    let a = try SecureBytes.random(count: 32)
    let b = try SecureBytes.random(count: 32)
    #expect(a.count == 32)
    #expect(!a.constantTimeEquals(b))
    let copy = try a.withUnsafeBytes { try SecureBytes(copying: $0) }
    #expect(copy.constantTimeEquals(a))
    let head = try a.slice(0..<16)
    #expect(head.count == 16)
    #expect(try a.slice(0..<16).constantTimeEquals(head))
    #expect(!head.constantTimeEquals(a))
    let empty = try SecureBytes(count: 0) { _ in }
    #expect(empty.count == 0)
    #expect(empty.constantTimeEquals(try SecureBytes(count: 0) { _ in }))
    let scratch = try SecureBytes.scratch(count: 4)
    scratch.withUnsafeMutableBytes { $0[0] = 7 }
    #expect(scratch.withUnsafeBytes { $0[0] } == 7)
    #expect(String(describing: a) == "SecureBytes(redacted)")
    #expect(a.debugDescription == "SecureBytes(redacted)")
}

@Test("Zufallszahlen gleichverteilt im Bereich")
func kernZufall() {
    var counts = [Int](repeating: 0, count: 11)
    for _ in 0..<11_000 { counts[Int(secureUniform(11))] += 1 }
    #expect(counts.allSatisfy { $0 > 800 && $0 < 1200 })
    #expect(randomBytes(16) != randomBytes(16))
    for _ in 0..<200 {
        let g = VaultStore.randomConfirmationGroups()
        #expect(g.count == 2 && g[0] < g[1] && g[0] >= 0 && g[1] <= 10)
    }
}
