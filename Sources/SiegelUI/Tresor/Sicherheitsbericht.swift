import SiegelCore
import SwiftUI

// Offline-Sicherheitsbericht (SPEC v4 §17): schwache, wiederverwendete, alte und mit dem Master-Passwort gleiche
// Passwörter. Der Kern rechnet aus den Metadaten (auch für geschützte Einträge, ohne Geheimteile zu öffnen); die
// Oberfläche bekommt nur Kennungen. Kein Netzwerk, kein Abgleich mit Leak-Datenbanken (bewusst).

/// Aufbereiteter Bericht: nur Einträge, die es (noch) gibt, in fester Reihenfolge nach Dringlichkeit.
public struct SecurityReportSummary: Sendable, Equatable {
    public enum Category: String, Sendable, CaseIterable, Identifiable {
        case sameAsMaster, reused, weak, old
        public var id: String { rawValue }

        var title: String {
            switch self {
            case .sameAsMaster: "Gleich wie Master-Passwort"
            case .reused: "Wiederverwendet"
            case .weak: "Schwach"
            case .old: "Alt"
            }
        }

        /// Kurz für die Zähler.
        var tileLabel: String {
            switch self {
            case .sameAsMaster: "gleich wie Master"
            case .reused: "wiederverwendet"
            case .weak: "schwach"
            case .old: "über ein Jahr alt"
            }
        }

        var explanation: String {
            switch self {
            case .sameAsMaster:
                "Wer eines dieser Passwörter kennt, kann deinen Tresor öffnen. Ändere sie zuerst."
            case .reused:
                "Dasselbe Passwort bei mehreren Diensten: Wird einer davon gehackt, sind alle offen. Gib jedem Eintrag ein eigenes."
            case .weak:
                "Leicht zu erraten. Ersetze sie im Bearbeiten mit dem Generator."
            case .old:
                "Seit über einem Jahr nicht geändert. Wichtige Konten zuerst erneuern."
            }
        }

        var symbol: String {
            switch self {
            case .sameAsMaster: "key"
            case .reused: "square.on.square"
            case .weak: "gauge.with.dots.needle.0percent"
            case .old: "calendar"
            }
        }
    }

    public let sameAsMaster: [UUID]
    public let reused: [[UUID]]
    public let weak: [UUID]
    public let old: [UUID]
    public let total: Int

    public init(_ report: SecurityReport, existing: Set<UUID>) {
        func filter(_ ids: [UUID]) -> [UUID] {
            var gesehen = Set<UUID>()
            return ids.filter { existing.contains($0) && gesehen.insert($0).inserted }
        }
        sameAsMaster = filter(report.sameAsMaster)
        reused = report.reused.map(filter).filter { $0.count > 1 }
        weak = filter(report.weak)
        old = filter(report.old)
        total = report.total
    }

    public func count(_ category: Category) -> Int {
        switch category {
        case .sameAsMaster: sameAsMaster.count
        case .reused: reused.reduce(0) { $0 + $1.count }
        case .weak: weak.count
        case .old: old.count
        }
    }

    /// Einträge mit mindestens einem Befund.
    public var affected: Set<UUID> {
        Set(sameAsMaster).union(reused.flatMap { $0 }).union(weak).union(old)
    }

    /// Befunde eines Eintrags (für die Zeile im Detail).
    public func findings(for id: UUID) -> [Category] {
        var out: [Category] = []
        if sameAsMaster.contains(id) { out.append(.sameAsMaster) }
        if reused.contains(where: { $0.contains(id) }) { out.append(.reused) }
        if weak.contains(id) { out.append(.weak) }
        if old.contains(id) { out.append(.old) }
        return out
    }

    /// Wie viele andere Einträge teilen das Passwort dieses Eintrags?
    public func reuseCount(for id: UUID) -> Int {
        (reused.first { $0.contains(id) }?.count ?? 1) - 1
    }
}

extension AppModel {
    // MARK: Bericht rechnen

    /// Bericht im Hintergrund neu rechnen (nach jedem Entsperren und jeder Änderung).
    func scheduleSecurityReport() {
        reportTask?.cancel()
        guard let vault, !vault.isLocked else {
            securityReport = nil
            return
        }
        let start = epoch
        reportTask = Task { @MainActor [weak self] in
            let result = await Self.background { vault.securityReport() }
            guard let self, !Task.isCancelled, start == self.epoch, self.vault === vault,
                  case let .success(report) = result else { return }
            self.securityReport = report
        }
    }

    /// Wartet, bis der Bericht für den aktuellen Stand fertig ist (Snapshots, Tests).
    public func updateSecurityReport() async {
        scheduleSecurityReport()
        await reportTask?.value
    }

    /// Bericht für die Anzeige (nur bestehende Einträge).
    public var reportSummary: SecurityReportSummary? {
        guard let securityReport else { return nil }
        return SecurityReportSummary(securityReport, existing: Set(entries.map(\.id)))
    }

    // MARK: Navigation

    /// Seitenleiste „Sicherheit“.
    public func showSecurityReport() {
        guard isUnlocked, browser.mode != .edit else { return }
        browser.resetDetailState()
        browser.confirmingPurge = nil
        browser.mode = .report
        syncVaultCommands()
        scheduleSecurityReport()
    }

    public func closeSecurityReport() {
        guard browser.mode == .report else { return }
        browser.mode = .browse
        syncVaultCommands()
    }

    /// Sprung aus dem Bericht zum Eintrag.
    public func openReportEntry(_ id: UUID) {
        guard browser.mode == .report, entries.contains(where: { $0.id == id }) else { return }
        browser.mode = .browse
        select(id)
        focusList()
    }
}

// MARK: - Ansicht

/// „Sicherheit“ im Detailbereich: vier Zähler, darunter je Kategorie die Einträge (Klick springt zum Eintrag).
struct SecurityReportView: View {
    let model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            DetailHeader {
                Button("Fertig") { model.closeSecurityReport() }
                    .buttonStyle(CompactButtonStyle())
                    .keyboardShortcut(.cancelAction)
            }
            ScrollView(.vertical) {
                VStack(alignment: .leading, spacing: 0) {
                    Text("Sicherheit")
                        .font(Theme.title)
                    Text(Typo.keepCompounds("Offline geprüft: Stärke, Wiederverwendung und Alter deiner Passwörter – auch bei geschützten Einträgen, ohne sie aufzudecken. Ohne Netzwerk und ohne Abgleich mit Listen gestohlener Passwörter."))
                        .font(Theme.body)
                        .foregroundStyle(Theme.secondary)
                        .lineSpacing(2)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, 6)
                    if let summary = model.reportSummary {
                        content(summary)
                    } else {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Bericht wird erstellt …")
                                .font(Theme.caption)
                                .foregroundStyle(Theme.secondary)
                            ProgressLine(active: true)
                                .frame(width: 220)
                        }
                        .padding(.top, 30)
                    }
                }
                .frame(maxWidth: DetailMetrics.column, alignment: .leading)
                .padding(.horizontal, DetailMetrics.side)
                .padding(.top, TresorMetrics.contentTop)
                .padding(.bottom, 48)
                .frame(maxWidth: .infinity)
            }
            .scrollIndicators(.automatic)
        }
    }

    @ViewBuilder
    private func content(_ summary: SecurityReportSummary) -> some View {
        HStack(spacing: 10) {
            ForEach(SecurityReportSummary.Category.allCases) { kategorie in
                ReportTile(category: kategorie, count: summary.count(kategorie))
            }
        }
        .padding(.top, 24)

        if summary.affected.isEmpty {
            HintBox(symbol: "checkmark.shield") {
                Text(summary.total == 1
                     ? "Keine Auffälligkeiten im einzigen Eintrag."
                     : "Keine Auffälligkeiten in \(summary.total) Einträgen.")
            }
            .padding(.top, 22)
        } else {
            Text(summary.affected.count == 1 ? "1 Eintrag braucht Aufmerksamkeit." : "\(summary.affected.count) Einträge brauchen Aufmerksamkeit.")
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .padding(.top, 12)
            ForEach(SecurityReportSummary.Category.allCases) { kategorie in
                if summary.count(kategorie) > 0 {
                    section(kategorie, summary)
                        .padding(.top, 30)
                }
            }
        }
    }

    private func section(_ kategorie: SecurityReportSummary.Category, _ summary: SecurityReportSummary) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: kategorie.symbol)
                    .font(.system(size: 12, weight: .medium))
                    .frame(width: 16)
                Text(kategorie.title)
                    .font(Theme.heading)
                Text("\(summary.count(kategorie))")
                    .font(Theme.heading)
                    .foregroundStyle(Theme.secondary)
                    .monospacedDigit()
            }
            Text(Typo.keepCompounds(kategorie.explanation))
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 4)
                .padding(.leading, 24)
            switch kategorie {
            case .reused:
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(Array(summary.reused.enumerated()), id: \.offset) { _, gruppe in
                        entryList(gruppe, caption: "Gleiches Passwort · \(gruppe.count) Einträge")
                    }
                }
                .padding(.top, 12)
            case .sameAsMaster:
                entryList(summary.sameAsMaster).padding(.top, 12)
            case .weak:
                entryList(summary.weak).padding(.top, 12)
            case .old:
                entryList(summary.old).padding(.top, 12)
            }
        }
    }

    private func entryList(_ ids: [UUID], caption: String? = nil) -> some View {
        let liste = ids.compactMap { id in model.entries.first { $0.id == id } }
            .sorted { AppModel.listTitle($0).localizedStandardCompare(AppModel.listTitle($1)) == .orderedAscending }
        return VStack(alignment: .leading, spacing: 0) {
            if let caption {
                Text(caption)
                    .font(Theme.caption.weight(.medium))
                    .foregroundStyle(Theme.secondary)
                    .padding(.vertical, 8)
                Hairline()
            }
            ForEach(Array(liste.enumerated()), id: \.element.id) { index, entry in
                if index > 0 { Hairline() }
                ReportEntryRow(entry: entry) { model.openReportEntry(entry.id) }
            }
        }
        .padding(.horizontal, 14)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1))
    }
}

/// Zähler einer Kategorie.
struct ReportTile: View {
    var category: SecurityReportSummary.Category
    var count: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("\(count)")
                .font(.system(size: 26, weight: .semibold))
                .monospacedDigit()
                .foregroundStyle(count > 0 ? Theme.text : Theme.secondary)
            Text(category.tileLabel)
                .font(Theme.caption)
                .foregroundStyle(Theme.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.85)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Theme.hairline, lineWidth: 1)
        )
        .accessibilityElement(children: .combine)
    }
}

/// Zeile im Bericht: Titel, Benutzername, Pfeil – Klick öffnet den Eintrag.
struct ReportEntryRow: View {
    var entry: VaultEntry
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(AppModel.listTitle(entry))
                        .font(Theme.bodyMedium)
                        .lineLimit(1)
                    if !entry.username.isEmpty {
                        Text(entry.username)
                            .font(Theme.caption)
                            .foregroundStyle(Theme.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                Spacer(minLength: 8)
                if entry.protection > .normal {
                    ProtectionGlyphs(protection: entry.protection, size: 10)
                        .foregroundStyle(Theme.secondary)
                }
                Image(systemName: "chevron.right")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(Theme.secondary)
            }
            .padding(.vertical, 9)
            .contentShape(Rectangle())
        }
        .buttonStyle(PlainActionButtonStyle())
        .help("Eintrag öffnen")
    }
}

/// „Sicherheit“ unten in der Seitenleiste (über „Zuletzt gelöscht“), mit der Zahl betroffener Einträge.
struct ReportLine: View {
    var affected: Int?
    var active: Bool
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: (affected ?? 0) > 0 ? "exclamationmark.shield" : "checkmark.shield")
                    .font(.system(size: 12))
                    .frame(width: 18)
                Text("Sicherheit")
                    .font(Theme.caption)
                Spacer(minLength: 0)
                if let affected, affected > 0 {
                    Text("\(affected)")
                        .font(Theme.caption.weight(.semibold))
                        .monospacedDigit()
                        .foregroundStyle(active ? Theme.background : Theme.text)
                }
            }
            .foregroundStyle(active ? Theme.background : Theme.secondary)
            .padding(.horizontal, 8)
            .frame(height: 30)
            .background(
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(active ? Theme.text : Color.clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(affected.map { $0 > 0 ? "Sicherheit, \($0) Einträge mit Hinweisen" : "Sicherheit, keine Hinweise" }
                            ?? "Sicherheit")
        .accessibilityAddTraits(active ? .isSelected : [])
    }
}

/// Zeile unter dem Titel im Detail: Befunde des Berichts für diesen Eintrag (ohne „gleich wie Master“, das zeigt
/// schon die Passwort-Zeile).
struct ReportFindingsLine: View {
    var findings: [SecurityReportSummary.Category]
    var reuseCount: Int
    var action: () -> Void

    private var text: String {
        findings.compactMap { kategorie -> String? in
            switch kategorie {
            case .sameAsMaster: nil
            case .reused: reuseCount == 1 ? "auch in 1 anderen Eintrag verwendet" : "auch in \(reuseCount) anderen Einträgen verwendet"
            case .weak: "schwaches Passwort"
            case .old: "seit über einem Jahr nicht geändert"
            }
        }.joined(separator: " · ")
    }

    var body: some View {
        if !text.isEmpty {
            Button(action: action) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Image(systemName: "exclamationmark.shield")
                        .font(.system(size: 11, weight: .medium))
                    Text(Typo.keepCompounds(text.prefix(1).uppercased() + text.dropFirst()))
                        .fixedSize(horizontal: false, vertical: true)
                        .multilineTextAlignment(.leading)
                }
                .font(Theme.caption)
                .foregroundStyle(Theme.text)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help("Im Sicherheitsbericht zeigen")
        }
    }
}
