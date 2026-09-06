import SwiftUI
import AppKit

/// Context for one pending signature, sent by the daemon.
struct PendingSignature: Codable {
    var headline: String
    var app: String?
    var appBundle: String?
    var process: String?
    var key: String?
    var fingerprint: String?
    var host: String?
    var repo: String?
    var branch: String?
    var subject: String?
    var command: String?
    var script: Bool?
    var chain: [String]
    var session: String?
}

enum CardMetrics {
    static let pad: CGFloat = 24
    static let gap: CGFloat = 20
    static let baseDetail: CGFloat = 470
    /// A script needs room to wrap rather than be cut off mid-pipeline.
    static let wideDetail: CGFloat = 660

    static func detailWidth(for ctx: PendingSignature) -> CGFloat {
        if let c = ctx.command, ApprovalView.isMultilineCommand(c) { return wideDetail }
        return baseDetail
    }
}

/// The card the system Touch ID sheet docks into.
///
/// The sheet belongs to `coreautha`, sits at window layer 1000, and cannot be
/// restyled, reparented or moved — so instead of fighting it, the card is laid
/// out *around* it: details on the left, and a reserved slot on the right of
/// exactly the sheet's dimensions. The panel finds the sheet's real frame at
/// runtime and positions itself so the sheet lands in that slot.
struct ApprovalView: View {
    let ctx: PendingSignature
    let sheetSize: CGSize

    var body: some View {
        HStack(alignment: .top, spacing: CardMetrics.gap) {
            details
                .frame(width: CardMetrics.detailWidth(for: ctx), alignment: .leading)
            // The slot. Empty on purpose — the system draws into it. Pinned to
            // the top so a card that grew for a long script still lines up.
            VStack(spacing: 0) {
                Color.clear.frame(width: sheetSize.width, height: sheetSize.height)
                Spacer(minLength: 0)
            }
        }
        .padding(CardMetrics.pad)
        .background(
            ZStack {
                VisualEffect(material: .hudWindow)
                Color.black.opacity(0.55)
            }
            .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 20, style: .continuous)
                    .strokeBorder(.white.opacity(0.13), lineWidth: 1)
            )
            .shadow(color: .black.opacity(0.55), radius: 40, y: 16)
        )
        .preferredColorScheme(.dark)
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 11) {
                if let b = ctx.appBundle, let icon = iconFor(b) {
                    Image(nsImage: icon).resizable().frame(width: 34, height: 34)
                }
                Text(ctx.headline)
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(.white)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 0)
            }
            .padding(.bottom, 14)

            if let c = ctx.command, isMultiline(c) {
                scriptBlock(c).padding(.bottom, 11)
            }

            // Grouped, with a rule between groups: what is being done, who
            // asked, and which key. Label-above-value gives each value the full
            // width, which is what lets the font be readable at all.
            ForEach(Array(groups.enumerated()), id: \.offset) { idx, group in
                if idx > 0 {
                    Divider().overlay(.white.opacity(0.10))
                        .padding(.vertical, 11)
                }
                VStack(alignment: .leading, spacing: 9) {
                    ForEach(group, id: \.label) { block($0) }
                }
            }
        }
        .frame(minHeight: sheetSize.height, alignment: .center)
    }

    private struct Field: Hashable {
        let label: String
        let value: String
        var mono: Bool = true
        var lines: Int = 1
    }

    /// Three groups, five values at most. Everything else — fingerprint, raw
    /// session id, the untrimmed process chain — lives in the app window, where
    /// there is room to read it.
    private var groups: [[Field]] {
        var act: [Field] = []
        if let s = ctx.subject { act.append(Field(label: "Commit", value: s, mono: false, lines: 2)) }
        // A multi-line script gets its own block below, not a squashed row.
        if let c = ctx.command, !isMultiline(c) { act.append(Field(label: "Command", value: c, lines: 2)) }
        // The headline already names the host; repeating it as a field is noise.
        if let h = ctx.host, !ctx.headline.contains(h) {
            act.append(Field(label: "Server", value: h))
        }
        if let r = ctx.repo, ctx.host == nil { act.append(Field(label: "Repository", value: r)) }

        // One line, not two: who asked and how they got here are one thought.
        var who: [Field] = []
        var by = requestedBy
        if let v = shortChain { by += "   ·   \(v)" }
        who.append(Field(label: "Requested by", value: by, mono: false, lines: 2))

        var key: [Field] = []
        if let k = ctx.key { key.append(Field(label: "Key", value: k)) }

        return [act, who, key].filter { !$0.isEmpty }
    }

    private var requestedBy: String {
        let app = ctx.app ?? ctx.process ?? "an unknown process"
        if let s = ctx.session { return "\(app) — \(s)" }
        return app
    }

    /// Collapses repeats and the app's own launch helpers, which say nothing.
    private var shortChain: String? {
        var seen: [String] = []
        for name in ctx.chain {
            let n = name.lowercased()
            if n == ctx.app?.lowercased() || n == "disclaimer" { continue }
            if seen.last?.lowercased() == n { continue }
            seen.append(name)
        }
        if seen.count > 4 {
            seen = [seen.first!, "…"] + seen.suffix(2)
        }
        return seen.isEmpty ? nil : seen.joined(separator: " › ")
    }

    static let scriptMaxLines = 10

    static func isMultilineCommand(_ c: String) -> Bool {
        c.contains("\n") || c.count > 72
    }
    private func isMultiline(_ c: String) -> Bool { Self.isMultilineCommand(c) }

    struct CodeLine: Identifiable {
        let id: Int
        let text: String
        let comment: Bool
    }

    /// Section echoes become headings; everything else keeps its shell shape.
    static func codeLines(_ raw: String) -> [CodeLine] {
        var out: [CodeLine] = []
        for line in raw.split(separator: "\n", omittingEmptySubsequences: false) {
            let l = String(line)
            if let sec = ShellHighlighter.sectionTitle(l) {
                out.append(CodeLine(id: out.count, text: "# " + sec.title, comment: true))
                if !sec.rest.isEmpty {
                    out.append(CodeLine(id: out.count, text: sec.rest, comment: false))
                }
                continue
            }
            out.append(CodeLine(id: out.count, text: l, comment: false))
        }
        return out
    }

    /// The actual work, when it arrived as a script rather than a command.
    private func scriptBlock(_ raw: String) -> some View {
        let all = Self.codeLines(raw)
        let shown = Array(all.prefix(Self.scriptMaxLines))
        let hidden = all.count - shown.count
        return VStack(alignment: .leading, spacing: 5) {
            Text((ctx.script == true ? "SCRIPT" : "COMMAND")
                 + (all.count > 1 ? " · \(all.count) LINES" : ""))
                .font(.system(size: 9.5, weight: .semibold))
                .tracking(0.7)
                .foregroundStyle(.white.opacity(0.40))
            VStack(alignment: .leading, spacing: 3) {
                ForEach(shown) { line in
                    Text(ShellHighlighter.attributed(line.text, comment: line.comment))
                        .font(.system(size: 11.5, design: .monospaced))
                        .lineLimit(3)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                if hidden > 0 {
                    Text("… \(hidden) more line\(hidden == 1 ? "" : "s")")
                        .font(.system(size: 10.5))
                        .foregroundStyle(.white.opacity(0.45))
                        .padding(.top, 3)
                }
            }
            .padding(11)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(.black.opacity(0.38))
                    .overlay(RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .strokeBorder(.white.opacity(0.08), lineWidth: 1))
            )
        }
        .textSelection(.enabled)
    }

    /// The panel needs the height before the view exists, so it is computed
    /// from the same numbers the layout uses rather than measured afterwards.
    static func preferredHeight(for ctx: PendingSignature, sheetHeight: CGFloat) -> CGFloat {
        var h: CGFloat = 48                       // header
        if let c = ctx.command, isMultilineCommand(c) {
            let width = CardMetrics.detailWidth(for: ctx) - 22
            let perLine = max(20.0, Double(width) / 6.9)   // 11.5pt monospace
            let all = codeLines(c)
            let shown = all.prefix(scriptMaxLines)
            // Wrapped lines cost more than one row each.
            let visual = shown.reduce(0.0) { acc, l in
                acc + Double(min(3, max(1, Int(ceil(Double(l.text.count) / perLine)))))
            }
            h += 13 + 5 + 22 + CGFloat(visual) * 17 + (all.count > shown.count ? 18 : 0) + 11
        }
        var rows = 0
        if ctx.subject != nil { rows += 1 }
        if let c = ctx.command, !isMultilineCommand(c) { rows += 1 }
        if let hst = ctx.host, !ctx.headline.contains(hst) { rows += 1 }
        if ctx.host == nil && ctx.repo != nil { rows += 1 }
        rows += 1                                  // requested by (+ via, same row)
        if ctx.key != nil { rows += 1 }            // key
        h += CGFloat(rows) * 36 + 8                // blocks + dividers
        return max(sheetHeight, h)
    }

    private func block(_ f: Field) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(f.label.uppercased())
                .font(.system(size: 9.5, weight: .semibold))
                .tracking(0.7)
                .foregroundStyle(.white.opacity(0.40))
            Text(f.value)
                .font(f.mono ? .system(size: 13, design: .monospaced)
                             : .system(size: 13.5))
                .foregroundStyle(.white)
                .lineLimit(f.lines)
                .truncationMode(.middle)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var provenance: String? {
        var parts: [String] = []
        if let a = ctx.app { parts.append(a) }
        if let p = ctx.process, p != ctx.app { parts.append(p) }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    private func iconFor(_ bundle: String) -> NSImage? {
        FileManager.default.fileExists(atPath: bundle)
            ? NSWorkspace.shared.icon(forFile: bundle) : nil
    }
}

/// The same blur the system dialogs are built from.
struct VisualEffect: NSViewRepresentable {
    let material: NSVisualEffectView.Material
    func makeNSView(context: Context) -> NSVisualEffectView {
        let v = NSVisualEffectView()
        v.material = material
        v.blendingMode = .behindWindow
        v.state = .active
        return v
    }
    func updateNSView(_ v: NSVisualEffectView, context: Context) { v.material = material }
}
