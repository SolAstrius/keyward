import SwiftUI
import AppKit

struct ContentView: View {
    @EnvironmentObject var store: EventStore
    @State private var selection: AgentEvent.ID?
    @State private var query = ""
    @State private var signaturesOnly = true
    @State private var health: AgentHealth.Status = .unreachable("checking")

    private var filtered: [AgentEvent] {
        store.events
            .filter { !signaturesOnly || $0.kind == .sign }
            .filter { query.isEmpty || matches($0, query) }
            .reversed()
    }

    private func matches(_ e: AgentEvent, _ q: String) -> Bool {
        let hay = [e.appName, e.who.destination ?? "", e.keyComment ?? "",
                   e.upstream ?? "", e.who.chain, e.outcome]
            .joined(separator: " ").lowercased()
        return hay.contains(q.lowercased())
    }

    var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                HealthBanner(status: health)
                List(filtered, selection: $selection) { event in
                    EventRow(event: event).tag(event.id)
                }
                .listStyle(.inset)
            }
            .searchable(text: $query, placement: .sidebar, prompt: "app, host, key")
            .toolbar {
                ToolbarItem {
                    Picker("", selection: $signaturesOnly) {
                        Text("Signatures").tag(true)
                        Text("All activity").tag(false)
                    }
                    .pickerStyle(.segmented)
                }
            }
            .navigationSplitViewColumnWidth(min: 320, ideal: 380)
        } detail: {
            if let id = selection, let event = store.events.first(where: { $0.id == id }) {
                EventDetail(event: event)
            } else {
                ContentUnavailableView(
                    "Nothing selected",
                    systemImage: "key.horizontal",
                    description: Text("Pick a request to see which app asked, what it signed, and where it was going.")
                )
            }
        }
        .onChange(of: filtered.map(\.id)) { _, ids in
            // Land on the newest request rather than an empty pane; only when
            // the user has not chosen one themselves.
            if selection == nil || !ids.contains(where: { $0 == selection }) {
                selection = ids.first
            }
        }
        .task {
            while !Task.isCancelled {
                let s = await Task.detached { AgentHealth.check() }.value
                health = s
                try? await Task.sleep(for: .seconds(5))
            }
        }
    }
}

struct HealthBanner: View {
    let status: AgentHealth.Status

    var body: some View {
        HStack(spacing: 8) {
            Circle()
                .fill(status.isHealthy ? Color.green : Color.orange)
                .frame(width: 8, height: 8)
            Text(status.label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.quaternary.opacity(0.4))
    }
}

struct EventRow: View {
    @EnvironmentObject var store: EventStore
    let event: AgentEvent

    var body: some View {
        HStack(spacing: 10) {
            ZStack(alignment: .bottomTrailing) {
                if let icon = store.appIcon(for: event) {
                    Image(nsImage: icon).resizable().frame(width: 30, height: 30)
                } else {
                    Image(systemName: "app.dashed")
                        .frame(width: 30, height: 30)
                        .foregroundStyle(.tertiary)
                }
                Image(systemName: event.purposeSymbol)
                    .font(.system(size: 9, weight: .bold))
                    .foregroundStyle(.white)
                    .padding(2.5)
                    .background(Circle().fill(event.succeeded ? Color.accentColor : Color.orange))
                    .offset(x: 3, y: 3)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(event.summary).font(.body).lineLimit(1)
                Text(event.provenance)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 2) {
                Text(event.date, format: .dateTime.hour().minute().second())
                    .font(.caption2).foregroundStyle(.secondary)
                if !event.succeeded {
                    Text(event.outcome).font(.caption2).foregroundStyle(.orange)
                }
            }
        }
        .padding(.vertical, 3)
    }
}

struct EventDetail: View {
    @EnvironmentObject var store: EventStore
    let event: AgentEvent

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Pinned rather than scrolled: the identity of the caller is the
            // whole point of this pane, so it must never scroll out of view or
            // hide under the toolbar.
            header
                .padding(.horizontal, 24)
                .padding(.vertical, 16)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    if event.kind == .sign {
                        Section2("Purpose") {
                            Row("What", event.who.purpose.kind.label)
                            if let h = event.who.purpose.host { Row("Server", h, mono: true) }
                            if let r = event.who.purpose.repo { Row("Repository", r) }
                            if let rp = event.who.purpose.repoPath, rp != event.who.purpose.repo {
                                Row("Repo path", rp, mono: true)
                            }
                            if let rr = event.who.purpose.remoteRepo { Row("Remote", rr, mono: true) }
                            if let ns = event.who.purpose.namespace { Row("Namespace", ns) }
                            if let rc = event.who.purpose.remoteCommand { Row("Ran", rc, mono: true) }
                        }
                    }

                    Section2("Request") {
                        Row("Action", event.kind.label)
                        Row("Outcome", event.outcome)
                        Row("Took", "\(event.durationMs) ms")
                        Row("When", event.date.formatted(date: .abbreviated, time: .standard))
                    }

                    if event.keyFp != nil || event.upstream != nil {
                        Section2("Key") {
                            if let c = event.keyComment { Row("Comment", c) }
                            if let f = event.keyFp { Row("Fingerprint", f, mono: true) }
                            if let u = event.upstream { Row("Held by", u) }
                        }
                    }

                    if event.who.destination != nil || event.boundHostFp != nil {
                        Section2("Destination") {
                            if let d = event.who.destination { Row("Target", d, mono: true) }
                            if let h = event.boundHostFp { Row("Host key", h, mono: true) }
                        }
                    }

                    Section2("Who asked") {
                        Row("Process", event.who.process?.display ?? "—")
                        Row("PID", String(event.who.pid))
                        if !event.who.apps.isEmpty {
                            Row("Bundles", event.who.apps.map(\.name).joined(separator: "  ←  "))
                        }
                        if let cmd = event.who.process?.commandLine, !cmd.isEmpty {
                            Row("Command", cmd, mono: true)
                        }
                    }

                    Section2("Process chain") {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(Array(event.who.ancestry.reversed().enumerated()), id: \.offset) { idx, p in
                                HStack(spacing: 8) {
                                    Text(String(repeating: "   ", count: idx) + "└ ")
                                        .font(.system(.caption, design: .monospaced))
                                        .foregroundStyle(.tertiary)
                                    Text(p.display).font(.system(.caption, design: .monospaced))
                                    Text("\(p.pid)").font(.caption2).foregroundStyle(.tertiary)
                                }
                            }
                        }
                    }
                }
                .padding(24)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .navigationTitle(event.appName)
        .navigationSubtitle(event.summary)
    }

    private var header: some View {
        HStack(spacing: 14) {
            if let icon = store.appIcon(for: event) {
                Image(nsImage: icon).resizable().frame(width: 52, height: 52)
            } else {
                Image(systemName: event.purposeSymbol)
                    .font(.system(size: 30))
                    .frame(width: 52, height: 52)
                    .foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 3) {
                Text(event.summary).font(.title3).bold().lineLimit(2)
                Text(event.provenance).font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
        }
    }
}

// MARK: - Small building blocks

struct Section2<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title.uppercased())
                .font(.caption2).bold()
                .foregroundStyle(.tertiary)
            VStack(alignment: .leading, spacing: 6) { content }
        }
    }
}

struct Row: View {
    let label: String
    let value: String
    var mono: Bool = false

    init(_ label: String, _ value: String, mono: Bool = false) {
        self.label = label
        self.value = value
        self.mono = mono
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 92, alignment: .leading)
            Text(value)
                .font(mono ? .system(.caption, design: .monospaced) : .callout)
                .textSelection(.enabled)
            Spacer()
        }
    }
}
