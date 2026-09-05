import Foundation

/// Mirrors the daemon's event schema. The daemon is the single writer; the app
/// only ever reads, so a decode failure on one line must never lose the rest.

enum EventKind: String, Codable {
    case listIdentities = "list_identities"
    case sign
    case sessionBind = "session_bind"
    case other

    init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = EventKind(rawValue: raw) ?? .other
    }

    var label: String {
        switch self {
        case .listIdentities: return "Listed keys"
        case .sign: return "Signed"
        case .sessionBind: return "Bound session"
        case .other: return "Other"
        }
    }

    var symbol: String {
        switch self {
        case .listIdentities: return "list.bullet"
        case .sign: return "signature"
        case .sessionBind: return "link"
        case .other: return "questionmark"
        }
    }
}

enum PurposeKind: String, Codable {
    case sshLogin = "ssh_login"
    case remoteCommand = "remote_command"
    case gitFetch = "git_fetch"
    case gitPush = "git_push"
    case gitOverSsh = "git_over_ssh"
    case commitSigning = "commit_signing"
    case signing
    case fileTransfer = "file_transfer"
    case unknown

    init(from decoder: Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = PurposeKind(rawValue: raw) ?? .unknown
    }

    var symbol: String {
        switch self {
        case .sshLogin: return "terminal"
        case .remoteCommand: return "chevron.left.forwardslash.chevron.right"
        case .gitFetch: return "arrow.down.circle"
        case .gitPush: return "arrow.up.circle"
        case .gitOverSsh: return "arrow.triangle.branch"
        case .commitSigning: return "signature"
        case .signing: return "pencil.and.outline"
        case .fileTransfer: return "doc.on.doc"
        case .unknown: return "questionmark.circle"
        }
    }

    var label: String {
        switch self {
        case .sshLogin: return "SSH login"
        case .remoteCommand: return "Remote command"
        case .gitFetch: return "git fetch"
        case .gitPush: return "git push"
        case .gitOverSsh: return "git over SSH"
        case .commitSigning: return "Commit signing"
        case .signing: return "Signing"
        case .fileTransfer: return "File transfer"
        case .unknown: return "Unknown"
        }
    }
}

struct Purpose: Codable, Hashable {
    let kind: PurposeKind
    let summary: String
    let host: String?
    let repo: String?
    let repoPath: String?
    let remoteRepo: String?
    let namespace: String?
    let remoteCommand: String?
}

/// The declaration file is free-form JSON, so it needs a general value type.
enum JSONValue: Codable, Hashable {
    case string(String), number(Double), bool(Bool), null
    case array([JSONValue]), object([String: JSONValue])

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(Double.self) { self = .number(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode([JSONValue].self) { self = .array(v) }
        else if let v = try? c.decode([String: JSONValue].self) { self = .object(v) }
        else { self = .null }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .string(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .bool(let v): try c.encode(v)
        case .null: try c.encodeNil()
        case .array(let v): try c.encode(v)
        case .object(let v): try c.encode(v)
        }
    }

    var display: String {
        switch self {
        case .string(let v): return v
        case .number(let v): return v == v.rounded() ? String(Int(v)) : String(v)
        case .bool(let v): return v ? "true" : "false"
        case .null: return "—"
        case .array(let v): return v.map(\.display).joined(separator: ", ")
        case .object(let v): return v.map { "\($0.key): \($0.value.display)" }.joined(separator: ", ")
        }
    }
}

struct GitContext: Codable, Hashable {
    let branch: String?
    let remote: String?
    /// Subject line of the commit message being signed.
    let subject: String?
}

struct RequestContext: Codable, Hashable {
    let env: [String: String]
    let envFromPid: Int32?
    let envFrom: String?
    let declared: [String: JSONValue]?
    let declaredFromPid: Int32?
    let git: GitContext?

    /// Session identity of the agent that ultimately caused this.
    var sessionID: String? { env["CLAUDE_CODE_HOST_SESSION_ID"] }
    var entrypoint: String? { env["CLAUDE_CODE_ENTRYPOINT"] }
    /// snake_case / SCREAMING_CASE -> "Words A Human Reads"
    static func humanise(_ key: String) -> String {
        key.replacingOccurrences(of: "KEYWARD_", with: "")
            .split(whereSeparator: { $0 == "_" || $0 == "-" })
            .map { $0.prefix(1).uppercased() + $0.dropFirst().lowercased() }
            .joined(separator: " ")
    }

    /// Everything deliberately declared, from both channels, in one list.
    ///
    /// A declaration filed against a pid is more specific than a variable
    /// inherited from a long-lived session, so it wins a label collision.
    var declarations: [(label: String, value: String)] {
        var out: [(label: String, value: String)] = []
        var seen = Set<String>()
        for (k, v) in (declared ?? [:]).sorted(by: { $0.key < $1.key }) {
            let label = Self.humanise(k)
            if seen.insert(label.lowercased()).inserted { out.append((label, v.display)) }
        }
        for (k, v) in env.filter({ $0.key.hasPrefix("KEYWARD_") }).sorted(by: { $0.key < $1.key }) {
            let label = Self.humanise(k)
            if seen.insert(label.lowercased()).inserted { out.append((label, v)) }
        }
        return out
    }
}

struct ProcInfo: Codable, Hashable {
    let pid: Int32
    let name: String?
    let path: String?
    let cwd: String?
    let args: [String]

    var display: String { name ?? path.map { ($0 as NSString).lastPathComponent } ?? "pid \(pid)" }
    var commandLine: String { args.isEmpty ? (path ?? "") : args.joined(separator: " ") }
}

struct AppInfo: Codable, Hashable {
    let bundlePath: String
    let name: String
    let depth: Int
}

struct Attribution: Codable, Hashable {
    let pid: Int32
    let process: ProcInfo?
    let ancestry: [ProcInfo]
    let app: AppInfo?
    let apps: [AppInfo]
    let destination: String?
    let purpose: Purpose
    let context: RequestContext

    /// ssh <- zsh <- Ghostty, read left to right as caller to launcher.
    var chain: String {
        ancestry.map(\.display).joined(separator: "  ←  ")
    }
}

struct AgentEvent: Codable, Identifiable, Hashable {
    let ts: Double
    let kind: EventKind
    let who: Attribution
    let keyFp: String?
    let keyComment: String?
    let upstream: String?
    let boundHostFp: String?
    let outcome: String
    let durationMs: UInt64

    var id: String { "\(ts)-\(who.pid)-\(kind.rawValue)-\(keyFp ?? "")" }
    var date: Date { Date(timeIntervalSince1970: ts) }
    var succeeded: Bool { !outcome.hasPrefix("error") && outcome != "timeout" && outcome != "denied" }

    var appName: String { who.app?.name ?? who.process?.display ?? "Unknown" }

    /// What happened, in the terms a human cares about.
    var summary: String {
        switch kind {
        case .sign:
            if who.purpose.kind == .commitSigning, let subject = who.context.git?.subject {
                if let repo = who.purpose.repo {
                    return "Signed “\(subject)” in \(repo)"
                }
                return "Signed “\(subject)”"
            }
            return who.purpose.summary
        case .listIdentities: return "Listed keys — \(outcome)"
        case .sessionBind: return who.destination.map { "Bound to \($0)" } ?? "Bound session"
        case .other: return outcome
        }
    }

    /// Secondary line: who carried out the request, and with which key.
    var provenance: String {
        var parts: [String] = []
        if let app = who.app?.name { parts.append(app) }
        if let proc = who.process?.name, proc != who.app?.name { parts.append(proc) }
        if let c = keyComment, !c.isEmpty { parts.append(c) }
        return parts.joined(separator: " · ")
    }

    var purposeSymbol: String {
        kind == .sign ? who.purpose.kind.symbol : kind.symbol
    }
}
