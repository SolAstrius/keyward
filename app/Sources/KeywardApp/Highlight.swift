import SwiftUI

/// A deliberately small shell highlighter.
///
/// Not a parser — it only needs to make a command scannable at a glance: what
/// is a string, what is a substitution, where one command ends and the next
/// begins. A real grammar would be more correct and no more readable.
enum ShellHighlighter {
    private static let palette: [Token: Color] = [
        .comment:  Color(red: 0.51, green: 0.56, blue: 0.62),
        .string:   Color(red: 0.76, green: 0.91, blue: 0.55),
        .variable: Color(red: 0.51, green: 0.67, blue: 1.00),
        .keyword:  Color(red: 0.78, green: 0.57, blue: 0.92),
        .oper:     Color(red: 0.54, green: 0.87, blue: 1.00),
        .plain:    Color.white.opacity(0.92),
    ]

    private enum Token { case comment, string, variable, keyword, oper, plain }

    private static let keywords: Set<String> = [
        "for", "in", "do", "done", "if", "then", "else", "elif", "fi", "while",
        "case", "esac", "function", "return", "local", "export", "set", "echo",
        "printf", "cd", "exit", "sudo",
    ]

    static func attributed(_ line: String, comment: Bool = false) -> AttributedString {
        if comment {
            var a = AttributedString(line)
            a.foregroundColor = palette[.comment]
            return a
        }
        var out = AttributedString()
        let chars = Array(line)
        var i = 0

        func emit(_ s: String, _ t: Token) {
            var a = AttributedString(s)
            a.foregroundColor = palette[t]
            out.append(a)
        }

        while i < chars.count {
            let c = chars[i]

            if c == "#" && (i == 0 || chars[i - 1] == " ") {
                emit(String(chars[i...]), .comment)
                break
            }

            if c == "\"" || c == "'" {
                let quote = c
                var j = i + 1
                while j < chars.count {
                    if chars[j] == "\\" && quote == "\"" { j += 2; continue }
                    if chars[j] == quote { j += 1; break }
                    j += 1
                }
                emit(String(chars[i..<min(j, chars.count)]), .string)
                i = j
                continue
            }

            if c == "$" {
                var j = i + 1
                if j < chars.count && (chars[j] == "{" || chars[j] == "(") {
                    let open = chars[j], close: Character = open == "{" ? "}" : ")"
                    var depth = 0
                    while j < chars.count {
                        if chars[j] == open { depth += 1 }
                        if chars[j] == close { depth -= 1; if depth == 0 { j += 1; break } }
                        j += 1
                    }
                } else {
                    while j < chars.count, chars[j].isLetter || chars[j].isNumber || chars[j] == "_" {
                        j += 1
                    }
                }
                emit(String(chars[i..<min(j, chars.count)]), .variable)
                i = j
                continue
            }

            if c.isLetter || c == "_" {
                var j = i
                while j < chars.count, chars[j].isLetter || chars[j].isNumber
                        || chars[j] == "_" || chars[j] == "-" { j += 1 }
                let word = String(chars[i..<j])
                emit(word, keywords.contains(word) ? .keyword : .plain)
                i = j
                continue
            }

            if "|;&<>()=".contains(c) {
                emit(String(c), .oper)
                i += 1
                continue
            }

            emit(String(c), .plain)
            i += 1
        }
        return out
    }

    /// `echo "=== firewall ==="` is a section marker, not work. Rendering it as
    /// a comment turns a wall of shell into something with headings.
    static func sectionTitle(_ line: String) -> (title: String, rest: String)? {
        let t = line.trimmingCharacters(in: .whitespaces)
        guard t.hasPrefix("echo ") else { return nil }
        let body = String(t.dropFirst(5)).trimmingCharacters(in: .whitespaces)
        guard let q = body.first, q == "\"" || q == "'" else { return nil }
        guard let close = body.dropFirst().firstIndex(of: q) else { return nil }
        let inner = String(body[body.index(after: body.startIndex)..<close])
        guard inner.hasPrefix("===") || inner.hasPrefix("---") else { return nil }
        let title = inner.trimmingCharacters(in: CharacterSet(charactersIn: "=- "))
        var rest = String(body[body.index(after: close)...]).trimmingCharacters(in: .whitespaces)
        if rest.hasPrefix(";") { rest = String(rest.dropFirst()).trimmingCharacters(in: .whitespaces) }
        return (title.isEmpty ? inner : title, rest)
    }
}
