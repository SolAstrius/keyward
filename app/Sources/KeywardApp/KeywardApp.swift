import SwiftUI

@main
struct KeywardApp: App {
    @StateObject private var store = EventStore()

    var body: some Scene {
        Window("Keyward", id: "main") {
            ContentView()
                .environmentObject(store)
                .frame(minWidth: 860, minHeight: 520)
                .onAppear { store.start() }
        }
        .commands {
            CommandGroup(replacing: .newItem) {}
        }

        MenuBarExtra("Keyward", systemImage: "key.horizontal.fill") {
            MenuBarContent().environmentObject(store)
        }
    }
}

struct MenuBarContent: View {
    @EnvironmentObject var store: EventStore
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let recent = store.signEvents.suffix(6).reversed()
        if recent.isEmpty {
            Text("No signatures yet")
        } else {
            ForEach(Array(recent), id: \.id) { e in
                Text("\(e.appName) — \(e.who.destination ?? e.keyComment ?? e.outcome)")
            }
        }
        Divider()
        Toggle("Notify on every signature", isOn: $store.notifyOnSign)
        Divider()
        Button("Open Keyward") { openWindow(id: "main") }
        Button("Quit") { NSApplication.shared.terminate(nil) }
    }
}
