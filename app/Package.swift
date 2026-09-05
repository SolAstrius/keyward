// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "KeywardApp",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(
            name: "KeywardApp",
            path: "Sources/KeywardApp",
            swiftSettings: [.swiftLanguageMode(.v5)]
        )
    ]
)
