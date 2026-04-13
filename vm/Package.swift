// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "safeyolo-vm",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "safeyolo-vm",
            path: "Sources/SafeYoloVM",
            linkerSettings: [
                .linkedFramework("Virtualization"),
            ]
        )
    ]
)
