// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "safeyolo-vm",
    // macOS 14+ required for VZVirtualMachine.saveMachineStateTo /
    // restoreMachineStateFrom (used by VMSnapshot for fast warm-boot).
    // Gated at compile time, not runtime — the snapshot feature is
    // load-bearing for the helper's value proposition; macOS 13 callers
    // would lose the warm-boot path entirely.
    platforms: [.macOS(.v14)],
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
