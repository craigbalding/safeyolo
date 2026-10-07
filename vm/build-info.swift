#!/usr/bin/env swift
// Generate metadata for the signed VM helper. Verification runs in that helper.
import Foundation

func command(_ arguments: [String], in root: URL) throws -> String {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = arguments
    process.currentDirectoryURL = root
    let pipe = Pipe()
    process.standardOutput = pipe
    try process.run()
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        throw NSError(domain: "SafeYoloBuild", code: Int(process.terminationStatus),
                      userInfo: [NSLocalizedDescriptionKey: "command failed: \(arguments[0])"])
    }
    return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
}

do {
    let args = CommandLine.arguments
    guard args.count == 4, args[1] == "--profile", ["production", "development"].contains(args[2]) else {
        throw NSError(domain: "SafeYoloBuild", code: 1,
                      userInfo: [NSLocalizedDescriptionKey: "Usage: build-info.swift --profile production|development OUTPUT"])
    }
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
    let environment = ProcessInfo.processInfo.environment
    let revision = try environment["SAFEYOLO_BUILD_REVISION"] ?? command(["git", "rev-parse", "HEAD"], in: root)
    guard revision.range(of: "^[0-9a-f]{40}$", options: .regularExpression) != nil else {
        throw NSError(domain: "SafeYoloBuild", code: 1,
                      userInfo: [NSLocalizedDescriptionKey: "source revision must be a full Git SHA"])
    }
    let dirty: Any
    if let supplied = environment["SAFEYOLO_BUILD_DIRTY"] {
        guard ["yes", "no", "unknown"].contains(supplied) else {
            throw NSError(domain: "SafeYoloBuild", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "SAFEYOLO_BUILD_DIRTY must be yes, no or unknown"])
        }
        dirty = supplied == "unknown" ? NSNull() : supplied == "yes" as Any
    } else {
        dirty = try !command(["git", "status", "--porcelain", "--untracked-files=normal"], in: root).isEmpty
    }
    let manifest = try String(contentsOf: root.appendingPathComponent("proxy/Cargo.toml"), encoding: .utf8)
    let expression = try NSRegularExpression(pattern: "(?m)^version = \"([^\"]+)\"$")
    guard let match = expression.firstMatch(in: manifest, range: NSRange(manifest.startIndex..., in: manifest)),
          let range = Range(match.range(at: 1), in: manifest) else {
        throw NSError(domain: "SafeYoloBuild", code: 1,
                      userInfo: [NSLocalizedDescriptionKey: "native product version is missing"])
    }
    let metadata: [String: Any] = [
        "schema_version": 1, "version": String(manifest[range]), "git_sha": revision,
        "git_dirty": dirty, "build_profile": args[2],
        "swift_compiler": try command(["swift", "--version"], in: root).components(separatedBy: "\n")[0],
        "optimization": "release", "symbols": "DWARF+dSYM"
    ]
    let destination = URL(fileURLWithPath: args[3])
    try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
    var data = try JSONSerialization.data(withJSONObject: metadata, options: [.sortedKeys])
    data.append(0x0a)
    try data.write(to: destination, options: .atomic)
} catch {
    fputs("VM helper metadata failed: \(error.localizedDescription)\n", stderr)
    exit(1)
}
