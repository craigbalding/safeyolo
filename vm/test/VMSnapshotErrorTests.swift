import Foundation

@main
struct VMSnapshotErrorTests {
    static func main() {
        let denied = NSError(domain: NSPOSIXErrorDomain, code: 13, userInfo: [
            NSLocalizedDescriptionKey: "private underlying description",
            "credential": "private credential",
        ])
        let restore = NSError(domain: "VZErrorDomain", code: 9, userInfo: [
            NSLocalizedDescriptionKey: "permission denied",
            NSUnderlyingErrorKey: denied,
            "credential": "private credential",
        ])
        let message = VMSnapshot.Error.restoreFailed(restore).localizedDescription
        precondition(message == "restore failed: permission denied [VZErrorDomain code=9; underlying: NSPOSIXErrorDomain code=13]")
        precondition(!message.contains("private"))
        print("PASS restore description retains domain/code and omits underlying descriptions and other userInfo")

        let plain = NSError(domain: "VZErrorDomain", code: 9, userInfo: [
            NSLocalizedDescriptionKey: "restore refused",
        ])
        precondition(VMSnapshot.Error.restoreFailed(plain).localizedDescription ==
            "restore failed: restore refused [VZErrorDomain code=9]")
        print("PASS restore error without an underlying error")

        var chain = denied
        for code in (1...5).reversed() {
            chain = NSError(domain: "VZErrorDomain", code: code, userInfo: [
                NSLocalizedDescriptionKey: "restore refused",
                NSUnderlyingErrorKey: chain,
            ])
        }
        let bounded = VMSnapshot.Error.restoreFailed(chain).localizedDescription
        precondition(bounded.contains("VZErrorDomain code=4"))
        precondition(!bounded.contains("VZErrorDomain code=5"))
        precondition(bounded.hasSuffix("further underlying errors omitted]"))
        precondition(!bounded.contains("private"))
        print("PASS restore error chain stops after four error identities")
    }
}
