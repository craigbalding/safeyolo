import Darwin
import Foundation
import Virtualization

// MARK: - Argument parsing

struct RunConfig {
    var kernelPath: String = ""
    var initrdPath: String = ""
    var rootfsPath: String = ""
    var overlayPath: String = ""     // optional per-agent writable upper disk (ext4 img). When set, attached as /dev/vdb and the guest's initramfs layers overlayfs(upper=/dev/vdb) over the read-only rootfs.
    var cpus: Int = 2
    var memoryMB: Int = 2048
    var cmdline: String = "console=hvc0 root=/dev/vda rw quiet"
    var shares: [(hostPath: String, tag: String, readOnly: Bool)] = []
    var console: Bool = true
    var noTerminal: Bool = false     // detach mode: skip vsock terminal, keep VM alive
    var proxySocketPath: String = "" // host UDS the vsock proxy relay connects to (per-agent bridge socket)
    var shellSocketPath: String = "" // host UDS the shell bridge listens on; connects to guest vsock:2220
    var snapshotOnSignal: String = "" // path to write snapshot to on SIGUSR1
    var restoreFrom: String = ""      // path to snapshot file to restore from
}

let helperVersion = "0.3.0"

func printUsage() {
    let usage = """
    Usage: safeyolo-vm run [OPTIONS]

    Options:
      --kernel PATH       Path to kernel Image (required)
      --initrd PATH       Path to initramfs (required)
      --rootfs PATH       Path to root disk image (ext4 or erofs) (required)
      --overlay PATH      Optional writable ext4 image attached as /dev/vdb.
                          When set, the guest layers overlayfs(upper=ext4-on-
                          vdb) over the (typically read-only) rootfs, so
                          runtime writes to / persist across agent stops.
                          Omit for tmpfs upper (ephemeral writes).
      --cpus N            Number of CPUs (default: 2)
      --memory N          Memory in MB (default: 2048)
      --cmdline STRING    Kernel command line (default: console=hvc0 root=/dev/vda rw quiet)
      --share HOST:TAG:MODE  VirtioFS share (MODE = ro or rw, repeatable)
      --proxy-socket PATH Host UDS the in-VM proxy forwarder reaches via vsock.
                          Enables vsock→UDS relay; bridges each flow to
                          mitmproxy with agent-attributed upstream source.
      --shell-socket PATH Host UDS the shell bridge listens on; forwards
                          each connection to guest vsock:2220 (sshd-via-socat
                          in the guest). Used by `safeyolo agent shell` when
                          the VM has no network interface.
      --no-terminal       Detach mode: skip vsock terminal, keep VM alive for SSH
      --snapshot-on-signal PATH
                          Write a VM snapshot to PATH when SIGUSR1 is received.
                          Sidecar metadata is written to PATH.meta.json.
      --restore-from PATH Restore VM from a previously-saved snapshot at PATH
                          instead of cold-booting. Must pass the same
                          --kernel / --initrd / --memory / --cpus values that
                          were used when the snapshot was created.
      --help              Show this help

    Example:
      safeyolo-vm run \\
        --kernel ~/.safeyolo/share/Image \\
        --initrd ~/.safeyolo/share/initramfs.cpio.gz \\
        --rootfs ~/.safeyolo/agents/test/rootfs.ext4 \\
        --cpus 4 --memory 4096 \\
        --share /Users/me/code:workspace:rw \\
        --proxy-socket ~/.safeyolo/data/sockets/test.sock \\
        --shell-socket ~/.safeyolo/data/shell-sockets/test.sock
    """
    fputs(usage, stderr)
}

func parseArguments() -> RunConfig? {
    let args = CommandLine.arguments
    guard args.count > 1, args[1] == "run" else {
        if args.count > 1 && args[1] == "--help" {
            printUsage()
            return nil
        }
        if args.count > 1 && args[1] == "version" {
            print("safeyolo-vm \(helperVersion)")
            return nil
        }
        fputs("Error: expected 'run' subcommand\n", stderr)
        printUsage()
        return nil
    }

    var config = RunConfig()
    var i = 2
    while i < args.count {
        switch args[i] {
        case "--kernel":
            i += 1; guard i < args.count else { fputs("Error: --kernel requires a value\n", stderr); return nil }
            config.kernelPath = args[i]
        case "--initrd":
            i += 1; guard i < args.count else { fputs("Error: --initrd requires a value\n", stderr); return nil }
            config.initrdPath = args[i]
        case "--rootfs":
            i += 1; guard i < args.count else { fputs("Error: --rootfs requires a value\n", stderr); return nil }
            config.rootfsPath = args[i]
        case "--overlay":
            i += 1; guard i < args.count else { fputs("Error: --overlay requires a value\n", stderr); return nil }
            config.overlayPath = args[i]
        case "--cpus":
            i += 1; guard i < args.count, let n = Int(args[i]), n > 0 else { fputs("Error: --cpus requires a positive integer\n", stderr); return nil }
            config.cpus = n
        case "--memory":
            i += 1; guard i < args.count, let n = Int(args[i]), n > 0 else { fputs("Error: --memory requires a positive integer\n", stderr); return nil }
            config.memoryMB = n
        case "--cmdline":
            i += 1; guard i < args.count else { fputs("Error: --cmdline requires a value\n", stderr); return nil }
            config.cmdline = args[i]
        case "--share":
            i += 1; guard i < args.count else { fputs("Error: --share requires HOST:TAG:MODE\n", stderr); return nil }
            let parts = args[i].split(separator: ":", maxSplits: 2).map(String.init)
            guard parts.count == 3, (parts[2] == "ro" || parts[2] == "rw") else {
                fputs("Error: --share format is HOST_PATH:TAG:ro|rw\n", stderr)
                return nil
            }
            config.shares.append((hostPath: parts[0], tag: parts[1], readOnly: parts[2] == "ro"))
        case "--proxy-socket":
            i += 1; guard i < args.count else { fputs("Error: --proxy-socket requires a path\n", stderr); return nil }
            config.proxySocketPath = args[i]
        case "--shell-socket":
            i += 1; guard i < args.count else { fputs("Error: --shell-socket requires a path\n", stderr); return nil }
            config.shellSocketPath = args[i]
        case "--no-terminal":
            config.noTerminal = true
        case "--snapshot-on-signal":
            i += 1; guard i < args.count else { fputs("Error: --snapshot-on-signal requires a path\n", stderr); return nil }
            config.snapshotOnSignal = args[i]
        case "--restore-from":
            i += 1; guard i < args.count else { fputs("Error: --restore-from requires a path\n", stderr); return nil }
            config.restoreFrom = args[i]
        case "--help":
            printUsage()
            return nil
        default:
            fputs("Error: unknown option '\(args[i])'\n", stderr)
            printUsage()
            return nil
        }
        i += 1
    }

    // Validate required args
    if config.kernelPath.isEmpty {
        fputs("Error: --kernel is required\n", stderr)
        return nil
    }
    if config.initrdPath.isEmpty {
        fputs("Error: --initrd is required\n", stderr)
        return nil
    }
    if config.rootfsPath.isEmpty {
        fputs("Error: --rootfs is required\n", stderr)
        return nil
    }

    return config
}

// MARK: - Main

guard VZVirtualMachine.isSupported else {
    fputs("Error: Virtualization is not supported on this machine\n", stderr)
    exit(1)
}

guard var config = parseArguments() else {
    exit(1)
}

// Ignore SIGPIPE — the vsock bridges' pump threads write to socket
// fds whose peers can hang up asynchronously (ssh client disconnects,
// guest vsock EOF). Default action for SIGPIPE is terminating the
// process; we want EPIPE as a regular error return from write()
// instead, caught in _forward's except block.
signal(SIGPIPE, SIG_IGN)

// Diagnostic: log every fatal signal before default action fires, so
// we can tell "crashed with SIGBUS" from "exited cleanly from main".
for sig in [SIGABRT, SIGBUS, SIGSEGV, SIGILL, SIGFPE, SIGTRAP] {
    signal(sig) { s in
        fputs("[vm] caught fatal signal \(s), about to die\n", stderr)
        // Re-raise with default handler so normal crash machinery still fires
        signal(s, SIG_DFL)
        raise(s)
    }
}

atexit {
    fputs("[vm] atexit\n", stderr)
}

do {
    // Determine the machine identifier BEFORE building the VM config.
    // It defaults to random-per-process, so without pinning it VZ
    // rejects any cross-process restore with EINVAL. On restore we
    // read the sidecar to recover it; on cold boot we mint a fresh
    // one and persist it via the save-time sidecar.
    let machineIdentifier: VZGenericMachineIdentifier
    if !config.restoreFrom.isEmpty {
        let snapURL = URL(fileURLWithPath: NSString(string: config.restoreFrom).expandingTildeInPath)
        let sidecarURL = VMSnapshot.sidecarURL(for: snapURL)
        guard FileManager.default.fileExists(atPath: sidecarURL.path) else {
            throw VMSnapshot.Error.sidecarMissing(sidecarURL)
        }
        let sidecarData = try Data(contentsOf: sidecarURL)
        let savedFingerprint: VMSnapshot.Fingerprint
        do {
            savedFingerprint = try JSONDecoder().decode(VMSnapshot.Fingerprint.self, from: sidecarData)
        } catch {
            throw VMSnapshot.Error.sidecarParseFailed(error)
        }
        guard let idData = Data(base64Encoded: savedFingerprint.machineIdentifier),
              let decoded = VZGenericMachineIdentifier(dataRepresentation: idData) else {
            throw VMSnapshot.Error.sidecarParseFailed(NSError(
                domain: "VMSnapshot",
                code: 3,
                userInfo: [NSLocalizedDescriptionKey: "sidecar machineIdentifier is not a valid VZGenericMachineIdentifier"]
            ))
        }
        machineIdentifier = decoded
    } else {
        machineIdentifier = VZGenericMachineIdentifier()
    }

    let vmConfig = try VMConfiguration.build(
        from: config,
        machineIdentifier: machineIdentifier
    )
    try vmConfig.validate()

    let vmQueue = DispatchQueue(label: "com.safeyolo.vm", qos: .userInteractive)
    let vm = VZVirtualMachine(configuration: vmConfig, queue: vmQueue)
    let runner = VMRunner(vm: vm, queue: vmQueue)

    // Compute the hardware fingerprint we'll need for save (sidecar) and
    // restore (sidecar validation). Done once here so a SIGUSR1 mid-run
    // doesn't have to recompute kernel/initrd hashes.
    let fingerprint = VMSnapshot.Fingerprint(
        memoryMB: config.memoryMB,
        cpus: config.cpus,
        kernelSHA256: try VMSnapshot.sha256(ofFileAt: config.kernelPath),
        initrdSHA256: try VMSnapshot.sha256(ofFileAt: config.initrdPath),
        vmHelperVersion: helperVersion,
        machineIdentifier: machineIdentifier.dataRepresentation.base64EncodedString()
    )

    if !config.snapshotOnSignal.isEmpty {
        let url = URL(fileURLWithPath: NSString(string: config.snapshotOnSignal).expandingTildeInPath)
        let rootfsURL = URL(fileURLWithPath: NSString(string: config.rootfsPath).expandingTildeInPath)
        // Auto-derive clone path: <snapshot>.rootfs. Restore must use this
        // clone (via --rootfs <X>.rootfs --restore-from <X>) to satisfy
        // VZ's requirement that the disk match its save-time state.
        let cloneURL = url.appendingPathExtension("rootfs")
        runner.configureSnapshotOnSignal(
            url: url,
            rootfsURL: rootfsURL,
            rootfsCloneURL: cloneURL,
            fingerprint: fingerprint
        )
    }

    runner.installSignalHandlers()

    let isRestoring = !config.restoreFrom.isEmpty
    if isRestoring {
        let url = URL(fileURLWithPath: NSString(string: config.restoreFrom).expandingTildeInPath)
        try runner.restoreFromSnapshot(url: url, expectedFingerprint: fingerprint)
    } else {
        try runner.start()
    }

    // Start the vsock proxy relay if a host UDS path was provided.
    // This is the primary egress path — each guest-initiated flow
    // lands on the host-side UDS and is forwarded to mitmproxy with
    // the agent-attributed upstream source IP.
    var proxyRelay: VSockProxyRelay? = nil
    if !config.proxySocketPath.isEmpty {
        proxyRelay = VSockProxyRelay(
            vm: vm, queue: vmQueue,
            socketPath: config.proxySocketPath,
        )
        proxyRelay?.start()
    }
    _ = proxyRelay  // keep the VZVirtioSocketListener alive for process lifetime

    // Start the host-side shell bridge if a socket path was provided.
    // Each accept on the host UDS dials guest:2220 where socat proxies
    // to the guest's sshd. `safeyolo agent shell` uses this via
    // `ssh -o ProxyCommand='nc -U <path>'`.
    var shellBridge: VSockShellBridge? = nil
    if !config.shellSocketPath.isEmpty {
        shellBridge = VSockShellBridge(
            vm: vm, queue: vmQueue,
            socketPath: config.shellSocketPath,
        )
        do {
            try shellBridge?.start()
        } catch {
            fputs("[shell-bridge] failed to start: \(error)\n", stderr)
        }
    }
    _ = shellBridge  // keep reference alive for process lifetime

    // In detach mode (--no-terminal), the VM stays alive until SIGTERM and
    // is accessed via SSH (`safeyolo agent shell <name>`); no vsock-term.
    // Otherwise, attach the vsock terminal once the guest's per-run init
    // has spawned it.
    if !config.noTerminal {
        let terminal = VSockTerminal(vm: vm, queue: vmQueue)

        DispatchQueue.global().async {
            // Retry vsock connection until guest is ready (up to 120s for first boot with npm install).
            // On restore, sshd + per-run init are nearly instant — skip the
            // first 2s sleep so the terminal attaches as fast as possible.
            //
            // Only break on terminal states (.stopped / .error), NOT on
            // transient .pausing/.paused/.saving/.restoring/.resuming —
            // those happen mid-snapshot and the VM will be back to .running
            // momentarily.
            var connected = false
            for attempt in 1...60 {
                if !(isRestoring && attempt == 1) {
                    sleep(2)
                }
                if vm.state == .stopped || vm.state == .error { break }

                if vm.state == .running && terminal.tryConnect() {
                    connected = true
                    break
                }
            }

            if connected {
                terminal.run()
            }
            // Terminal session ended — stop VM
            runner.requestStopFromMain()
        }
    }

    // Run until VM exits.
    //
    // NOTE: in --no-terminal mode the signal DispatchSources on .main
    // appear to be serviced unreliably (SIGUSR1 default action terminates
    // the process before the dispatch source fires). The vsock-term retry
    // loop on the global queue happens to keep things lively in the
    // common case. dispatchMain() didn't fix it cleanly either. For now
    // the snapshot test runs in vsock-term mode where SIGUSR1 works; a
    // proper fix for --no-terminal SIGUSR1 is tracked separately and not
    // load-bearing for the CLI orchestration in PR 4.
    //
    // Detach + bridges: RunLoop.main returns once it has no input
    // sources. The vsock bridges run on GCD, not on the main runloop —
    // so once the initial setup work drains, the runloop would exit
    // and the whole process with it. Keep a recurring Timer attached
    // so RunLoop.main stays alive for the VM's lifetime.
    let keepalive = Timer(timeInterval: 30.0, repeats: true) { _ in }
    RunLoop.main.add(keepalive, forMode: .default)
    RunLoop.main.run()
} catch {
    fputs("Error: \(error.localizedDescription)\n", stderr)
    // Use sysexits.h EX_TEMPFAIL (75) for snapshot-related errors so the CLI
    // can detect this case and fall back to cold-boot capture cleanly.
    if error is VMSnapshot.Error {
        exit(75)
    }
    exit(1)
}
