import Foundation
import Virtualization

/// Manages the lifecycle of a VZVirtualMachine: start, state observation, signal handling, shutdown.
class VMRunner: NSObject {

    let vm: VZVirtualMachine
    private let queue: DispatchQueue
    private var observation: NSKeyValueObservation?
    private var hasExited = false

    // When non-zero, the state observer ignores .stopped and .error
    // transitions. Used during restore/save where VZ may transition the
    // VM through .stopped on its own (failure path) and we want the
    // calling code to detect that explicitly via vm.state checks rather
    // than racing the observer to exit().
    private var suppressAutoExit = 0
    private let suppressLock = NSLock()
    private func withSuppressedAutoExit<T>(_ body: () throws -> T) rethrows -> T {
        suppressLock.lock()
        suppressAutoExit += 1
        suppressLock.unlock()
        defer {
            suppressLock.lock()
            suppressAutoExit -= 1
            suppressLock.unlock()
        }
        return try body()
    }
    private var isSuppressed: Bool {
        suppressLock.lock()
        defer { suppressLock.unlock() }
        return suppressAutoExit > 0
    }

    // Snapshot-on-signal config — set by main.swift after parsing
    // `--snapshot-on-signal PATH`. SIGUSR1 calls `VMSnapshot.save` with
    // these values. nil means SIGUSR1 is a no-op.
    private var snapshotURL: URL?
    private var snapshotFingerprint: VMSnapshot.Fingerprint?
    private let snapshotLock = NSLock()
    private var snapshotInProgress = false

    init(vm: VZVirtualMachine, queue: DispatchQueue? = nil) {
        self.vm = vm
        self.queue = queue ?? DispatchQueue(label: "com.safeyolo.vm.runner", qos: .userInteractive)
        super.init()
        observeState()
    }

    /// Configure SIGUSR1 to capture a snapshot to `url`. Must be called
    /// before `installSignalHandlers()`. Calling this twice replaces the
    /// previous configuration. Pass `nil` to disable.
    func configureSnapshotOnSignal(url: URL?, fingerprint: VMSnapshot.Fingerprint?) {
        snapshotURL = url
        snapshotFingerprint = fingerprint
    }

    // MARK: - State observation

    private func observeState() {
        observation = vm.observe(\.state, options: [.new]) { [weak self] vm, _ in
            self?.handleStateChange(vm.state)
        }
    }

    private func handleStateChange(_ state: VZVirtualMachine.State) {
        // Diagnostic: log every state transition to stderr so we can see
        // exactly what VZ is doing during cold-boot, save, and restore.
        fputs("[vm state] → \(state.rawValue) (\(stateName(state)))\(isSuppressed ? " [auto-exit suppressed]" : "")\n", stderr)
        switch state {
        case .stopped:
            if !isSuppressed { exitClean(code: 0) }
        case .error:
            if !isSuppressed { exitClean(code: 1) }
        case .running:
            break
        case .starting:
            break
        case .stopping:
            break
        case .pausing, .paused, .resuming, .saving, .restoring:
            break
        @unknown default:
            break
        }
    }

    private func stateName(_ state: VZVirtualMachine.State) -> String {
        switch state {
        case .stopped:    return "stopped"
        case .running:    return "running"
        case .paused:     return "paused"
        case .error:      return "error"
        case .starting:   return "starting"
        case .pausing:    return "pausing"
        case .resuming:   return "resuming"
        case .stopping:   return "stopping"
        case .saving:     return "saving"
        case .restoring:  return "restoring"
        @unknown default: return "unknown"
        }
    }

    // MARK: - Start (completion handler API, not async)

    func start() throws {
        try withSuppressedAutoExit {
            let semaphore = DispatchSemaphore(value: 0)
            var startError: Error?

            // Terminal raw mode is handled by VSockTerminal, not here.

            queue.async { [self] in
                vm.start { (result: Result<Void, Error>) in
                    if case .failure(let error) = result {
                        startError = error
                    }
                    semaphore.signal()
                }
            }

            semaphore.wait()
            if let error = startError {
                restoreTerminal()
                throw error
            }
            // If VZ reported success but state isn't running, treat as
            // failure so we don't fall through to the run loop with a
            // dead VM.
            if vm.state != .running {
                restoreTerminal()
                throw NSError(domain: "VMRunner", code: 1, userInfo: [NSLocalizedDescriptionKey: "VM not running after start (state=\(stateName(vm.state)))"])
            }
        }
    }

    // MARK: - Restore (alternative to start)

    /// Restore the VM from a previously-saved snapshot at `url` and resume
    /// it. Must be called *instead of* `start()` — the VM transitions
    /// directly from `.stopped` to `.paused` (via `.restoring`) and then
    /// to `.running` via the resume inside `VMSnapshot.restore`.
    ///
    /// The caller must have constructed `vm` with the same hardware config
    /// (kernel, initrd, memory, cpus) that was used at save time;
    /// `expectedFingerprint` lets us catch mismatches before VZ does.
    func restoreFromSnapshot(url: URL, expectedFingerprint: VMSnapshot.Fingerprint) throws {
        try withSuppressedAutoExit {
            do {
                try VMSnapshot.restore(vm: vm, queue: queue, fromURL: url, expectedFingerprint: expectedFingerprint)
            } catch {
                restoreTerminal()
                throw error
            }
            // VZ may transition the VM to .stopped during restore failure
            // without surfacing an error in the completion handler. The
            // KVO observer is suppressed during restore (so we don't race
            // to exit), so we have to detect this case explicitly here.
            if vm.state != .running {
                restoreTerminal()
                throw VMSnapshot.Error.restoreFailed(NSError(
                    domain: "VMSnapshot",
                    code: 2,
                    userInfo: [NSLocalizedDescriptionKey: "VM in \(stateName(vm.state)) state after restore — VZ rejected the snapshot (likely incompatible config or corrupt file)"]
                ))
            }
        }
    }

    // MARK: - Shutdown

    /// Called from outside (e.g., when vsock terminal session ends).
    func requestStopFromMain() {
        requestStop()
    }

    /// Graceful shutdown: sends ACPI power button request to guest.
    private func requestStop() {
        queue.async { [self] in
            guard vm.canRequestStop else {
                fputs("Cannot request graceful stop, forcing...\n", stderr)
                forceStop()
                return
            }

            do {
                try vm.requestStop()
            } catch {
                fputs("Graceful stop failed: \(error.localizedDescription), forcing...\n", stderr)
                forceStop()
            }
        }

        // If the VM doesn't stop within 5 seconds, force it
        DispatchQueue.global().asyncAfter(deadline: .now() + 5.0) { [self] in
            if !hasExited {
                fputs("VM did not stop within 5s, forcing...\n", stderr)
                forceStop()
            }
        }
    }

    /// Force stop using completion handler API (not the async variant).
    private func forceStop() {
        queue.async { [self] in
            guard vm.state == .running || vm.state == .starting || vm.state == .stopping else {
                exitClean(code: 1)
                return
            }
            // Use stop(completionHandler:) — the callback API, not the async stop()
            vm.stop { [self] (error: Error?) in
                if let error = error {
                    fputs("Force stop failed: \(error.localizedDescription)\n", stderr)
                }
                exitClean(code: 1)
            }
        }
    }

    private func exitClean(code: Int32) {
        guard !hasExited else { return }
        hasExited = true
        fputs("[exitClean] code=\(code)\n", stderr)
        restoreTerminal()
        exit(code)
    }

    // MARK: - Signal handling

    func installSignalHandlers() {
        signal(SIGINT, SIG_IGN)
        signal(SIGTERM, SIG_IGN)
        signal(SIGUSR1, SIG_IGN)

        // First Ctrl-C: try graceful stop. Second Ctrl-C: force stop immediately.
        let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        sigintSource.setEventHandler { [weak self] in
            guard let self = self else { return }
            if self.stopRequested {
                fputs("\nForce stopping VM...\n", stderr)
                self.forceStop()
            } else {
                fputs("\nShutting down VM... (Ctrl-C again to force)\n", stderr)
                self.stopRequested = true
                self.requestStop()
            }
        }
        sigintSource.resume()

        let sigtermSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        sigtermSource.setEventHandler { [weak self] in
            fputs("Received SIGTERM, shutting down VM...\n", stderr)
            self?.requestStop()
        }
        sigtermSource.resume()

        // SIGUSR1: take a snapshot to the configured path. No-op if the
        // helper wasn't started with --snapshot-on-signal. Debounced:
        // duplicate signals while a save is in flight are ignored, since
        // VZ requires the VM to be paused for save and we must always
        // resume it before the next save can run.
        //
        // Uses .global() instead of .main so the source fires reliably in
        // --no-terminal mode (where the main run loop has nothing else to
        // service and the kernel races us to the default action).
        // handleSnapshotSignal dispatches its real work to .global anyway,
        // so there's no main-thread ordering requirement here.
        let sigusr1Source = DispatchSource.makeSignalSource(signal: SIGUSR1, queue: .global())
        sigusr1Source.setEventHandler { [weak self] in
            self?.handleSnapshotSignal()
        }
        sigusr1Source.resume()

        _signalSources = [sigintSource, sigtermSource, sigusr1Source]
    }

    private func handleSnapshotSignal() {
        // Debounce: drop the signal if a save is already running.
        snapshotLock.lock()
        if snapshotInProgress {
            snapshotLock.unlock()
            fputs("Snapshot already in progress, ignoring SIGUSR1\n", stderr)
            return
        }
        snapshotInProgress = true
        snapshotLock.unlock()

        guard let url = snapshotURL, let fingerprint = snapshotFingerprint else {
            fputs("SIGUSR1 received but --snapshot-on-signal was not configured\n", stderr)
            snapshotLock.lock()
            snapshotInProgress = false
            snapshotLock.unlock()
            return
        }

        // Run save off the main queue so the signal source isn't blocked.
        // VMSnapshot.save handles pause → save → resume, always resuming.
        // Suppress auto-exit during the operation so a transient .paused
        // observer callback doesn't race to kill the helper.
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            do {
                try self.withSuppressedAutoExit {
                    try VMSnapshot.save(vm: self.vm, queue: self.queue, toURL: url, fingerprint: fingerprint)
                }
                fputs("Snapshot written to \(url.path)\n", stderr)
            } catch {
                fputs("Snapshot failed: \(error.localizedDescription)\n", stderr)
            }
            self.snapshotLock.lock()
            self.snapshotInProgress = false
            self.snapshotLock.unlock()
        }
    }

    private var _signalSources: [Any] = []
    private var stopRequested = false

    // MARK: - Terminal raw mode

    private var originalTermios: termios?

    private func enableRawMode() {
        guard isatty(STDIN_FILENO) != 0 else { return }

        var raw = termios()
        tcgetattr(STDIN_FILENO, &raw)
        originalTermios = raw

        // Keep ISIG enabled so Ctrl-C generates SIGINT for our signal handler.
        // Disable ICANON (line buffering) and ECHO (character echo) for raw serial passthrough.
        raw.c_lflag &= ~tcflag_t(ICANON | ECHO)
        raw.c_iflag &= ~tcflag_t(IXON | ICRNL)
        withUnsafeMutablePointer(to: &raw.c_cc) { ptr in
            let cc = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: cc_t.self)
            cc[Int(VMIN)] = 1
            cc[Int(VTIME)] = 0
        }

        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw)
    }

    private func restoreTerminal() {
        guard var original = originalTermios else { return }
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original)
        originalTermios = nil
    }
}
