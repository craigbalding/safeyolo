import Foundation
import Virtualization

/// Connects to the guest's vsock-term daemon and bridges the host terminal
/// to a guest PTY. Handles terminal resize (SIGWINCH) forwarding.
class VSockTerminal {

    private let vm: VZVirtualMachine
    private let queue: DispatchQueue
    private var dataFD: Int32 = -1
    private var ctrlFD: Int32 = -1
    // Must retain connection objects or the fds get closed on dealloc
    private var dataConnection: VZVirtioSocketConnection?
    private var ctrlConnection: VZVirtioSocketConnection?
    private var originalTermios: termios?
    private var bridgeRunning = false

    static let DATA_PORT: UInt32 = 1024
    static let CTRL_PORT: UInt32 = 1025

    init(vm: VZVirtualMachine, queue: DispatchQueue) {
        self.vm = vm
        self.queue = queue
    }

    /// Try to connect to both vsock ports. Returns true if data channel connected.
    func tryConnect() -> Bool {
        guard let dataConn = connectToPort(VSockTerminal.DATA_PORT) else {
            return false
        }
        dataConnection = dataConn  // Retain to keep fd alive
        dataFD = dataConn.fileDescriptor

        // Control channel is non-fatal
        if let ctrlConn = connectToPort(VSockTerminal.CTRL_PORT) {
            ctrlConnection = ctrlConn  // Retain to keep fd alive
            ctrlFD = ctrlConn.fileDescriptor
        }
        return true
    }

    /// Bridge terminal I/O. Call after tryConnect() succeeds.
    /// Blocks until the session ends.
    func run() {
        guard dataFD >= 0 else {
            fputs("vsock: not connected\n", stderr)
            return
        }

        // Clear screen and move cursor home (boot log output pushed cursor down)
        let clearScreen = "\u{1B}[2J\u{1B}[H"
        write(STDOUT_FILENO, clearScreen, clearScreen.utf8.count)

        // Put host terminal in raw mode
        enableRawMode()

        // Send initial window size
        sendWindowSize()

        // Install SIGWINCH handler for resize
        installResizeHandler()

        // Bridge stdin ↔ vsock data, bidirectional
        bridgeRunning = true
        bridge()

        // Restore terminal
        restoreTerminal()
    }

    // MARK: - vsock connection

    private func connectToPort(_ port: UInt32) -> VZVirtioSocketConnection? {
        let semaphore = DispatchSemaphore(value: 0)
        var result: VZVirtioSocketConnection?

        queue.async { [self] in
            guard let device = vm.socketDevices.first as? VZVirtioSocketDevice else {
                semaphore.signal()
                return
            }
            device.connect(toPort: port) { connectResult in
                switch connectResult {
                case .success(let connection):
                    result = connection
                case .failure:
                    break  // Expected during boot — guest vsock-term not ready yet
                }
                semaphore.signal()
            }
        }

        _ = semaphore.wait(timeout: .now() + 10)
        return result
    }

    // MARK: - Terminal bridge

    private func bridge() {
        let stdinFD = FileHandle.standardInput.fileDescriptor
        let stdoutFD = FileHandle.standardOutput.fileDescriptor
        let dfd = dataFD

        // Make fds non-blocking
        fcntl(dfd, F_SETFL, O_NONBLOCK)
        fcntl(stdinFD, F_SETFL, O_NONBLOCK)

        var buf = [UInt8](repeating: 0, count: 4096)

        while bridgeRunning {
            var readSet = fd_set()
            fdZero(&readSet)
            fdSet(stdinFD, set: &readSet)
            fdSet(dfd, set: &readSet)

            let maxFD = max(stdinFD, dfd) + 1
            var timeout = timeval(tv_sec: 1, tv_usec: 0)

            let ready = select(maxFD, &readSet, nil, nil, &timeout)
            if ready < 0 {
                if errno == EINTR { continue }
                break
            }

            // stdin → vsock (host typing)
            if fdIsSet(stdinFD, set: &readSet) {
                let n = read(stdinFD, &buf, buf.count)
                if n > 0 {
                    _ = write(dfd, buf, n)
                } else if n == 0 {
                    break
                }
            }

            // vsock → stdout (guest output)
            if fdIsSet(dfd, set: &readSet) {
                let n = read(dfd, &buf, buf.count)
                if n > 0 {
                    _ = write(stdoutFD, buf, n)
                } else if n == 0 {
                    break
                } else if errno != EAGAIN {
                    break
                }
            }
        }

        // Restore stdin to blocking
        fcntl(stdinFD, F_SETFL, 0)
    }

    func stop() {
        bridgeRunning = false
    }

    // MARK: - Resize handling

    private func sendWindowSize() {
        guard ctrlFD >= 0 else { return }
        var ws = winsize()
        if ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 {
            var msg: [UInt8] = [
                UInt8((ws.ws_row >> 8) & 0xFF),
                UInt8(ws.ws_row & 0xFF),
                UInt8((ws.ws_col >> 8) & 0xFF),
                UInt8(ws.ws_col & 0xFF),
            ]
            _ = write(ctrlFD, &msg, 4)
        }
    }

    private func installResizeHandler() {
        signal(SIGWINCH, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: SIGWINCH, queue: .main)
        source.setEventHandler { [weak self] in
            self?.sendWindowSize()
        }
        source.resume()
        _resizeSource = source
    }

    private var _resizeSource: Any?

    // MARK: - Raw terminal mode

    private func enableRawMode() {
        guard isatty(STDIN_FILENO) != 0 else { return }
        var raw = termios()
        tcgetattr(STDIN_FILENO, &raw)
        originalTermios = raw
        // Disable ICANON (line buffering), ECHO, and ISIG (so Ctrl-C passes
        // through to the guest as 0x03 instead of generating host SIGINT)
        raw.c_lflag &= ~tcflag_t(ICANON | ECHO | ISIG)
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

    // MARK: - fd_set helpers (Swift doesn't expose these nicely)

    private func fdZero(_ set: inout fd_set) {
        withUnsafeMutablePointer(to: &set) { ptr in
            let raw = UnsafeMutableRawPointer(ptr)
            memset(raw, 0, MemoryLayout<fd_set>.size)
        }
    }

    private func fdSet(_ fd: Int32, set: inout fd_set) {
        let intOffset = Int(fd) / (MemoryLayout<Int32>.size * 8)
        let bitOffset = Int(fd) % (MemoryLayout<Int32>.size * 8)
        withUnsafeMutablePointer(to: &set) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: Int32.self)
            raw[intOffset] |= Int32(1 << bitOffset)
        }
    }

    private func fdIsSet(_ fd: Int32, set: inout fd_set) -> Bool {
        let intOffset = Int(fd) / (MemoryLayout<Int32>.size * 8)
        let bitOffset = Int(fd) % (MemoryLayout<Int32>.size * 8)
        return withUnsafeMutablePointer(to: &set) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: Int32.self)
            return (raw[intOffset] & Int32(1 << bitOffset)) != 0
        }
    }
}
