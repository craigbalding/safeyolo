import Foundation
import Virtualization

/// Connects to the guest's vsock-term daemon and bridges the host terminal
/// to a guest PTY. Handles terminal resize (SIGWINCH) forwarding.
class VSockTerminal {

    private let vm: VZVirtualMachine
    private let queue: DispatchQueue
    private var dataFD: Int32 = -1
    private var ctrlFD: Int32 = -1
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

    func tryConnect() -> Bool {
        guard let dataConn = connectToPort(VSockTerminal.DATA_PORT) else {
            return false
        }
        dataConnection = dataConn
        dataFD = dataConn.fileDescriptor

        if let ctrlConn = connectToPort(VSockTerminal.CTRL_PORT) {
            ctrlConnection = ctrlConn
            ctrlFD = ctrlConn.fileDescriptor
        }
        return true
    }

    /// Bridge terminal I/O. Blocks until the session ends.
    func run() {
        guard dataFD >= 0 else { return }

        // Clear screen before handing over to the TUI
        let clear = "\u{1B}[2J\u{1B}[H"
        _ = writeAll(STDOUT_FILENO, Array(clear.utf8))

        enableRawMode()
        sendWindowSize()
        installResizeHandler()

        bridgeRunning = true
        bridge()

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
                if case .success(let connection) = connectResult {
                    result = connection
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

        // Keep fds BLOCKING — prevents partial writes that corrupt ANSI sequences.
        // Use select() to check readability, then blocking read/write.
        var buf = [UInt8](repeating: 0, count: 16384)

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
            if ready == 0 { continue }

            // stdin → vsock (host typing)
            if fdIsSet(stdinFD, set: &readSet) {
                let n = read(stdinFD, &buf, buf.count)
                if n > 0 {
                    if !writeAll(dfd, Array(buf[0..<n])) { break }
                } else if n == 0 {
                    break
                }
            }

            // vsock → stdout (guest output)
            if fdIsSet(dfd, set: &readSet) {
                let n = read(dfd, &buf, buf.count)
                if n > 0 {
                    if !writeAll(stdoutFD, Array(buf[0..<n])) { break }
                } else if n == 0 {
                    break
                }
            }
        }
    }

    /// Write all bytes, retrying on partial writes and EINTR.
    @discardableResult
    private func writeAll(_ fd: Int32, _ data: [UInt8]) -> Bool {
        var offset = 0
        while offset < data.count {
            let n = data[offset...].withUnsafeBufferPointer { buf in
                write(fd, buf.baseAddress!, buf.count)
            }
            if n > 0 {
                offset += n
            } else if n < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN {
                    // Brief wait for fd to become writable
                    usleep(1000)
                    continue
                }
                return false
            }
        }
        return true
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

    // MARK: - Full raw terminal mode (cfmakeraw equivalent)

    private func enableRawMode() {
        guard isatty(STDIN_FILENO) != 0 else { return }
        var raw = termios()
        tcgetattr(STDIN_FILENO, &raw)
        originalTermios = raw

        // cfmakeraw equivalent — full raw mode like SSH/tmux
        raw.c_iflag &= ~tcflag_t(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON)
        raw.c_oflag &= ~tcflag_t(OPOST)
        raw.c_lflag &= ~tcflag_t(ECHO | ECHONL | ICANON | ISIG | IEXTEN)
        raw.c_cflag &= ~tcflag_t(CSIZE | PARENB)
        raw.c_cflag |= tcflag_t(CS8)
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

    // MARK: - fd_set helpers

    private func fdZero(_ set: inout fd_set) {
        withUnsafeMutablePointer(to: &set) { ptr in
            memset(UnsafeMutableRawPointer(ptr), 0, MemoryLayout<fd_set>.size)
        }
    }

    private func fdSet(_ fd: Int32, set: inout fd_set) {
        let intOff = Int(fd) / (MemoryLayout<Int32>.size * 8)
        let bitOff = Int(fd) % (MemoryLayout<Int32>.size * 8)
        withUnsafeMutablePointer(to: &set) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: Int32.self)
            raw[intOff] |= Int32(1 << bitOff)
        }
    }

    private func fdIsSet(_ fd: Int32, set: inout fd_set) -> Bool {
        let intOff = Int(fd) / (MemoryLayout<Int32>.size * 8)
        let bitOff = Int(fd) % (MemoryLayout<Int32>.size * 8)
        return withUnsafeMutablePointer(to: &set) { ptr in
            let raw = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: Int32.self)
            return (raw[intOff] & Int32(1 << bitOff)) != 0
        }
    }
}
