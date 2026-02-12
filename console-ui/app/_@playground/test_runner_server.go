package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
)

const (
	TYPE_OUTPUT = 0x00
	TYPE_INPUT  = 0x01
	TYPE_RESIZE = 0x02
)

type ResizeMsg struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

func main() {
	socketPath := "/tmp/safeyolo-runner.sock"

	// Clean up old socket
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to listen: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(socketPath)
	defer listener.Close()

	fmt.Printf("Listening on %s\n", socketPath)
	fmt.Printf("Run: ./ptyend/runner.ts --- ls -la\n")
	fmt.Printf("Or:  ./ptyend/runner.ts --- top\n")
	fmt.Println("Commands: 'r' to resize to 100x30, 'q' to quit, any other key sends to PTY")

	// Accept one connection
	conn, err := listener.Accept()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to accept: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Println("Client connected")

	// Channel for graceful shutdown
	done := make(chan struct{})

	// Goroutine: read from socket and print to stdout
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		var pending []byte
		for {
			n, err := conn.Read(buf)
			if err != nil {
				fmt.Fprintf(os.Stderr, "\n[Server] Connection closed: %v\n", err)
				return
			}
			// Append new data to any pending partial frame
			pending = append(pending, buf[:n]...)
			// Process complete frames, keep any partial remainder
			pending = processFramesBuffer(pending)
		}
	}()

	// Goroutine: read from stdin and send to socket
	go func() {
		input := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(input)
			if err != nil || n == 0 {
				continue
			}

			switch input[0] {
			case 'q':
				fmt.Println("[Server] Quitting...")
				conn.Close()
				return
			case 'r':
				fmt.Println("[Server] Resizing to 100x30...")
				sendResize(conn, 100, 30)
			default:
				// Send as input to PTY
				sendFrame(conn, TYPE_INPUT, []byte{input[0]})
			}
		}
	}()

	// Handle interrupt
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case <-done:
	case <-sigCh:
		fmt.Println("\n[Server] Interrupted")
	}

	fmt.Println("[Server] Exiting")
}

// processFramesBuffer processes complete frames from the buffer and returns
// any remaining partial frame data for the next read.
func processFramesBuffer(data []byte) []byte {
	offset := 0
	for offset < len(data) {
		if offset+5 > len(data) {
			// Need more data for complete header
			return data[offset:]
		}

		frameType := data[offset]
		length := binary.BigEndian.Uint32(data[offset+1:])

		if offset+5+int(length) > len(data) {
			// Need more data for complete payload
			return data[offset:]
		}

		payload := data[offset+5 : offset+5+int(length)]

		switch frameType {
		case TYPE_OUTPUT:
			// PTY output - write to stdout
			os.Stdout.Write(payload)
		case TYPE_INPUT:
			fmt.Printf("[Unexpected INPUT from client: %v]\n", payload)
		case TYPE_RESIZE:
			fmt.Printf("[Unexpected RESIZE from client: %v]\n", payload)
		default:
			fmt.Printf("[Unknown frame type: %d, len: %d]\n", frameType, length)
		}

		offset += 5 + int(length)
	}
	// All data processed, nothing pending
	return nil
}

func sendFrame(conn net.Conn, frameType byte, payload []byte) {
	frame := make([]byte, 5+len(payload))
	frame[0] = frameType
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	copy(frame[5:], payload)
	conn.Write(frame)
}

func sendResize(conn net.Conn, cols, rows int) {
	msg := ResizeMsg{Cols: cols, Rows: rows}
	data, _ := json.Marshal(msg)
	sendFrame(conn, TYPE_RESIZE, data)
}
