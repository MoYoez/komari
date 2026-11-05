package terminal

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/komari-monitor/komari/web/connection"
)

const (
	terminalOutputLimit = 1 << 20
	terminalIOTimeout   = 10 * time.Second
)

type terminalFrame struct {
	kind int
	data []byte
	ack  chan error
}

// memoryPeer replaces only the browser side of the existing PTY forwarding.
// Input is handed to the forwarder; output stays here until a destructive read.
type memoryPeer struct {
	mu       sync.Mutex
	output   []byte
	closed   bool
	err      string
	changed  chan struct{}
	done     chan struct{}
	stopped  chan struct{}
	ready    chan struct{}
	input    chan terminalFrame
	inputAck chan error // Used only by the browser-to-agent forwarding goroutine.

	// Assigned once, before ready is closed and forwarding starts.
	agentConn *websocket.Conn
	writeMu   sync.Mutex
}

func newMemoryPeer() *memoryPeer {
	return &memoryPeer{
		changed: make(chan struct{}),
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
		ready:   make(chan struct{}),
		input:   make(chan terminalFrame),
	}
}

func (p *memoryPeer) ReadMessage() (int, []byte, error) {
	select {
	case frame := <-p.input:
		if p.isClosed() {
			return 0, nil, io.EOF
		}
		p.inputAck = frame.ack
		return frame.kind, frame.data, nil
	case <-p.done:
		return 0, nil, io.EOF
	}
}

func (p *memoryPeer) WriteMessage(_ int, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return io.ErrClosedPipe
	}
	if len(data) > terminalOutputLimit-len(p.output) {
		err := fmt.Errorf("terminal output buffer exceeded %d bytes", terminalOutputLimit)
		p.err = err.Error()
		p.closeLocked()
		return err
	}
	p.output = append(p.output, data...)
	p.signalLocked()
	return nil
}

func (p *memoryPeer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closeLocked()
	return nil
}

func (p *memoryPeer) closeLocked() {
	if p.closed {
		return
	}
	p.closed = true
	close(p.done)
	p.signalLocked()
}

func (p *memoryPeer) signalLocked() {
	close(p.changed)
	p.changed = make(chan struct{})
}

func (p *memoryPeer) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

func (p *memoryPeer) closedError() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != "" {
		return errors.New(p.err)
	}
	return errors.New("terminal session is closed")
}

func (p *memoryPeer) fail(err error) {
	if err == nil || errors.Is(err, io.EOF) || websocket.IsCloseError(err,
		websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.err = err.Error()
		p.closeLocked()
	}
}

func (p *memoryPeer) send(kind int, data []byte) error {
	ack := make(chan error, 1)
	select {
	case <-p.done:
		return p.closedError()
	case p.input <- terminalFrame{kind: kind, data: data, ack: ack}:
	}
	select {
	case err := <-ack:
		return err
	case <-p.done:
		return p.closedError()
	}
}

func (p *memoryPeer) acknowledge(err error) {
	p.inputAck <- err
}

func (p *memoryPeer) read(wait time.Duration) ([]byte, bool, string) {
	var timeout <-chan time.Time
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		timeout = timer.C
	}
	for {
		p.mu.Lock()
		if len(p.output) > 0 || p.closed || wait == 0 {
			data, closed, err := p.output, p.closed, p.err
			p.output = nil
			p.mu.Unlock()
			return data, closed, err
		}
		changed := p.changed
		p.mu.Unlock()
		select {
		case <-changed:
		case <-timeout:
			wait = 0
		}
	}
}

func (p *memoryPeer) writeAgent(agent *connection.SafeConn, kind int, data []byte) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if err := p.agentConn.SetWriteDeadline(time.Now().Add(terminalIOTimeout)); err != nil {
		return err
	}
	return agent.WriteMessage(kind, data)
}

func (p *memoryPeer) closeAgent(agent *connection.SafeConn) {
	defer close(p.stopped)
	if agent == nil {
		return
	}
	// Closing the raw socket also interrupts a writer holding SafeConn's mutex.
	// The timer covers both waiting for that writer and sending the close frame.
	timer := time.AfterFunc(terminalIOTimeout, func() { _ = p.agentConn.Close() })
	defer timer.Stop()
	_ = p.writeAgent(agent, websocket.TextMessage, []byte(`{"type":"close"}`))
	_ = agent.Close()
}
