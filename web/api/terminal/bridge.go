package terminal

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/komari-monitor/komari/database/clients"
	"github.com/komari-monitor/komari/utils"
	agent_runtime "github.com/komari-monitor/komari/web/agent"
)

const (
	terminalOpenTimeout = 15 * time.Second
	terminalMaxWaitMS   = 15000
)

type OpenParams struct {
	Owner      string `json:"owner"`
	ClientUUID string `json:"client_uuid"`
	UserUUID   string `json:"user_uuid"`
	RemoteIP   string `json:"remote_ip"`
	ExpiresAt  int64  `json:"expires_at"`
	Cols       uint16 `json:"cols"`
	Rows       uint16 `json:"rows"`
}

type SessionInfo struct {
	ID         string `json:"id"`
	ClientUUID string `json:"client_uuid"`
	Status     string `json:"status"`
	ExpiresAt  int64  `json:"expires_at"`
	CreatedAt  int64  `json:"created_at"`
}

type ReadResult struct {
	ID         string `json:"id"`
	ClientUUID string `json:"client_uuid"`
	Status     string `json:"status"`
	DataBase64 string `json:"data_base64"`
	Error      string `json:"error"`
}

type bridgeSession struct {
	info   SessionInfo
	owner  string
	peer   *memoryPeer
	timer  *time.Timer
	opened bool
}

func (s *bridgeSession) close() {
	closeSession(s.info.ID)
	// A concurrent forwarder may already own connection cleanup.
	<-s.peer.stopped
}

// Bridge belongs to one plugin load. Its registry never includes browser
// terminals; the plugin short name is supplied by the host, not JavaScript.
type Bridge struct {
	mu           sync.Mutex
	short        string
	sessions     map[string]*bridgeSession
	closedOwners map[string]struct{}
	closed       bool
}

func NewBridge(short string) *Bridge {
	return &Bridge{
		short:        short,
		sessions:     make(map[string]*bridgeSession),
		closedOwners: make(map[string]struct{}),
	}
}

func (b *Bridge) ownerKey(owner string) string { return b.short + ":" + owner }

func (b *Bridge) checkOwnerLocked(owner string) error {
	if b.closed {
		return errors.New("plugin terminal bridge is closed")
	}
	if owner == "" {
		return errors.New("terminal owner is required")
	}
	if _, revoked := b.closedOwners[b.ownerKey(owner)]; revoked {
		return errors.New("terminal owner is revoked")
	}
	return nil
}

func (b *Bridge) sessionLocked(owner, id string) (*bridgeSession, error) {
	if err := b.checkOwnerLocked(owner); err != nil {
		return nil, err
	}
	session := b.sessions[id]
	if session == nil || session.owner != b.ownerKey(owner) {
		return nil, errors.New("terminal session not found")
	}
	if time.Now().Unix() >= session.info.ExpiresAt {
		return nil, errors.New("terminal session expired")
	}
	return session, nil
}

func (b *Bridge) session(owner, id string) (*bridgeSession, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sessionLocked(owner, id)
}

// CheckSession prevents a delayed open Promise from resolving after revocation.
func (b *Bridge) CheckSession(owner, id string) error {
	session, err := b.session(owner, id)
	if err != nil {
		return err
	}
	if session.peer.isClosed() {
		return session.peer.closedError()
	}
	return nil
}

func (b *Bridge) Open(params OpenParams) (SessionInfo, error) {
	if params.ClientUUID == "" || params.UserUUID == "" || params.RemoteIP == "" {
		return SessionInfo{}, errors.New("client_uuid, user_uuid and remote_ip are required")
	}
	if params.Cols == 0 || params.Rows == 0 {
		return SessionInfo{}, errors.New("cols and rows must be between 1 and 65535")
	}
	if params.ExpiresAt <= time.Now().Unix() {
		return SessionInfo{}, errors.New("expires_at must be a future UNIX timestamp in seconds")
	}
	if _, err := clients.GetClientByUUID(params.ClientUUID); err != nil {
		return SessionInfo{}, err
	}
	if !slices.Contains(agent_runtime.GetAllOnlineUUIDs(), params.ClientUUID) {
		return SessionInfo{}, errors.New("terminal client is offline")
	}
	session := &bridgeSession{
		info: SessionInfo{
			ID: utils.GenerateRandomString(32), ClientUUID: params.ClientUUID,
			Status: "open", ExpiresAt: params.ExpiresAt, CreatedAt: time.Now().Unix(),
		},
		owner: b.ownerKey(params.Owner),
		peer:  newMemoryPeer(),
	}
	id := session.info.ID
	b.mu.Lock()
	if err := b.checkOwnerLocked(params.Owner); err != nil {
		b.mu.Unlock()
		return SessionInfo{}, err
	}
	b.sessions[id] = session
	TerminalSessionsMutex.Lock()
	TerminalSessions[id] = &TerminalSession{
		UUID: params.ClientUUID, UserUUID: params.UserUUID, RequesterIp: params.RemoteIP,
		Browser: session.peer, native: session.peer,
	}
	TerminalSessionsMutex.Unlock()
	session.timer = time.AfterFunc(time.Until(time.Unix(params.ExpiresAt, 0)), func() { b.remove(id) })
	b.mu.Unlock()

	opened := false
	defer func() {
		if !opened {
			b.remove(id)
		}
	}()
	timer := time.NewTimer(terminalOpenTimeout)
	defer timer.Stop()
	dispatched := make(chan bool, 1)
	go func() { dispatched <- dispatchTerminalRequest(params.ClientUUID, id) }()
	select {
	case online := <-dispatched:
		if !online {
			return SessionInfo{}, errors.New("terminal client is offline")
		}
	case <-session.peer.done:
		return SessionInfo{}, session.peer.closedError()
	case <-timer.C:
		return SessionInfo{}, errors.New("timed out dispatching terminal request")
	}
	select {
	case <-session.peer.ready:
	case <-session.peer.done:
		return SessionInfo{}, session.peer.closedError()
	case <-timer.C:
		return SessionInfo{}, errors.New("timed out waiting for terminal agent connection")
	}
	if err := sendResize(session.peer, params.Cols, params.Rows); err != nil {
		return SessionInfo{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, err := b.sessionLocked(params.Owner, id); err != nil {
		return SessionInfo{}, err
	}
	if session.peer.isClosed() {
		return SessionInfo{}, session.peer.closedError()
	}
	session.opened = true
	opened = true
	return session.info, nil
}

func (b *Bridge) List(owner string) ([]SessionInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.checkOwnerLocked(owner); err != nil {
		return nil, err
	}
	result := make([]SessionInfo, 0)
	for _, session := range b.sessions {
		if session.owner != b.ownerKey(owner) || !session.opened || time.Now().Unix() >= session.info.ExpiresAt {
			continue
		}
		info := session.info
		if session.peer.isClosed() {
			info.Status = "closed"
		}
		result = append(result, info)
	}
	return result, nil
}

func (b *Bridge) Read(owner, id string, waitMS int) (ReadResult, error) {
	if waitMS < 0 || waitMS > terminalMaxWaitMS {
		return ReadResult{}, errors.New("wait_ms must be between 0 and 15000")
	}
	session, err := b.session(owner, id)
	if err != nil {
		return ReadResult{}, err
	}
	data, closed, terminalErr := session.peer.read(time.Duration(waitMS) * time.Millisecond)
	if _, err := b.session(owner, id); err != nil {
		return ReadResult{}, err
	}
	status := "open"
	if closed {
		status = "closed"
	}
	return ReadResult{
		ID: id, ClientUUID: session.info.ClientUUID, Status: status,
		DataBase64: base64.StdEncoding.EncodeToString(data), Error: terminalErr,
	}, nil
}

func (b *Bridge) Write(owner, id, dataBase64 string) (int, error) {
	session, err := b.session(owner, id)
	if err != nil {
		return 0, err
	}
	data, err := base64.StdEncoding.Strict().DecodeString(dataBase64)
	if err != nil {
		return 0, err
	}
	if err := session.peer.send(websocket.BinaryMessage, data); err != nil {
		return 0, err
	}
	if _, err := b.session(owner, id); err != nil {
		return 0, err
	}
	return len(data), nil
}

func sendResize(peer *memoryPeer, cols, rows uint16) error {
	if cols == 0 || rows == 0 {
		return errors.New("cols and rows must be between 1 and 65535")
	}
	data, err := json.Marshal(struct {
		Type string `json:"type"`
		Cols uint16 `json:"cols"`
		Rows uint16 `json:"rows"`
	}{Type: "resize", Cols: cols, Rows: rows})
	if err != nil {
		return err
	}
	return peer.send(websocket.TextMessage, data)
}

func (b *Bridge) Resize(owner, id string, cols, rows uint16) error {
	session, err := b.session(owner, id)
	if err != nil {
		return err
	}
	if err := sendResize(session.peer, cols, rows); err != nil {
		return err
	}
	_, err = b.session(owner, id)
	return err
}

func (b *Bridge) removeLocked(session *bridgeSession) {
	delete(b.sessions, session.info.ID)
	session.timer.Stop()
	_ = session.peer.Close()
}

func (b *Bridge) remove(id string) {
	b.mu.Lock()
	session := b.sessions[id]
	if session != nil {
		b.removeLocked(session)
	}
	b.mu.Unlock()
	if session != nil {
		session.close()
	}
}

func (b *Bridge) CloseSession(owner, id string) error {
	b.mu.Lock()
	session, err := b.sessionLocked(owner, id)
	if err != nil {
		b.mu.Unlock()
		return err
	}
	b.removeLocked(session)
	b.mu.Unlock()
	session.close()
	return nil
}

func (b *Bridge) CloseOwner(owner string) (int, error) {
	b.mu.Lock()
	if b.closed || owner == "" {
		b.mu.Unlock()
		return 0, errors.New("an active plugin and terminal owner are required")
	}
	key := b.ownerKey(owner)
	// Grant UUIDs are never reused. Keep this tombstone until plugin unload,
	// including when no session exists yet, to reject concurrent opens.
	b.closedOwners[key] = struct{}{}
	sessions := make([]*bridgeSession, 0)
	for _, session := range b.sessions {
		if session.owner == key {
			b.removeLocked(session)
			sessions = append(sessions, session)
		}
	}
	b.mu.Unlock()
	for _, session := range sessions {
		session.close()
	}
	return len(sessions), nil
}

func (b *Bridge) Close() {
	b.mu.Lock()
	b.closed = true
	sessions := make([]*bridgeSession, 0, len(b.sessions))
	for _, session := range b.sessions {
		b.removeLocked(session)
		sessions = append(sessions, session)
	}
	b.mu.Unlock()
	for _, session := range sessions {
		session.close()
	}
}
