package terminal

import (
	"encoding/json"
	"time"

	"github.com/gorilla/websocket"
	"github.com/komari-monitor/komari/database/auditlog"
	"github.com/komari-monitor/komari/web/connection"
)

func ForwardTerminal(id string, browser TerminalPeer, agent *connection.SafeConn) {
	if browser == nil || agent == nil {
		return
	}
	TerminalSessionsMutex.Lock()
	session := TerminalSessions[id]
	requesterIp, userUUID := "", ""
	var peer *memoryPeer
	if session != nil && session.Browser == browser && session.Agent == agent {
		requesterIp, userUUID = session.RequesterIp, session.UserUUID
		peer = session.native
	}
	TerminalSessionsMutex.Unlock()
	if requesterIp == "" {
		return
	}

	auditlog.Log(requesterIp, userUUID, "established, terminal id:"+id, "terminal")
	established_time := time.Now()
	errChan := make(chan error, 2)
	reportError := func(err error) {
		if peer != nil {
			peer.fail(err)
		}
		errChan <- err
	}
	writeAgent := agent.WriteMessage
	if peer != nil {
		writeAgent = func(messageType int, data []byte) error {
			return peer.writeAgent(agent, messageType, data)
		}
	}

	go func() {
		for {
			messageType, data, err := browser.ReadMessage()
			if err != nil {
				reportError(err)
				return
			}

			if messageType == websocket.TextMessage {
				var control struct {
					Type string `json:"type"`
				}
				if json.Unmarshal(data, &control) == nil {
					if control.Type == "heartbeat" {
						continue
					}
					if control.Type == "close" {
						_ = writeAgent(websocket.TextMessage, []byte(`{"type":"close"}`))
						closeSession(id)
						errChan <- nil
						return
					}
				}
				if len(data) > 0 && data[0] == '{' {
					err = writeAgent(websocket.TextMessage, data)
				} else {
					err = writeAgent(websocket.BinaryMessage, data)
				}
			} else {
				err = writeAgent(websocket.BinaryMessage, data)
			}

			if peer != nil {
				peer.acknowledge(err)
			}
			if err != nil {
				reportError(err)
				return
			}
		}
	}()

	go func() {
		for {
			_, data, err := agent.ReadMessage()
			if err != nil {
				reportError(err)
				return
			}
			err = browser.WriteMessage(websocket.BinaryMessage, data)
			if err != nil {
				reportError(err)
				return
			}
		}
	}()

	// 等待错误或主动关闭
	<-errChan
	suspendSession(id, browser, agent)
	disconnect_time := time.Now()
	auditlog.Log(requesterIp, userUUID, "disconnected, terminal id:"+id+", duration:"+disconnect_time.Sub(established_time).String(), "terminal")
}
