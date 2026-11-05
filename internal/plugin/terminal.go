package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/Calcium-Ion/moejs"
	"github.com/Calcium-Ion/moejs/engine"
	"github.com/komari-monitor/komari/pkg/jsruntime"
	"github.com/komari-monitor/komari/pkg/jsruntime/native"
	"github.com/komari-monitor/komari/web/api"
	"github.com/komari-monitor/komari/web/api/terminal"
)

type terminalParams struct {
	terminal.OpenParams
	ID         string `json:"id"`
	WaitMS     int    `json:"wait_ms"`
	DataBase64 string `json:"data_base64"`
	Code       string `json:"code"`
}

func parseTerminalParams(vm *moejs.Runtime, action string, value moejs.Value) (terminalParams, error) {
	var fields []string
	switch action {
	case "authorize":
		fields = []string{"user_uuid", "code"}
	case "open":
		fields = []string{"owner", "client_uuid", "user_uuid", "remote_ip", "expires_at", "cols", "rows"}
	case "list", "closeOwner":
		fields = []string{"owner"}
	case "read":
		fields = []string{"owner", "id", "wait_ms"}
	case "write":
		fields = []string{"owner", "id", "data_base64"}
	case "resize":
		fields = []string{"owner", "id", "cols", "rows"}
	case "close":
		fields = []string{"owner", "id"}
	default:
		return terminalParams{}, fmt.Errorf("unknown terminal action %q", action)
	}
	var input map[string]any
	if err := native.ExportTo(vm, value, &input); err != nil {
		return terminalParams{}, fmt.Errorf("terminal params must be an object: %w", err)
	}
	for _, field := range fields {
		if v, ok := input[field]; !ok || v == nil {
			return terminalParams{}, fmt.Errorf("terminal %s requires %s", action, field)
		}
	}
	for field := range input {
		if !slices.Contains(fields, field) {
			return terminalParams{}, fmt.Errorf("unknown terminal %s parameter %q", action, field)
		}
	}
	data, err := json.Marshal(input)
	if err != nil {
		return terminalParams{}, err
	}
	var params terminalParams
	if err := json.Unmarshal(data, &params); err != nil {
		return terminalParams{}, fmt.Errorf("invalid terminal %s params: %w", action, err)
	}
	return params, nil
}

func (m *Manager) registerTerminal(host *jsruntime.Host, vm *moejs.Runtime, exports *engine.Object, inst *Instance) {
	_ = native.Function(vm, exports, "terminal", func(_ *moejs.Realm, _ moejs.Value, args []moejs.Value) (moejs.Value, error) {
		promise, resolve, reject := vm.NewPromise()
		if !inst.info.Permissions.AllowSystemRPC {
			_ = reject(native.GoError(vm, errors.New("server.terminal requires allowSystemRPC")))
			return promise, nil
		}
		if len(args) != 2 || !args[0].IsString() {
			_ = reject(native.GoError(vm, errors.New("server.terminal requires an action string and params object")))
			return promise, nil
		}
		action := native.String(vm, args[0])
		params, err := parseTerminalParams(vm, action, args[1])
		if err != nil {
			_ = reject(native.GoError(vm, err))
			return promise, nil
		}
		go func() {
			var result any
			var callErr error
			if m.instanceFor(inst.info.Short) != inst {
				callErr = errNotLoaded
			} else {
				result, callErr = inst.callTerminal(action, params)
			}
			host.RunOnLoop(func(vm *moejs.Runtime) {
				if callErr == nil && action == "open" {
					// An open may finish in Go while a grant is being revoked on
					// the JS loop. Never resolve a stale successful open afterward.
					info := result.(terminal.SessionInfo)
					callErr = inst.terminals.CheckSession(params.Owner, info.ID)
				}
				if callErr != nil {
					_ = reject(native.GoError(vm, callErr))
					return
				}
				value, err := normalizeRPCValue(result)
				if err != nil {
					_ = reject(native.GoError(vm, err))
					return
				}
				_ = resolve(native.From(vm, value))
			})
		}()
		return promise, nil
	})
}

func (inst *Instance) callTerminal(action string, params terminalParams) (any, error) {
	switch action {
	case "authorize":
		if err := api.VerifySensitive2FACore(params.UserUUID, params.Code, false); err != nil {
			return nil, err
		}
		return map[string]any{"authorized": true}, nil
	case "open":
		return inst.terminals.Open(params.OpenParams)
	case "list":
		return inst.terminals.List(params.Owner)
	case "read":
		return inst.terminals.Read(params.Owner, params.ID, params.WaitMS)
	case "write":
		written, err := inst.terminals.Write(params.Owner, params.ID, params.DataBase64)
		return map[string]any{"id": params.ID, "written": written}, err
	case "resize":
		err := inst.terminals.Resize(params.Owner, params.ID, params.Cols, params.Rows)
		return map[string]any{"id": params.ID, "cols": params.Cols, "rows": params.Rows}, err
	case "close":
		err := inst.terminals.CloseSession(params.Owner, params.ID)
		return map[string]any{"id": params.ID, "closed": true}, err
	case "closeOwner":
		closed, err := inst.terminals.CloseOwner(params.Owner)
		return map[string]any{"closed": closed}, err
	default:
		return nil, fmt.Errorf("unknown terminal action %q", action)
	}
}
