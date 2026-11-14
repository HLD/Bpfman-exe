// Package event defines the normalized telemetry record produced by the
// sensor and consumed by the rule engine and outputs.
package event

import (
	"time"
)

// Event is one piece of host telemetry. Fields holds the flattened,
// rule-addressable view (e.g. "proc.exe", "net.dport", "file.write").
type Event struct {
	Time   time.Time      `json:"time"`
	Type   string         `json:"type"`
	PID    uint32         `json:"pid"`
	TGID   uint32         `json:"tgid"`
	PPID   uint32         `json:"ppid"`
	UID    uint32         `json:"uid"`
	Comm   string         `json:"comm"`
	Fields map[string]any `json:"fields"`
}

// Get returns a rule-addressable field. Header values are exposed under
// their bare names so rules can say `field: uid`.
func (e *Event) Get(name string) (any, bool) {
	switch name {
	case "type":
		return e.Type, true
	case "pid":
		return e.TGID, true
	case "tid":
		return e.PID, true
	case "ppid":
		return e.PPID, true
	case "uid":
		return e.UID, true
	case "comm":
		return e.Comm, true
	}
	v, ok := e.Fields[name]
	return v, ok
}

func (e *Event) Set(name string, v any) {
	if e.Fields == nil {
		e.Fields = map[string]any{}
	}
	e.Fields[name] = v
}
