// Copyright 2025 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package container

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/clog/slogtest"
)

// ObservabilityEvent represents the JSON event structure emitted by the
// observability framework. Used for event schema validation and test parsing.
type ObservabilityEvent struct {
	ProcessExec   *ProcessExec   `json:"process_exec,omitempty"`
	ProcessKprobe *ProcessKprobe `json:"process_kprobe,omitempty"`
	ProcessExit   *ProcessExit   `json:"process_exit,omitempty"`
	NodeName      string         `json:"node_name,omitempty"`
	Time          string         `json:"time,omitempty"`
}

type ProcessExec struct {
	Process *Process `json:"process,omitempty"`
	Parent  *Process `json:"parent,omitempty"`
}

type ProcessKprobe struct {
	Process      *Process    `json:"process,omitempty"`
	Parent       *Process    `json:"parent,omitempty"`
	FunctionName string      `json:"function_name,omitempty"`
	Args         []KprobeArg `json:"args,omitempty"`
	Action       string      `json:"action,omitempty"`
	PolicyName   string      `json:"policy_name,omitempty"`
}

type ProcessExit struct {
	Process *Process `json:"process,omitempty"`
	Parent  *Process `json:"parent,omitempty"`
}

type Process struct {
	ExecID       string `json:"exec_id,omitempty"`
	PID          uint32 `json:"pid,omitempty"`
	UID          uint32 `json:"uid,omitempty"`
	CWD          string `json:"cwd,omitempty"`
	Binary       string `json:"binary,omitempty"`
	Arguments    string `json:"arguments,omitempty"`
	Flags        string `json:"flags,omitempty"`
	StartTime    string `json:"start_time,omitempty"`
	ParentExecID string `json:"parent_exec_id,omitempty"`
}

type KprobeArg struct {
	SockArg *KprobeSock `json:"sock_arg,omitempty"`
	SkbArg  *KprobeSkb  `json:"skb_arg,omitempty"`
	IntArg  *int64      `json:"int_arg,omitempty"`
}

type KprobeSock struct {
	Family   string `json:"family,omitempty"`
	Type     string `json:"type,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	SAddr    string `json:"saddr,omitempty"`
	DAddr    string `json:"daddr,omitempty"`
	SPort    uint32 `json:"sport,omitempty"`
	DPort    uint32 `json:"dport,omitempty"`
	State    string `json:"state,omitempty"`
}

type KprobeSkb struct {
	SAddr    string `json:"saddr,omitempty"`
	DAddr    string `json:"daddr,omitempty"`
	SPort    uint32 `json:"sport,omitempty"`
	DPort    uint32 `json:"dport,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	Family   string `json:"family,omitempty"`
	Len      uint32 `json:"len,omitempty"`
}

// --- Unit Tests ---

func TestObservabilityEventParsing(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantType  string // "exec", "kprobe", "exit"
		wantValid bool
	}{
		{
			name: "process_exec event",
			input: `{
				"process_exec": {
					"process": {
						"binary": "/usr/bin/gcc",
						"arguments": "-o hello hello.c",
						"pid": 1234
					}
				},
				"time": "2025-01-01T00:00:00Z"
			}`,
			wantType:  "exec",
			wantValid: true,
		},
		{
			name: "tcp_connect kprobe event",
			input: `{
				"process_kprobe": {
					"process": {
						"binary": "/usr/bin/curl",
						"pid": 5678
					},
					"function_name": "tcp_connect",
					"args": [{
						"sock_arg": {
							"family": "AF_INET",
							"type": "SOCK_STREAM",
							"protocol": "IPPROTO_TCP",
							"saddr": "10.0.2.15",
							"daddr": "104.198.14.52",
							"sport": 48272,
							"dport": 443
						}
					}],
					"policy_name": "network-monitor"
				},
				"time": "2025-01-01T00:00:01Z"
			}`,
			wantType:  "kprobe",
			wantValid: true,
		},
		{
			name: "tcp_close kprobe event",
			input: `{
				"process_kprobe": {
					"process": {
						"binary": "/usr/bin/wget",
						"pid": 9012
					},
					"function_name": "tcp_close",
					"args": [{
						"sock_arg": {
							"family": "AF_INET",
							"type": "SOCK_STREAM",
							"protocol": "IPPROTO_TCP",
							"daddr": "8.8.8.8",
							"dport": 53
						}
					}],
					"policy_name": "network-monitor"
				},
				"time": "2025-01-01T00:00:02Z"
			}`,
			wantType:  "kprobe",
			wantValid: true,
		},
		{
			name:      "empty JSON",
			input:     `{}`,
			wantType:  "",
			wantValid: true,
		},
		{
			name:      "invalid JSON",
			input:     `{not valid json}`,
			wantType:  "",
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var event ObservabilityEvent
			err := json.Unmarshal([]byte(tt.input), &event)

			if tt.wantValid && err != nil {
				t.Fatalf("expected valid JSON, got error: %v", err)
			}
			if !tt.wantValid && err == nil {
				t.Fatalf("expected invalid JSON, got nil error")
			}
			if !tt.wantValid {
				return
			}

			switch tt.wantType {
			case "exec":
				if event.ProcessExec == nil {
					t.Error("expected process_exec event, got nil")
				}
				if event.ProcessExec != nil && event.ProcessExec.Process == nil {
					t.Error("expected process_exec.process, got nil")
				}
			case "kprobe":
				if event.ProcessKprobe == nil {
					t.Error("expected process_kprobe event, got nil")
				}
				if event.ProcessKprobe != nil {
					if event.ProcessKprobe.FunctionName == "" {
						t.Error("expected function_name in kprobe event")
					}
					if len(event.ProcessKprobe.Args) == 0 {
						t.Error("expected args in kprobe event")
					}
				}
			case "":
				// Empty event
			default:
				t.Fatalf("unknown event type: %s", tt.wantType)
			}
		})
	}
}

func TestObservabilityNetworkEventExtraction(t *testing.T) {
	input := `{
		"process_kprobe": {
			"process": {
				"binary": "/usr/bin/apk",
				"arguments": "add --no-cache gcc",
				"pid": 100
			},
			"function_name": "tcp_connect",
			"args": [{
				"sock_arg": {
					"family": "AF_INET",
					"type": "SOCK_STREAM",
					"protocol": "IPPROTO_TCP",
					"saddr": "10.0.2.15",
					"daddr": "packages.wolfi.dev",
					"sport": 54321,
					"dport": 443
				}
			}],
			"policy_name": "network-monitor"
		},
		"time": "2025-01-01T00:00:00Z"
	}`

	var event ObservabilityEvent
	if err := json.Unmarshal([]byte(input), &event); err != nil {
		t.Fatalf("failed to parse event: %v", err)
	}

	if event.ProcessKprobe == nil {
		t.Fatal("expected kprobe event")
	}

	kp := event.ProcessKprobe
	if kp.FunctionName != "tcp_connect" {
		t.Errorf("function_name = %q, want %q", kp.FunctionName, "tcp_connect")
	}
	if len(kp.Args) == 0 || kp.Args[0].SockArg == nil {
		t.Fatal("expected sock_arg in args[0]")
	}

	sock := kp.Args[0].SockArg
	if sock.DPort != 443 {
		t.Errorf("dport = %d, want 443", sock.DPort)
	}
	if sock.Protocol != "IPPROTO_TCP" {
		t.Errorf("protocol = %q, want IPPROTO_TCP", sock.Protocol)
	}
}

func TestParseObservabilityEventsFile(t *testing.T) {
	eventsData := strings.Join([]string{
		`{"process_exec":{"process":{"binary":"/bin/sh","pid":1}},"time":"2025-01-01T00:00:00Z"}`,
		`{"process_kprobe":{"process":{"binary":"/usr/bin/wget","pid":2},"function_name":"tcp_connect","args":[{"sock_arg":{"daddr":"1.2.3.4","dport":80,"family":"AF_INET","protocol":"IPPROTO_TCP"}}],"policy_name":"network-monitor"},"time":"2025-01-01T00:00:01Z"}`,
		`{"process_kprobe":{"process":{"binary":"/usr/bin/apk","pid":3},"function_name":"tcp_connect","args":[{"sock_arg":{"daddr":"5.6.7.8","dport":443,"family":"AF_INET","protocol":"IPPROTO_TCP"}}],"policy_name":"network-monitor"},"time":"2025-01-01T00:00:02Z"}`,
		`{"process_exit":{"process":{"binary":"/bin/sh","pid":1}},"time":"2025-01-01T00:00:03Z"}`,
	}, "\n")

	events, networkEvents, err := parseObservabilityEvents([]byte(eventsData))
	if err != nil {
		t.Fatalf("parseObservabilityEvents() error: %v", err)
	}

	if len(events) != 4 {
		t.Errorf("got %d events, want 4", len(events))
	}
	if len(networkEvents) != 2 {
		t.Errorf("got %d network events, want 2", len(networkEvents))
	}

	expectedIPs := map[string]uint32{"1.2.3.4": 80, "5.6.7.8": 443}
	for _, ne := range networkEvents {
		if ne.ProcessKprobe == nil || len(ne.ProcessKprobe.Args) == 0 || ne.ProcessKprobe.Args[0].SockArg == nil {
			t.Error("network event missing sock_arg")
			continue
		}
		sock := ne.ProcessKprobe.Args[0].SockArg
		wantPort, ok := expectedIPs[sock.DAddr]
		if !ok {
			t.Errorf("unexpected destination IP: %s", sock.DAddr)
		}
		if sock.DPort != wantPort {
			t.Errorf("for IP %s: dport = %d, want %d", sock.DAddr, sock.DPort, wantPort)
		}
	}
}

// --- Tests for observability.go functions ---

func TestExtractNetworkConnections(t *testing.T) {
	eventsData := strings.Join([]string{
		`{"process_exec":{"process":{"binary":"/bin/sh","pid":1}},"time":"2025-01-01T00:00:00Z"}`,
		`{"process_kprobe":{"process":{"binary":"/usr/bin/wget"},"function_name":"tcp_connect","args":[{"sock_arg":{"family":"AF_INET","protocol":"IPPROTO_TCP","saddr":"10.0.2.15","daddr":"1.2.3.4","sport":54321,"dport":80}}]},"time":"2025-01-01T00:00:01Z"}`,
		`{"process_kprobe":{"process":{"binary":"/usr/bin/apk"},"function_name":"tcp_connect","args":[{"sock_arg":{"family":"AF_INET","protocol":"IPPROTO_TCP","saddr":"10.0.2.15","daddr":"5.6.7.8","sport":54322,"dport":443}}]},"time":"2025-01-01T00:00:02Z"}`,
		`{"process_kprobe":{"process":{"binary":"/usr/bin/wget"},"function_name":"tcp_close","args":[{"sock_arg":{"family":"AF_INET","protocol":"IPPROTO_TCP","saddr":"10.0.2.15","daddr":"1.2.3.4","sport":54321,"dport":80}}]},"time":"2025-01-01T00:00:03Z"}`,
		`{"process_exit":{"process":{"binary":"/bin/sh","pid":1}},"time":"2025-01-01T00:00:04Z"}`,
	}, "\n")

	connections, eventCount := extractNetworkConnections([]byte(eventsData))
	if eventCount != 5 {
		t.Errorf("eventCount = %d, want 5", eventCount)
	}
	if len(connections) != 3 {
		t.Errorf("len(connections) = %d, want 3", len(connections))
	}
	if len(connections) > 0 {
		c := connections[0]
		if c.DstAddr != "1.2.3.4" || c.DstPort != 80 {
			t.Errorf("connection[0] = %s:%d, want 1.2.3.4:80", c.DstAddr, c.DstPort)
		}
		if c.Process != "/usr/bin/wget" {
			t.Errorf("connection[0].Process = %q, want /usr/bin/wget", c.Process)
		}
	}
}

func TestExtractNetworkConnections_EmptyData(t *testing.T) {
	connections, eventCount := extractNetworkConnections([]byte(""))
	if eventCount != 0 {
		t.Errorf("eventCount = %d, want 0", eventCount)
	}
	if len(connections) != 0 {
		t.Errorf("len(connections) = %d, want 0", len(connections))
	}
}

func TestExtractNetworkConnections_MalformedLines(t *testing.T) {
	eventsData := "not json\n{\"process_exec\":{\"process\":{\"binary\":\"/bin/sh\"}}}\n{broken\n"
	connections, eventCount := extractNetworkConnections([]byte(eventsData))
	if eventCount != 1 {
		t.Errorf("eventCount = %d, want 1 (only the valid line)", eventCount)
	}
	if len(connections) != 0 {
		t.Errorf("len(connections) = %d, want 0 (no network events)", len(connections))
	}
}

func TestLogObservabilityEvents(t *testing.T) {
	ctx := clog.WithLogger(context.Background(), slogtest.TestLogger(t))

	events := &ObservabilityEvents{
		RawData: []byte(strings.Join([]string{
			`{"process_exec":{"process":{"binary":"/bin/sh","pid":1}},"time":"2025-01-01T00:00:00Z"}`,
			`{"process_kprobe":{"process":{"binary":"/usr/bin/wget"},"function_name":"tcp_connect","args":[{"sock_arg":{"daddr":"1.2.3.4","dport":80,"family":"AF_INET","protocol":"IPPROTO_TCP","saddr":"10.0.2.15","sport":54321}}]},"time":"2025-01-01T00:00:01Z"}`,
		}, "\n")),
		EventCount: 2,
		NetworkConnections: []NetworkConnection{
			{Process: "/usr/bin/wget", Protocol: "IPPROTO_TCP", SrcAddr: "10.0.2.15", SrcPort: 54321, DstAddr: "1.2.3.4", DstPort: 80, Family: "AF_INET", Function: "tcp_connect"},
		},
	}

	// Should not panic or error — just logs to the test logger
	LogObservabilityEvents(ctx, events)
}

func TestLogObservabilityEvents_NilEvents(t *testing.T) {
	ctx := clog.WithLogger(context.Background(), slogtest.TestLogger(t))
	// Should be a no-op
	LogObservabilityEvents(ctx, nil)
}

func TestLogObservabilityEvents_EmptyRawData(t *testing.T) {
	ctx := clog.WithLogger(context.Background(), slogtest.TestLogger(t))
	// Should be a no-op
	LogObservabilityEvents(ctx, &ObservabilityEvents{})
}

// --- Helper Functions ---

// parseObservabilityEvents parses NDJSON event data.
// Returns all events and a filtered list of network-related kprobe events.
func parseObservabilityEvents(data []byte) ([]ObservabilityEvent, []ObservabilityEvent, error) {
	allEvents := make([]ObservabilityEvent, 0)
	var networkEvents []ObservabilityEvent

	for line := range bytes.SplitSeq(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var event ObservabilityEvent
		if err := json.Unmarshal(line, &event); err != nil {
			return nil, nil, err
		}
		allEvents = append(allEvents, event)
		if event.ProcessKprobe != nil {
			fn := event.ProcessKprobe.FunctionName
			if fn == "tcp_connect" || fn == "tcp_close" || fn == "tcp_sendmsg" {
				networkEvents = append(networkEvents, event)
			}
		}
	}
	return allEvents, networkEvents, nil
}
