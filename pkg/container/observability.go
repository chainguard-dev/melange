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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainguard-dev/clog"
)

// Well-known paths where the observability framework may write events.
// The hook package determines which path is used; we probe all of them.
var observabilityEventPaths = []string{
	"/var/log/observability/events.json",
	"/var/log/tetragon/events.json",
	"/opt/observability-logs/events.log",
	"/tmp/observability/events.log",
}

// ObservabilityEvents holds parsed event data retrieved from the build VM.
type ObservabilityEvents struct {
	// RawData is the raw NDJSON event data.
	RawData []byte

	// EventCount is the total number of events.
	EventCount int

	// NetworkConnections is the list of network connections observed.
	NetworkConnections []NetworkConnection
}

// NetworkConnection represents a single observed network connection.
type NetworkConnection struct {
	Process   string `json:"process"`
	Protocol  string `json:"protocol"`
	SrcAddr   string `json:"src_addr"`
	SrcPort   uint32 `json:"src_port"`
	DstAddr   string `json:"dst_addr"`
	DstPort   uint32 `json:"dst_port"`
	Family    string `json:"family"`
	Function  string `json:"function"` // tcp_connect, tcp_close, etc.
	Timestamp string `json:"timestamp"`
}

// RetrieveObservabilityEvents fetches observability events from the build VM
// via the SSHControlClient (port 2223, unchrooted root access). This should
// be called after the build completes but before TerminatePod.
//
// Returns nil with no error if the observability hook is not installed or no
// events were generated. This makes the feature fully optional — default
// builds without the hook are completely unaffected.
func RetrieveObservabilityEvents(ctx context.Context, cfg *Config) (*ObservabilityEvents, error) {
	if cfg.SSHControlClient == nil {
		return nil, nil
	}

	log := clog.FromContext(ctx)

	// Probe known event file locations. If none exist, the observability
	// hook is not installed and we silently return nil.
	eventsPath := ""
	for _, path := range observabilityEventPaths {
		var checkBuf bytes.Buffer
		err := sendSSHCommand(ctx, cfg.SSHControlClient, cfg, nil, nil, &checkBuf, false,
			[]string{"sh", "-c", fmt.Sprintf("test -f %s && echo exists || echo missing", path)})
		if err != nil {
			continue
		}
		if strings.TrimSpace(checkBuf.String()) == "exists" {
			eventsPath = path
			break
		}
	}

	if eventsPath == "" {
		// No events file found — observability hook is not installed.
		// This is the normal case for default builds; return silently.
		return nil, nil
	}

	log.Infof("qemu: found observability events at %s", eventsPath)

	// Retrieve the events file
	var eventsBuf bytes.Buffer
	err := sendSSHCommand(ctx, cfg.SSHControlClient, cfg, nil, nil, &eventsBuf, false,
		[]string{"cat", eventsPath})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve observability events: %w", err)
	}

	rawData := eventsBuf.Bytes()
	if len(rawData) == 0 {
		log.Warn("qemu: observability events file exists but is empty")
		return &ObservabilityEvents{RawData: rawData}, nil
	}

	// Parse events to extract network connections
	connections, eventCount, err := extractNetworkConnections(rawData)
	if err != nil {
		log.Warnf("qemu: failed to parse observability events: %v", err)
		return &ObservabilityEvents{RawData: rawData}, nil
	}

	log.Infof("qemu: retrieved %d observability events (%d network connections)", eventCount, len(connections))

	return &ObservabilityEvents{
		RawData:            rawData,
		EventCount:         eventCount,
		NetworkConnections: connections,
	}, nil
}

// SaveObservabilityEvents writes the observability events to a file in the
// workspace. The events are saved as NDJSON alongside the build artifacts.
func SaveObservabilityEvents(ctx context.Context, events *ObservabilityEvents, workspaceDir string) error {
	if events == nil || len(events.RawData) == 0 {
		return nil
	}

	log := clog.FromContext(ctx)

	eventsDir := filepath.Join(workspaceDir, "observability")
	if err := os.MkdirAll(eventsDir, 0o755); err != nil {
		return fmt.Errorf("failed to create observability events directory: %w", err)
	}

	eventsPath := filepath.Join(eventsDir, "events.json")
	if err := os.WriteFile(eventsPath, events.RawData, 0o644); err != nil {
		return fmt.Errorf("failed to write observability events: %w", err)
	}

	log.Infof("qemu: saved observability events to %s (%d bytes)", eventsPath, len(events.RawData))

	if len(events.NetworkConnections) > 0 {
		summaryPath := filepath.Join(eventsDir, "network-connections.json")
		summaryData, err := json.MarshalIndent(events.NetworkConnections, "", "  ")
		if err != nil {
			log.Warnf("qemu: failed to marshal network connections summary: %v", err)
		} else {
			if err := os.WriteFile(summaryPath, summaryData, 0o644); err != nil {
				log.Warnf("qemu: failed to write network connections summary: %v", err)
			} else {
				log.Infof("qemu: saved %d network connections to %s", len(events.NetworkConnections), summaryPath)
			}
		}
	}

	return nil
}

// extractNetworkConnections parses NDJSON observability events and extracts
// network connection information from kprobe events.
func extractNetworkConnections(data []byte) ([]NetworkConnection, int, error) {
	var connections []NetworkConnection
	eventCount := 0

	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var raw map[string]json.RawMessage
		if err := json.Unmarshal(line, &raw); err != nil {
			continue // Skip malformed lines
		}
		eventCount++

		kprobeData, ok := raw["process_kprobe"]
		if !ok {
			continue
		}

		var kprobe struct {
			Process struct {
				Binary string `json:"binary"`
			} `json:"process"`
			FunctionName string `json:"function_name"`
			Args         []struct {
				SockArg *struct {
					Family   string `json:"family"`
					Protocol string `json:"protocol"`
					SAddr    string `json:"saddr"`
					DAddr    string `json:"daddr"`
					SPort    uint32 `json:"sport"`
					DPort    uint32 `json:"dport"`
				} `json:"sock_arg,omitempty"`
			} `json:"args"`
		}

		if err := json.Unmarshal(kprobeData, &kprobe); err != nil {
			continue
		}

		switch kprobe.FunctionName {
		case "tcp_connect", "tcp_close", "tcp_sendmsg":
		default:
			continue
		}

		if len(kprobe.Args) == 0 || kprobe.Args[0].SockArg == nil {
			continue
		}

		sock := kprobe.Args[0].SockArg
		timestamp := ""
		if t, ok := raw["time"]; ok {
			json.Unmarshal(t, &timestamp)
		}

		connections = append(connections, NetworkConnection{
			Process:   kprobe.Process.Binary,
			Protocol:  sock.Protocol,
			SrcAddr:   sock.SAddr,
			SrcPort:   sock.SPort,
			DstAddr:   sock.DAddr,
			DstPort:   sock.DPort,
			Family:    sock.Family,
			Function:  kprobe.FunctionName,
			Timestamp: timestamp,
		})
	}

	return connections, eventCount, nil
}
