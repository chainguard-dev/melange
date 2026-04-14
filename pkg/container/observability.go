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

	"github.com/chainguard-dev/clog"
)

// Well-known paths where the observability framework may write events.
// The hook package determines which path is used; we probe all of them.
var observabilityEventPaths = []string{
	"/var/log/observability/events.json",
	"/opt/observability-logs/events.log",
	"/tmp/observability/events.log",
}

// observabilityHookSentinel is a file installed exclusively by the
// observability hook package. Its presence in the initramfs CPIO confirms
// the hook is installed, regardless of how it was included.
// CPIO record names are stored without a leading slash.
const observabilityHookSentinel = "etc/tetragon/tetragon.tp.d/network-monitor.yaml"

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
// If cfg.ObservabilityHook is false the function returns immediately without
// probing the VM. If true, a missing events file is treated as an error.
func RetrieveObservabilityEvents(ctx context.Context, cfg *Config) (*ObservabilityEvents, error) {
	if !cfg.ObservabilityHook {
		return nil, nil
	}
	if cfg.SSHControlClient == nil {
		return nil, nil
	}

	log := clog.FromContext(ctx)

	// Probe known event file locations.
	eventsPath := ""
	for _, path := range observabilityEventPaths {
		err := sendSSHCommand(ctx, cfg.SSHControlClient, cfg, nil, nil, nil, false,
			[]string{"test", "-f", path})
		if err == nil {
			eventsPath = path
			break
		}
	}

	if eventsPath == "" {
		return nil, fmt.Errorf("observability hook is installed but no events file found at any known path: %v", observabilityEventPaths)
	}

	log.Infof("qemu: found observability events at %s", eventsPath)

	// Cap retrieval to prevent a pathological VM from exhausting host memory.
	// 50 MiB is well above normal builds (9-17k events ≈ a few MiB).
	const maxEventsBytes = 50 << 20 // 50 MiB
	var eventsBuf bytes.Buffer
	err := sendSSHCommand(ctx, cfg.SSHControlClient, cfg, nil, nil, &eventsBuf, false,
		[]string{"head", "-c", fmt.Sprintf("%d", maxEventsBytes), eventsPath})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve observability events: %w", err)
	}

	rawData := eventsBuf.Bytes()
	if len(rawData) == 0 {
		log.Warn("qemu: observability events file exists but is empty")
		return &ObservabilityEvents{RawData: rawData}, nil
	}

	// Parse events to extract network connections
	connections, eventCount := extractNetworkConnections(rawData)

	log.Infof("qemu: retrieved %d observability events (%d network connections)", eventCount, len(connections))

	return &ObservabilityEvents{
		RawData:            rawData,
		EventCount:         eventCount,
		NetworkConnections: connections,
	}, nil
}

// LogObservabilityEvents writes all observability events to melange's stdout
// via the structured logger. Each raw event is logged as a separate line with
// an [OBSERVABILITY] prefix for filtering. Network connections get a dedicated
// summary section. In the elastic build environment, these log lines flow to
// Cloud Logging via GKE pod stdout and are individually searchable.
func LogObservabilityEvents(ctx context.Context, events *ObservabilityEvents) {
	if events == nil || len(events.RawData) == 0 {
		return
	}

	log := clog.FromContext(ctx)

	// Summary header
	log.Infof("[OBSERVABILITY] === Build Observability Report: %d events, %d network connections ===",
		events.EventCount, len(events.NetworkConnections))

	// Log each network connection (high-value, low-volume)
	for _, conn := range events.NetworkConnections {
		log.Infof("[OBSERVABILITY] network: %s %s %s:%d -> %s:%d (%s)",
			conn.Function, conn.Process,
			conn.SrcAddr, conn.SrcPort,
			conn.DstAddr, conn.DstPort,
			conn.Protocol)
	}

	// Log every raw event line (for Cloud Logging ingestion)
	for line := range bytes.SplitSeq(events.RawData, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		log.Infof("[OBSERVABILITY] %s", string(line))
	}

	log.Infof("[OBSERVABILITY] === End of observability report ===")
}

// extractNetworkConnections parses NDJSON observability events and extracts
// network connection information from kprobe events.
func extractNetworkConnections(data []byte) ([]NetworkConnection, int) {
	connections := make([]NetworkConnection, 0)
	eventCount := 0

	for line := range bytes.SplitSeq(data, []byte("\n")) {
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
			_ = json.Unmarshal(t, &timestamp)
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

	return connections, eventCount
}
