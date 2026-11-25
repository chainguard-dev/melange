// Copyright 2026 Chainguard, Inc.
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

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
	collector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

func TestBuildOTLPTraceParent(t *testing.T) {
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "OTEL_") {
			t.Setenv(key, "")
		}
	}
	// Check the documented default with no service-name override in the environment.
	t.Setenv("OTEL_SERVICE_NAME", "")
	if err := os.Unsetenv("OTEL_SERVICE_NAME"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTEL_TRACES_EXPORTER", "otlp")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")

	var mu sync.Mutex
	var spans []*tracepb.Span
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/v1/traces" {
			t.Errorf("unexpected OTLP request: %s %s", req.Method, req.URL.Path)
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var data collector.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &data); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		for _, resource := range data.ResourceSpans {
			serviceName := ""
			for _, attr := range resource.Resource.GetAttributes() {
				if attr.Key == "service.name" {
					serviceName = attr.Value.GetStringValue()
				}
			}
			if serviceName != "melange" {
				t.Errorf("service.name = %q, want melange", serviceName)
			}
			for _, scope := range resource.ScopeSpans {
				spans = append(spans, scope.Spans...)
			}
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer server.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", server.URL)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	previous := otel.GetTracerProvider()
	cmd := buildCmd()
	cmd.SetArgs([]string{filepath.Join(t.TempDir(), "missing.yaml"), "--arch", "x86_64"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.ExecuteContext(ctx); err == nil {
		t.Fatal("missing config should fail")
	}
	if cmd.Context() != ctx || otel.GetTracerProvider() != previous {
		t.Error("command context or tracer provider was not restored")
	}

	// Run flushes before returning, so examine the spans received over HTTP.
	mu.Lock()
	defer mu.Unlock()
	var root, build *tracepb.Span
	roots := 0
	for _, span := range spans {
		if len(span.ParentSpanId) == 0 {
			roots++
		}
		switch span.Name {
		case "melange build":
			root = span
		case "BuildCmd":
			build = span
		}
	}
	if root == nil || build == nil {
		t.Fatal("exported melange build root or BuildCmd span missing")
	}
	if roots != 1 || len(root.ParentSpanId) != 0 {
		t.Errorf("got %d root spans, want only melange build", roots)
	}
	if !bytes.Equal(build.TraceId, root.TraceId) || !bytes.Equal(build.ParentSpanId, root.SpanId) {
		t.Error("BuildCmd is not a child of melange build")
	}
}

func TestBuildTraceFileCompatibility(t *testing.T) {
	for _, exporter := range []string{"", "otlp"} {
		name := "without-otlp"
		if exporter != "" {
			name = "with-otlp"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("OTEL_TRACES_EXPORTER", exporter)
			// If the OTLP initializer runs, it will report an error. The legacy file
			// exporter must take precedence and avoid initializing OTLP at all.
			t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "invalid")
			t.Setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "")
			previousProvider := otel.GetTracerProvider()
			previousHandler := otel.GetErrorHandler()
			t.Cleanup(func() { otel.SetTracerProvider(previousProvider); otel.SetErrorHandler(previousHandler) })
			var mu sync.Mutex
			var reported []error
			otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) { mu.Lock(); defer mu.Unlock(); reported = append(reported, err) }))
			dir := t.TempDir()
			output := filepath.Join(dir, "trace.json")
			cmd := buildCmd()
			cmd.SetArgs([]string{filepath.Join(dir, "missing.yaml"), "--arch", "x86_64", "--trace", output})
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			if err := cmd.ExecuteContext(context.Background()); err == nil {
				t.Fatal("missing config should fail")
			}
			f, err := os.Open(output)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			decoder := json.NewDecoder(f)
			found := false
			for {
				var span struct{ Name string }
				err := decoder.Decode(&span)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if span.Name == "build" {
					found = true
				}
			}
			if !found {
				t.Fatal("legacy build span missing from stdouttrace JSON file")
			}
			mu.Lock()
			defer mu.Unlock()
			if len(reported) != 0 {
				t.Errorf("legacy --trace initialized OTLP or failed to flush: %v", reported)
			}
		})
	}
}
