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
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
)

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
