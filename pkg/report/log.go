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

package report

import (
	"context"
	"log/slog"

	"github.com/chainguard-dev/clog"
)

// recorder is a slog.Handler that forwards to the original handler and
// also records Info-and-above lines into the report and the current step.
// Runners log a step's stdout at Info and its stderr at Warn through the
// context logger, so this captures step output for every runner.
type recorder struct {
	inner  slog.Handler
	report *Report
	stage  *Stage
	step   *Step
}

func withRecorder(ctx context.Context, r *Report, s *Stage, st *Step) context.Context {
	inner := clog.FromContext(ctx).Handler()
	// Unwrap so nested steps don't also record into their parent step.
	if rec, ok := inner.(*recorder); ok {
		inner = rec.inner
	}
	// Not clog.New: that would wrap the recorder and defeat the unwrap above.
	// inner is already a clog handler.
	return clog.WithLogger(ctx, clog.NewLogger(slog.New(&recorder{inner: inner, report: r, stage: s, step: st})))
}

func (h *recorder) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo || h.inner.Enabled(ctx, level)
}

func (h *recorder) Handle(ctx context.Context, rec slog.Record) error {
	if rec.Level >= slog.LevelInfo {
		h.report.record(h.stage, h.step, LogLine{Time: rec.Time, Level: rec.Level.String(), Message: rec.Message})
	}
	if !h.inner.Enabled(ctx, rec.Level) {
		return nil
	}
	return h.inner.Handle(ctx, rec)
}

func (h *recorder) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &recorder{inner: h.inner.WithAttrs(attrs), report: h.report, stage: h.stage, step: h.step}
}

func (h *recorder) WithGroup(name string) slog.Handler {
	return &recorder{inner: h.inner.WithGroup(name), report: h.report, stage: h.stage, step: h.step}
}
