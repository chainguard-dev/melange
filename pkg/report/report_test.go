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
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog"
	"github.com/chainguard-dev/clog/slogtest"

	"chainguard.dev/melange/pkg/config"
)

func TestReport(t *testing.T) {
	ctx := slogtest.Context(t)
	cfg := &config.Configuration{Package: config.Package{Name: "foo", Version: "1.2.3", Epoch: 4}}
	r := New("build", cfg, "aarch64", "foo.yaml", "docker", []string{"PRIVATE"})
	ctx = r.Attach(ctx)

	clog.FromContext(ctx).Info("before any stage")

	sctx, stage := r.StartStage(ctx, "build foo", "foo")
	stage.SetEnv(map[string]string{"HOME": "/home/build", "PRIVATE": "x", "GITHUB_TOKEN": "y"})
	stage.SetPackages([]string{"go=1.0-r0"}, []Package{{Name: "zlib", Version: "1"}, {Name: "go", Version: "1.0-r0"}}, []string{"https://example.com"})
	clog.FromContext(sctx).Info("setting up guest")

	outerCtx, outer := StartStep(sctx, &config.Pipeline{Uses: "go/build", With: map[string]string{"packages": "."}}, nil)
	innerCtx, inner := StartStep(outerCtx, &config.Pipeline{Runs: "go build"}, map[string]string{"HOME": "/home/build", "PATH": "/bin"})
	clog.FromContext(innerCtx).Info("compiling")
	clog.FromContext(innerCtx).Warn("a warning on stderr")
	inner.Finish(nil)
	_, skipped := StartStep(outerCtx, &config.Pipeline{Name: "never", If: "false"}, nil)
	skipped.Skip()
	outer.Finish(nil)

	_, failing := StartStep(sctx, &config.Pipeline{Name: "fails", Runs: "false"}, nil)
	failing.Finish(errors.New("exit status 1"))

	_, post := r.StartStage(ctx, "post-build", "foo")
	r.Finish(errors.New("build failed"))

	if got := stage.Environment.Env["PRIVATE"]; got != "<redacted>" {
		t.Errorf("PRIVATE = %q, want redacted", got)
	}
	if got := stage.Environment.Env["GITHUB_TOKEN"]; got != "<redacted>" {
		t.Errorf("GITHUB_TOKEN = %q, want redacted", got)
	}
	if got := stage.Environment.Installed[0].Name; got != "go" {
		t.Errorf("installed not sorted, first is %q", got)
	}
	if len(stage.Logs) != 1 || stage.Logs[0].Message != "setting up guest" {
		t.Errorf("stage logs = %v", stage.Logs)
	}
	if len(stage.Steps) != 2 || len(outer.Steps) != 2 || outer.Steps[0] != inner {
		t.Fatalf("unexpected nesting: stage has %d steps, outer has %d", len(stage.Steps), len(outer.Steps))
	}
	if len(outer.Logs) != 0 {
		t.Errorf("outer step captured nested logs: %v", outer.Logs)
	}
	if len(inner.Logs) != 2 || inner.Logs[1].Level != "WARN" {
		t.Errorf("inner logs = %v", inner.Logs)
	}
	if skipped.Status != StatusSkipped || failing.Status != StatusFailed || inner.Status != StatusSuccess {
		t.Errorf("statuses: skipped=%s failing=%s inner=%s", skipped.Status, failing.Status, inner.Status)
	}
	if post.Status != StatusFailed || r.Status != StatusFailed {
		t.Errorf("unfinished stage = %s, report = %s; want both failed", post.Status, r.Status)
	}
	if outer.ID != "1" || inner.ID != "1.1" || skipped.ID != "1.2" || failing.ID != "2" {
		t.Errorf("ids: outer=%s inner=%s skipped=%s failing=%s", outer.ID, inner.ID, skipped.ID, failing.ID)
	}
	if len(inner.Env) != 1 || inner.Env["PATH"] != "/bin" {
		t.Errorf("step env should only hold what differs from the stage: %v", inner.Env)
	}
	if f := r.Failure; f == nil || f.Stage != "build foo" || f.StepID != "2" || f.StepPath != "fails" || f.Runs != "false" || f.Error != "exit status 1" {
		t.Errorf("failure = %+v", r.Failure)
	}
	if !strings.HasPrefix(r.ConfigFile, "/") {
		t.Errorf("config file %q is not absolute", r.ConfigFile)
	}
	if len(r.Logs) != 4 {
		t.Errorf("report has %d log lines, want 4", len(r.Logs))
	}

	dir := t.TempDir()
	paths, err := r.Write(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 3 || !strings.HasSuffix(paths[0], "foo-1.2.3-r4-aarch64.build.json") {
		t.Fatalf("paths = %v", paths)
	}
	data, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back.Stages[0].Steps[0].Steps[0].Runs != "go build" {
		t.Errorf("round-tripped nested step lost its runs: %+v", back.Stages[0].Steps[0])
	}
	md, err := os.ReadFile(paths[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"build report: foo-1.2.3-r4 (aarch64): FAILED", "logged nothing", "## Failure", "- step: 2 `fails`", "```sh\nfalse\n```", "| 1.1 | runs | success |"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("markdown report is missing %q:\n%s", want, md)
		}
	}
	html, err := os.ReadFile(paths[2])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "a warning on stderr") {
		t.Error("HTML report is missing step logs")
	}
}

func TestNilReport(t *testing.T) {
	ctx := slogtest.Context(t)
	var r *Report
	ctx = r.Attach(ctx)
	ctx, stage := r.StartStage(ctx, "x", "x")
	stage.SetEnv(nil)
	stage.SetPackages(nil, nil, nil)
	stage.Finish(nil)
	_, step := StartStep(ctx, &config.Pipeline{}, nil)
	step.Finish(nil)
	step.Skip()
	r.Finish(nil)
	if paths, err := r.Write(t.TempDir()); paths != nil || err != nil {
		t.Errorf("nil report wrote %v, %v", paths, err)
	}
}
