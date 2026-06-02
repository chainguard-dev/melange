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

package cli

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/pflag"
)

func TestFlagDefaults_Remove(t *testing.T) {
	// Build defaults --rm to true.
	buildFlags := &BuildFlags{}
	buildFS := pflag.NewFlagSet("build", pflag.ContinueOnError)
	addBuildFlags(buildFS, buildFlags)
	if !buildFlags.Remove {
		t.Error("build --rm should default to true")
	}

	// Test defaults --rm to true.
	testFlags := &TestFlags{}
	testFS := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addTestFlags(testFS, testFlags)
	if !testFlags.Remove {
		t.Error("test --rm should default to true")
	}

	// Compile defaults --rm to false.
	compileFlags := &CompileFlags{}
	compileFS := pflag.NewFlagSet("compile", pflag.ContinueOnError)
	addCompileFlags(compileFS, compileFlags)
	if compileFlags.Remove {
		t.Error("compile --rm should default to false")
	}
}

func TestFlagDefaults_CacheDir(t *testing.T) {
	// Build defaults --cache-dir to "./melange-cache/".
	buildFlags := &BuildFlags{}
	buildFS := pflag.NewFlagSet("build", pflag.ContinueOnError)
	addBuildFlags(buildFS, buildFlags)
	if buildFlags.CacheDir != "./melange-cache/" {
		t.Errorf("build --cache-dir = %q, want %q", buildFlags.CacheDir, "./melange-cache/")
	}

	// Test defaults --cache-dir to "".
	testFlags := &TestFlags{}
	testFS := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addTestFlags(testFS, testFlags)
	if testFlags.CacheDir != "" {
		t.Errorf("test --cache-dir = %q, want %q", testFlags.CacheDir, "")
	}

	// Compile defaults --cache-dir to "./melange-cache/".
	compileFlags := &CompileFlags{}
	compileFS := pflag.NewFlagSet("compile", pflag.ContinueOnError)
	addCompileFlags(compileFS, compileFlags)
	if compileFlags.CacheDir != "./melange-cache/" {
		t.Errorf("compile --cache-dir = %q, want %q", compileFlags.CacheDir, "./melange-cache/")
	}
}

func TestLoadProjectConfig(t *testing.T) {
	cfg, err := LoadProjectConfig("testdata/.melange.yaml")
	if err != nil {
		t.Fatalf("LoadProjectConfig: %v", err)
	}

	// Global section
	if cfg.Global.Runner != "bubblewrap" {
		t.Errorf("Global.Runner = %q, want %q", cfg.Global.Runner, "bubblewrap")
	}
	if cfg.Global.SigningKey != "local-signing.rsa" {
		t.Errorf("Global.SigningKey = %q, want %q", cfg.Global.SigningKey, "local-signing.rsa")
	}
	wantKeys := []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}
	if diff := cmp.Diff(wantKeys, cfg.Global.KeyringAppend); diff != "" {
		t.Errorf("Global.KeyringAppend mismatch (-want +got):\n%s", diff)
	}
	wantRepos := []string{"https://packages.wolfi.dev/os"}
	if diff := cmp.Diff(wantRepos, cfg.Global.RepositoryAppend); diff != "" {
		t.Errorf("Global.RepositoryAppend mismatch (-want +got):\n%s", diff)
	}
	wantArch := []string{"x86_64", "aarch64"}
	if diff := cmp.Diff(wantArch, cfg.Global.Arch); diff != "" {
		t.Errorf("Global.Arch mismatch (-want +got):\n%s", diff)
	}
	if cfg.Global.Namespace != "wolfi" {
		t.Errorf("Global.Namespace = %q, want %q", cfg.Global.Namespace, "wolfi")
	}
	if cfg.Global.Debug == nil || !*cfg.Global.Debug {
		t.Error("Global.Debug should be true")
	}

	// Build section
	if cfg.Build.Runner != "qemu" {
		t.Errorf("Build.Runner = %q, want %q", cfg.Build.Runner, "qemu")
	}
	wantLint := []string{"dev", "opt"}
	if diff := cmp.Diff(wantLint, cfg.Build.LintRequire); diff != "" {
		t.Errorf("Build.LintRequire mismatch (-want +got):\n%s", diff)
	}
	if cfg.Build.GenerateIndex == nil || *cfg.Build.GenerateIndex != false {
		t.Error("Build.GenerateIndex should be false")
	}

	// Test section
	wantTestPkgs := []string{"wolfi-base"}
	if diff := cmp.Diff(wantTestPkgs, cfg.Test.TestPackageAppend); diff != "" {
		t.Errorf("Test.TestPackageAppend mismatch (-want +got):\n%s", diff)
	}
}

func TestLoadProjectConfig_UnknownField(t *testing.T) {
	_, err := LoadProjectConfig("testdata/.melange-invalid-field.yaml")
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
	t.Logf("got expected error: %v", err)
}

func TestApplyToBuildFlags_CLIOverridesConfig(t *testing.T) {
	pc := &ProjectConfig{
		Global: GlobalConfig{
			Runner: "bubblewrap",
		},
	}

	flags := &BuildFlags{}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addBuildFlags(fs, flags)

	// Simulate CLI: --runner=docker
	if err := fs.Parse([]string{"--runner=docker"}); err != nil {
		t.Fatal(err)
	}

	pc.ApplyToBuildFlags(flags, fs)

	if flags.Runner != "docker" {
		t.Errorf("Runner = %q, want %q (CLI should override config)", flags.Runner, "docker")
	}
}

func TestApplyToBuildFlags_ConfigOverridesDefault(t *testing.T) {
	pc := &ProjectConfig{
		Global: GlobalConfig{
			Runner:    "bubblewrap",
			Namespace: "wolfi",
			Debug:     new(true),
		},
	}

	flags := &BuildFlags{}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addBuildFlags(fs, flags)

	// No CLI flags set — parse empty args
	if err := fs.Parse([]string{}); err != nil {
		t.Fatal(err)
	}

	pc.ApplyToBuildFlags(flags, fs)

	if flags.Runner != "bubblewrap" {
		t.Errorf("Runner = %q, want %q", flags.Runner, "bubblewrap")
	}
	if flags.PurlNamespace != "wolfi" {
		t.Errorf("PurlNamespace = %q, want %q", flags.PurlNamespace, "wolfi")
	}
	if !flags.Debug {
		t.Error("Debug should be true from config")
	}
}

func TestApplyToBuildFlags_BuildOverridesGlobal(t *testing.T) {
	pc := &ProjectConfig{
		Global: GlobalConfig{
			Runner: "bubblewrap",
		},
		Build: BuildSectionConfig{
			GlobalConfig: GlobalConfig{
				Runner: "qemu",
			},
		},
	}

	flags := &BuildFlags{}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addBuildFlags(fs, flags)
	if err := fs.Parse([]string{}); err != nil {
		t.Fatal(err)
	}

	pc.ApplyToBuildFlags(flags, fs)

	if flags.Runner != "qemu" {
		t.Errorf("Runner = %q, want %q (build section should override global)", flags.Runner, "qemu")
	}
}

func TestApplyToBuildFlags_NilConfig(t *testing.T) {
	flags := &BuildFlags{}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addBuildFlags(fs, flags)

	// Set a value after flag registration to simulate a default.
	flags.Runner = "original"

	var pc *ProjectConfig
	pc.ApplyToBuildFlags(flags, fs)

	if flags.Runner != "original" {
		t.Errorf("Runner = %q, want %q (nil config should be no-op)", flags.Runner, "original")
	}
}

func TestApplyToCompileFlags_ConfigApplied(t *testing.T) {
	pc := &ProjectConfig{
		Global: GlobalConfig{
			Runner: "bubblewrap",
			KeyringAppend: []string{
				"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub",
			},
			Namespace: "wolfi",
			Debug:     new(true),
		},
		Build: BuildSectionConfig{
			GlobalConfig: GlobalConfig{
				Runner: "qemu",
			},
			GenerateIndex: new(false),
		},
	}

	flags := &CompileFlags{}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addCompileFlags(fs, flags)
	if err := fs.Parse([]string{"--arch=x86_64"}); err != nil {
		t.Fatal(err)
	}

	pc.ApplyToCompileFlags(flags, fs)

	// Build section runner overrides global.
	if flags.Runner != "qemu" {
		t.Errorf("Runner = %q, want %q", flags.Runner, "qemu")
	}
	// Global keyring applied.
	wantKeys := []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}
	if diff := cmp.Diff(wantKeys, flags.ExtraKeys); diff != "" {
		t.Errorf("ExtraKeys mismatch (-want +got):\n%s", diff)
	}
	// Global namespace applied.
	if flags.PurlNamespace != "wolfi" {
		t.Errorf("PurlNamespace = %q, want %q", flags.PurlNamespace, "wolfi")
	}
	// Global debug applied.
	if !flags.Debug {
		t.Error("Debug should be true from config")
	}
	// Build section generate-index applied.
	if flags.GenerateIndex {
		t.Error("GenerateIndex should be false from build config")
	}
}

func TestApplyToCompileFlags_ConfigOverridesDefault(t *testing.T) {
	pc := &ProjectConfig{
		Global: GlobalConfig{
			Runner:    "bubblewrap",
			Namespace: "wolfi",
			Debug:     new(true),
		},
	}

	flags := &CompileFlags{}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addCompileFlags(fs, flags)
	if err := fs.Parse([]string{"--arch=x86_64"}); err != nil {
		t.Fatal(err)
	}

	pc.ApplyToCompileFlags(flags, fs)

	if flags.Runner != "bubblewrap" {
		t.Errorf("Runner = %q, want %q", flags.Runner, "bubblewrap")
	}
	if flags.PurlNamespace != "wolfi" {
		t.Errorf("PurlNamespace = %q, want %q", flags.PurlNamespace, "wolfi")
	}
	if !flags.Debug {
		t.Error("Debug should be true from config")
	}
}

func TestApplyToCompileFlags_BuildOverridesGlobal(t *testing.T) {
	pc := &ProjectConfig{
		Global: GlobalConfig{
			Runner: "bubblewrap",
		},
		Build: BuildSectionConfig{
			GlobalConfig: GlobalConfig{
				Runner: "qemu",
			},
		},
	}

	flags := &CompileFlags{}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addCompileFlags(fs, flags)
	if err := fs.Parse([]string{"--arch=x86_64"}); err != nil {
		t.Fatal(err)
	}

	pc.ApplyToCompileFlags(flags, fs)

	if flags.Runner != "qemu" {
		t.Errorf("Runner = %q, want %q (build section should override global)", flags.Runner, "qemu")
	}
}

func TestApplyToCompileFlags_NilConfig(t *testing.T) {
	flags := &CompileFlags{}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addCompileFlags(fs, flags)

	flags.Runner = "original"

	var pc *ProjectConfig
	pc.ApplyToCompileFlags(flags, fs)

	if flags.Runner != "original" {
		t.Errorf("Runner = %q, want %q (nil config should be no-op)", flags.Runner, "original")
	}
}

func TestApplyToCompileFlags_CLIOverridesConfig(t *testing.T) {
	pc := &ProjectConfig{
		Global: GlobalConfig{
			Runner: "bubblewrap",
		},
	}

	flags := &CompileFlags{}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addCompileFlags(fs, flags)

	// Simulate CLI: --runner=docker --arch=x86_64
	if err := fs.Parse([]string{"--runner=docker", "--arch=x86_64"}); err != nil {
		t.Fatal(err)
	}

	pc.ApplyToCompileFlags(flags, fs)

	if flags.Runner != "docker" {
		t.Errorf("Runner = %q, want %q (CLI should override config)", flags.Runner, "docker")
	}
}

func TestApplyToTestFlags_ConfigApplied(t *testing.T) {
	pc := &ProjectConfig{
		Global: GlobalConfig{
			Runner: "bubblewrap",
			KeyringAppend: []string{
				"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub",
			},
		},
		Test: TestSectionConfig{
			TestPackageAppend: []string{"wolfi-base"},
		},
	}

	flags := &TestFlags{}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addTestFlags(fs, flags)
	if err := fs.Parse([]string{}); err != nil {
		t.Fatal(err)
	}

	pc.ApplyToTestFlags(flags, fs)

	if flags.Runner != "bubblewrap" {
		t.Errorf("Runner = %q, want %q", flags.Runner, "bubblewrap")
	}
	wantKeys := []string{"https://packages.wolfi.dev/os/wolfi-signing.rsa.pub"}
	if diff := cmp.Diff(wantKeys, flags.ExtraKeys); diff != "" {
		t.Errorf("ExtraKeys mismatch (-want +got):\n%s", diff)
	}
	wantPkgs := []string{"wolfi-base"}
	if diff := cmp.Diff(wantPkgs, flags.ExtraTestPackages); diff != "" {
		t.Errorf("ExtraTestPackages mismatch (-want +got):\n%s", diff)
	}
}

func TestApplyToTestFlags_CLIOverridesConfig(t *testing.T) {
	pc := &ProjectConfig{
		Global: GlobalConfig{
			Runner: "bubblewrap",
		},
	}

	flags := &TestFlags{}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addTestFlags(fs, flags)

	// Simulate CLI: --runner=docker
	if err := fs.Parse([]string{"--runner=docker"}); err != nil {
		t.Fatal(err)
	}

	pc.ApplyToTestFlags(flags, fs)

	if flags.Runner != "docker" {
		t.Errorf("Runner = %q, want %q (CLI should override config)", flags.Runner, "docker")
	}
}

func TestApplyToTestFlags_ConfigOverridesDefault(t *testing.T) {
	pc := &ProjectConfig{
		Global: GlobalConfig{
			Runner: "bubblewrap",
			Debug:  new(true),
		},
	}

	flags := &TestFlags{}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addTestFlags(fs, flags)
	if err := fs.Parse([]string{}); err != nil {
		t.Fatal(err)
	}

	pc.ApplyToTestFlags(flags, fs)

	if flags.Runner != "bubblewrap" {
		t.Errorf("Runner = %q, want %q", flags.Runner, "bubblewrap")
	}
	if !flags.Debug {
		t.Error("Debug should be true from config")
	}
}

func TestApplyToTestFlags_TestOverridesGlobal(t *testing.T) {
	pc := &ProjectConfig{
		Global: GlobalConfig{
			Runner: "bubblewrap",
		},
		Test: TestSectionConfig{
			GlobalConfig: GlobalConfig{
				Runner: "qemu",
			},
		},
	}

	flags := &TestFlags{}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addTestFlags(fs, flags)
	if err := fs.Parse([]string{}); err != nil {
		t.Fatal(err)
	}

	pc.ApplyToTestFlags(flags, fs)

	if flags.Runner != "qemu" {
		t.Errorf("Runner = %q, want %q (test section should override global)", flags.Runner, "qemu")
	}
}

func TestApplyToTestFlags_NilConfig(t *testing.T) {
	flags := &TestFlags{}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addTestFlags(fs, flags)

	flags.Runner = "original"

	var pc *ProjectConfig
	pc.ApplyToTestFlags(flags, fs)

	if flags.Runner != "original" {
		t.Errorf("Runner = %q, want %q (nil config should be no-op)", flags.Runner, "original")
	}
}
