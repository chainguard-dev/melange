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
	"time"

	"github.com/spf13/pflag"
)

// applyCommonConfig applies project config values to CommonFlags fields,
// respecting CLI > sub-command config > global config precedence.
func applyCommonConfig(flags *CommonFlags, fs *pflag.FlagSet, sub *GlobalConfig, global *GlobalConfig) {
	setStringIfUnchanged(fs, "runner", &flags.Runner, sub.Runner, global.Runner)
	setStringSliceIfUnchanged(fs, "keyring-append", &flags.ExtraKeys, sub.KeyringAppend, global.KeyringAppend)
	setStringSliceIfUnchanged(fs, "repository-append", &flags.ExtraRepos, sub.RepositoryAppend, global.RepositoryAppend)
	setStringIfUnchanged(fs, "cache-dir", &flags.CacheDir, sub.CacheDir, global.CacheDir)
	setStringIfUnchanged(fs, "cache-source", &flags.CacheSource, sub.CacheSource, global.CacheSource)
	setStringIfUnchanged(fs, "apk-cache-dir", &flags.ApkCacheDir, sub.ApkCacheDir, global.ApkCacheDir)
	setStringSliceIfUnchanged(fs, "pipeline-dirs", &flags.PipelineDirs, sub.PipelineDirs, global.PipelineDirs)
	setStringIfUnchanged(fs, "source-dir", &flags.SourceDir, sub.SourceDir, global.SourceDir)
	setStringSliceIfUnchanged(fs, "env-file", &flags.EnvFiles, sub.EnvFile, global.EnvFile)
	setStringSliceIfUnchanged(fs, "package-append", &flags.ExtraPackages, sub.PackageAppend, global.PackageAppend)
	setBoolPtrIfUnchanged(fs, "debug", &flags.Debug, sub.Debug, global.Debug)
	setBoolPtrIfUnchanged(fs, "debug-runner", &flags.DebugRunner, sub.DebugRunner, global.DebugRunner)
	setBoolPtrIfUnchanged(fs, "interactive", &flags.Interactive, sub.Interactive, global.Interactive)
	setBoolPtrIfUnchanged(fs, "rm", &flags.Remove, sub.Remove, global.Remove)
	setBoolPtrIfUnchanged(fs, "ignore-signatures", &flags.IgnoreSignatures, sub.IgnoreSignatures, global.IgnoreSignatures)
	setStringIfUnchanged(fs, "cpu", &flags.CPU, sub.CPU, global.CPU)
	setStringIfUnchanged(fs, "cpumodel", &flags.CPUModel, sub.CPUModel, global.CPUModel)
	setStringIfUnchanged(fs, "memory", &flags.Memory, sub.Memory, global.Memory)
	setStringIfUnchanged(fs, "disk", &flags.Disk, sub.Disk, global.Disk)
	setDurationIfUnchanged(fs, "timeout", &flags.Timeout, sub.Timeout, global.Timeout)
}

// ApplyToBuildFlags applies project config values to build flags,
// respecting CLI > config file > hardcoded defaults precedence.
// A flag is only overridden if it was not explicitly set on the CLI.
func (pc *ProjectConfig) ApplyToBuildFlags(flags *BuildFlags, fs *pflag.FlagSet) {
	if pc == nil {
		return
	}

	g := &pc.Global
	b := &pc.Build

	// Common flags shared across build/test/compile.
	applyCommonConfig(&flags.CommonFlags, fs, &b.GlobalConfig, g)

	// Build has additional common-like fields with global fallback.
	setStringIfUnchanged(fs, "signing-key", &flags.SigningKey, b.SigningKey, g.SigningKey)
	setStringSliceIfUnchanged(fs, "arch", &flags.Archstrs, b.Arch, g.Arch)
	setStringIfUnchanged(fs, "out-dir", &flags.OutDir, b.OutDir, g.OutDir)
	setStringIfUnchanged(fs, "namespace", &flags.PurlNamespace, b.Namespace, g.Namespace)

	// Build-specific fields (no global fallback).
	setBoolPtrIfUnchanged(fs, "generate-index", &flags.GenerateIndex, b.GenerateIndex, nil)
	setBoolPtrIfUnchanged(fs, "empty-workspace", &flags.EmptyWorkspace, b.EmptyWorkspace, nil)
	setBoolPtrIfUnchanged(fs, "strip-origin-name", &flags.StripOriginName, b.StripOriginName, nil)
	setStringIfUnchanged(fs, "dependency-log", &flags.DependencyLog, b.DependencyLog, "")
	setStringIfUnchanged(fs, "vars-file", &flags.VarsFile, b.VarsFile, "")
	setStringSliceIfUnchanged(fs, "build-option", &flags.BuildOption, b.BuildOption, nil)
	setBoolPtrIfUnchanged(fs, "create-build-log", &flags.CreateBuildLog, b.CreateBuildLog, nil)
	setBoolPtrIfUnchanged(fs, "persist-lint-results", &flags.PersistLintResults, b.PersistLintResults, nil)
	setStringSliceIfUnchanged(fs, "lint-require", &flags.LintRequire, b.LintRequire, nil)
	setStringSliceIfUnchanged(fs, "lint-warn", &flags.LintWarn, b.LintWarn, nil)
	setBoolPtrIfUnchanged(fs, "cleanup", &flags.Cleanup, b.Cleanup, nil)
	setBoolPtrIfUnchanged(fs, "generate-provenance", &flags.GenerateProvenance, b.GenerateProvenance, nil)
	setStringIfUnchanged(fs, "override-host-triplet-libc-substitution-flavor", &flags.Libc, b.Libc, "")
}

// ApplyToTestFlags applies project config values to test flags,
// respecting CLI > config file > hardcoded defaults precedence.
func (pc *ProjectConfig) ApplyToTestFlags(flags *TestFlags, fs *pflag.FlagSet) {
	if pc == nil {
		return
	}

	g := &pc.Global
	t := &pc.Test

	// Common flags shared across build/test/compile.
	applyCommonConfig(&flags.CommonFlags, fs, &t.GlobalConfig, g)

	// Test has additional common-like fields with global fallback.
	setStringSliceIfUnchanged(fs, "arch", &flags.Archstrs, t.Arch, g.Arch)

	// Test-specific fields (no global fallback).
	setStringSliceIfUnchanged(fs, "test-option", &flags.TestOption, t.TestOption, nil)
	setStringSliceIfUnchanged(fs, "test-package-append", &flags.ExtraTestPackages, t.TestPackageAppend, nil)
}

// ApplyToCompileFlags applies project config values to compile flags,
// respecting CLI > config file > hardcoded defaults precedence.
// Compile uses the build: section for its sub-command config (there is no
// separate compile: section), falling back to global:.
func (pc *ProjectConfig) ApplyToCompileFlags(flags *CompileFlags, fs *pflag.FlagSet) {
	if pc == nil {
		return
	}

	g := &pc.Global
	b := &pc.Build

	// Common flags shared across build/test/compile.
	applyCommonConfig(&flags.CommonFlags, fs, &b.GlobalConfig, g)

	// Compile shares several fields with build.
	setStringIfUnchanged(fs, "signing-key", &flags.SigningKey, b.SigningKey, g.SigningKey)
	setStringIfUnchanged(fs, "out-dir", &flags.OutDir, b.OutDir, g.OutDir)
	setStringIfUnchanged(fs, "namespace", &flags.PurlNamespace, b.Namespace, g.Namespace)

	// Compile-specific fields from build section (no global fallback).
	setBoolPtrIfUnchanged(fs, "generate-index", &flags.GenerateIndex, b.GenerateIndex, nil)
	setBoolPtrIfUnchanged(fs, "empty-workspace", &flags.EmptyWorkspace, b.EmptyWorkspace, nil)
	setBoolPtrIfUnchanged(fs, "strip-origin-name", &flags.StripOriginName, b.StripOriginName, nil)
	setStringIfUnchanged(fs, "dependency-log", &flags.DependencyLog, b.DependencyLog, "")
	setStringIfUnchanged(fs, "vars-file", &flags.VarsFile, b.VarsFile, "")
	setStringSliceIfUnchanged(fs, "build-option", &flags.BuildOption, b.BuildOption, nil)
	setBoolPtrIfUnchanged(fs, "create-build-log", &flags.CreateBuildLog, b.CreateBuildLog, nil)
	setBoolPtrIfUnchanged(fs, "generate-provenance", &flags.GenerateProvenance, b.GenerateProvenance, nil)
}

// setStringIfUnchanged sets target to the first non-empty config value,
// but only if the named flag was not explicitly set on the command line.
// Note: an empty string in YAML (e.g. signing-key: "") is treated as "not set"
// and falls through to the next precedence level.
func setStringIfUnchanged(fs *pflag.FlagSet, name string, target *string, values ...string) {
	if fs.Changed(name) {
		return
	}
	for _, v := range values {
		if v != "" {
			*target = v
			return
		}
	}
}

// setBoolPtrIfUnchanged sets target to the first non-nil *bool config value,
// but only if the named flag was not explicitly set on the command line.
func setBoolPtrIfUnchanged(fs *pflag.FlagSet, name string, target *bool, values ...*bool) {
	if fs.Changed(name) {
		return
	}
	for _, v := range values {
		if v != nil {
			*target = *v
			return
		}
	}
}

// setStringSliceIfUnchanged sets target to the first non-nil, non-empty slice config value,
// but only if the named flag was not explicitly set on the command line.
func setStringSliceIfUnchanged(fs *pflag.FlagSet, name string, target *[]string, values ...[]string) {
	if fs.Changed(name) {
		return
	}
	for _, v := range values {
		if len(v) > 0 {
			*target = v
			return
		}
	}
}

// setDurationIfUnchanged sets target to the first non-zero duration config value,
// but only if the named flag was not explicitly set on the command line.
func setDurationIfUnchanged(fs *pflag.FlagSet, name string, target *time.Duration, values ...time.Duration) {
	if fs.Changed(name) {
		return
	}
	for _, v := range values {
		if v != 0 {
			*target = v
			return
		}
	}
}
