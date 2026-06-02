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

// ApplyToBuildFlags applies project config values to build flags,
// respecting CLI > config file > hardcoded defaults precedence.
// A flag is only overridden if it was not explicitly set on the CLI.
func (pc *ProjectConfig) ApplyToBuildFlags(flags *BuildFlags, fs *pflag.FlagSet) {
	if pc == nil {
		return
	}

	g := &pc.Global
	b := &pc.Build

	// For each flag, try the build section first (more specific), then global.
	// The build section embeds GlobalConfig, so b.GlobalConfig fields are
	// the per-subcommand overrides of global settings.

	setStringIfUnchanged(fs, "runner", &flags.Runner, b.Runner, g.Runner)
	setStringIfUnchanged(fs, "signing-key", &flags.SigningKey, b.SigningKey, g.SigningKey)
	setStringSliceIfUnchanged(fs, "keyring-append", &flags.ExtraKeys, b.KeyringAppend, g.KeyringAppend)
	setStringSliceIfUnchanged(fs, "repository-append", &flags.ExtraRepos, b.RepositoryAppend, g.RepositoryAppend)
	setStringSliceIfUnchanged(fs, "arch", &flags.Archstrs, b.Arch, g.Arch)
	setStringIfUnchanged(fs, "out-dir", &flags.OutDir, b.OutDir, g.OutDir)
	setStringIfUnchanged(fs, "cache-dir", &flags.CacheDir, b.CacheDir, g.CacheDir)
	setStringIfUnchanged(fs, "cache-source", &flags.CacheSource, b.CacheSource, g.CacheSource)
	setStringIfUnchanged(fs, "apk-cache-dir", &flags.ApkCacheDir, b.ApkCacheDir, g.ApkCacheDir)
	setStringIfUnchanged(fs, "namespace", &flags.PurlNamespace, b.Namespace, g.Namespace)
	setStringSliceIfUnchanged(fs, "pipeline-dirs", &flags.PipelineDirs, b.PipelineDirs, g.PipelineDirs)
	setStringIfUnchanged(fs, "source-dir", &flags.SourceDir, b.SourceDir, g.SourceDir)
	setStringSliceIfUnchanged(fs, "env-file", &flags.EnvFiles, b.EnvFile, g.EnvFile)
	setStringSliceIfUnchanged(fs, "package-append", &flags.ExtraPackages, b.PackageAppend, g.PackageAppend)
	setBoolPtrIfUnchanged(fs, "debug", &flags.Debug, b.Debug, g.Debug)
	setBoolPtrIfUnchanged(fs, "debug-runner", &flags.DebugRunner, b.DebugRunner, g.DebugRunner)
	setBoolPtrIfUnchanged(fs, "interactive", &flags.Interactive, b.Interactive, g.Interactive)
	setBoolPtrIfUnchanged(fs, "rm", &flags.Remove, b.Remove, g.Remove)
	setBoolPtrIfUnchanged(fs, "ignore-signatures", &flags.IgnoreSignatures, b.IgnoreSignatures, g.IgnoreSignatures)
	setStringIfUnchanged(fs, "cpu", &flags.CPU, b.CPU, g.CPU)
	setStringIfUnchanged(fs, "cpumodel", &flags.CPUModel, b.CPUModel, g.CPUModel)
	setStringIfUnchanged(fs, "memory", &flags.Memory, b.Memory, g.Memory)
	setStringIfUnchanged(fs, "disk", &flags.Disk, b.Disk, g.Disk)
	setDurationIfUnchanged(fs, "timeout", &flags.Timeout, b.Timeout, g.Timeout)

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

	setStringIfUnchanged(fs, "runner", &flags.Runner, t.Runner, g.Runner)
	setStringSliceIfUnchanged(fs, "keyring-append", &flags.ExtraKeys, t.KeyringAppend, g.KeyringAppend)
	setStringSliceIfUnchanged(fs, "repository-append", &flags.ExtraRepos, t.RepositoryAppend, g.RepositoryAppend)
	setStringSliceIfUnchanged(fs, "arch", &flags.Archstrs, t.Arch, g.Arch)
	setStringIfUnchanged(fs, "cache-dir", &flags.CacheDir, t.CacheDir, g.CacheDir)
	setStringIfUnchanged(fs, "cache-source", &flags.CacheSource, t.CacheSource, g.CacheSource)
	setStringIfUnchanged(fs, "apk-cache-dir", &flags.ApkCacheDir, t.ApkCacheDir, g.ApkCacheDir)
	setStringSliceIfUnchanged(fs, "pipeline-dirs", &flags.PipelineDirs, t.PipelineDirs, g.PipelineDirs)
	setStringIfUnchanged(fs, "source-dir", &flags.SourceDir, t.SourceDir, g.SourceDir)
	setStringSliceIfUnchanged(fs, "env-file", &flags.EnvFiles, t.EnvFile, g.EnvFile)
	setBoolPtrIfUnchanged(fs, "debug", &flags.Debug, t.Debug, g.Debug)
	setBoolPtrIfUnchanged(fs, "debug-runner", &flags.DebugRunner, t.DebugRunner, g.DebugRunner)
	setBoolPtrIfUnchanged(fs, "interactive", &flags.Interactive, t.Interactive, g.Interactive)
	setBoolPtrIfUnchanged(fs, "rm", &flags.Remove, t.Remove, g.Remove)
	setBoolPtrIfUnchanged(fs, "ignore-signatures", &flags.IgnoreSignatures, t.IgnoreSignatures, g.IgnoreSignatures)
	setStringIfUnchanged(fs, "cpu", &flags.CPU, t.CPU, g.CPU)
	setStringIfUnchanged(fs, "cpumodel", &flags.CPUModel, t.CPUModel, g.CPUModel)
	setStringIfUnchanged(fs, "memory", &flags.Memory, t.Memory, g.Memory)
	setStringIfUnchanged(fs, "disk", &flags.Disk, t.Disk, g.Disk)
	setDurationIfUnchanged(fs, "timeout", &flags.Timeout, t.Timeout, g.Timeout)

	// Test-specific fields (no global fallback).
	setStringSliceIfUnchanged(fs, "test-option", &flags.TestOption, t.TestOption, nil)
	setStringSliceIfUnchanged(fs, "test-package-append", &flags.ExtraTestPackages, t.TestPackageAppend, nil)
}

// setStringIfUnchanged sets target to the first non-empty config value,
// but only if the named flag was not explicitly set on the command line.
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
