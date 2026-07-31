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
	"fmt"
	"time"

	"github.com/spf13/pflag"

	"chainguard.dev/melange/pkg/build"
)

// CommonFlags holds flags shared across build, test, and compile commands.
type CommonFlags struct {
	WorkspaceDir     string
	SourceDir        string
	CacheDir         string
	CacheSource      string
	ApkCacheDir      string
	Runner           string
	ExtraKeys        []string // keyring-append
	ExtraRepos       []string // repository-append
	EnvFiles         []string // env-file
	ExtraPackages    []string // package-append
	PipelineDirs     []string
	Debug            bool
	DebugRunner      bool
	Interactive      bool
	Remove           bool // rm
	IgnoreSignatures bool
	CPU              string
	CPUModel         string
	Memory           string
	Disk             string
	Timeout          time.Duration
}

// addCommonFlags registers the shared flags onto fs, bound to the CommonFlags fields.
// The caller should pre-set any fields that need non-zero defaults (e.g. Remove, CacheDir)
// before calling this function — the current field values are used as the flag defaults.
func addCommonFlags(fs *pflag.FlagSet, flags *CommonFlags) {
	fs.StringVar(&flags.WorkspaceDir, "workspace-dir", flags.WorkspaceDir, "directory used for the workspace at /home/build")
	fs.StringSliceVar(&flags.PipelineDirs, "pipeline-dirs", flags.PipelineDirs, "directories used to extend defined built-in pipelines")
	fs.StringVar(&flags.SourceDir, "source-dir", flags.SourceDir, "directory used for included sources")
	fs.StringVar(&flags.CacheDir, "cache-dir", flags.CacheDir, "directory used for cached inputs")
	fs.StringVar(&flags.CacheSource, "cache-source", flags.CacheSource, "directory or bucket used for preloading the cache")
	fs.StringVar(&flags.ApkCacheDir, "apk-cache-dir", flags.ApkCacheDir, "directory used for cached apk packages (default is system-defined cache directory)")
	fs.StringVar(&flags.Runner, "runner", flags.Runner, fmt.Sprintf("which runner to use to enable running commands, default is based on your platform. Options are %q", build.GetAllRunners()))
	fs.StringSliceVarP(&flags.ExtraKeys, "keyring-append", "k", flags.ExtraKeys, "path to extra keys to include in the build environment keyring")
	fs.StringSliceVarP(&flags.ExtraRepos, "repository-append", "r", flags.ExtraRepos, "path to extra repositories to include in the build environment")
	fs.StringSliceVar(&flags.ExtraPackages, "package-append", flags.ExtraPackages, "extra packages to install for each of the build environments")
	fs.StringSliceVar(&flags.EnvFiles, "env-file", flags.EnvFiles, "files to use for preloaded environment variables")
	fs.BoolVar(&flags.Debug, "debug", flags.Debug, "enables debug logging of pipelines")
	fs.BoolVar(&flags.DebugRunner, "debug-runner", flags.DebugRunner, "when enabled, the runner pod will persist after the build succeeds or fails")
	fs.BoolVarP(&flags.Interactive, "interactive", "i", flags.Interactive, "when enabled, attaches stdin with a tty to the pod on failure")
	fs.BoolVar(&flags.Remove, "rm", flags.Remove, "clean up intermediate artifacts (e.g. container images, temp dirs)")
	fs.BoolVar(&flags.IgnoreSignatures, "ignore-signatures", flags.IgnoreSignatures, "ignore repository signature verification")
	fs.StringVar(&flags.CPU, "cpu", flags.CPU, "default CPU resources to use")
	fs.StringVar(&flags.CPUModel, "cpumodel", flags.CPUModel, "default CPU model to use")
	fs.StringVar(&flags.Memory, "memory", flags.Memory, "default memory resources to use")
	fs.StringVar(&flags.Disk, "disk", flags.Disk, "default disk size to use")
	fs.DurationVar(&flags.Timeout, "timeout", flags.Timeout, "default timeout")
}
