// Copyright 2023 Chainguard, Inc.
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
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/melange/pkg/build"
)

// addTestFlags registers all test command flags to the provided FlagSet using the TestFlags struct
func addTestFlags(fs *pflag.FlagSet, flags *TestFlags) {
	fs.StringVar(&flags.WorkspaceDir, "workspace-dir", "", "directory used for the workspace at /home/build")
	fs.StringSliceVar(&flags.PipelineDirs, "pipeline-dirs", []string{}, "directories used to extend defined built-in pipelines")
	fs.StringVar(&flags.SourceDir, "source-dir", "", "directory used for included sources")
	fs.StringVar(&flags.CacheDir, "cache-dir", "", "directory used for cached inputs")
	fs.StringVar(&flags.CacheSource, "cache-source", "", "directory or bucket used for preloading the cache")
	fs.StringVar(&flags.ApkCacheDir, "apk-cache-dir", "", "directory used for cached apk packages (default is system-defined cache directory)")
	fs.StringSliceVar(&flags.Archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config")
	fs.StringSliceVar(&flags.TestOption, "test-option", []string{}, "build options to enable")
	fs.StringVar(&flags.Runner, "runner", "", fmt.Sprintf("which runner to use to enable running commands, default is based on your platform. Options are %q", build.GetAllRunners()))
	fs.StringSliceVarP(&flags.ExtraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the build environment keyring")
	fs.StringVar(&flags.EnvFile, "env-file", "", "file to use for preloaded environment variables")
	fs.BoolVar(&flags.Debug, "debug", false, "enables debug logging of test pipelines (sets -x for steps)")
	fs.BoolVar(&flags.DebugRunner, "debug-runner", false, "when enabled, the builder pod will persist after the build succeeds or fails")
	fs.BoolVarP(&flags.Interactive, "interactive", "i", false, "when enabled, attaches stdin with a tty to the pod on failure")
	fs.StringSliceVarP(&flags.ExtraRepos, "repository-append", "r", []string{}, "path to extra repositories to include in the build environment")
	fs.StringSliceVar(&flags.ExtraTestPackages, "test-package-append", []string{}, "extra packages to install for each of the test environments")
	fs.BoolVar(&flags.Remove, "rm", true, "clean up intermediate artifacts (e.g. container images, temp dirs)")
	fs.BoolVar(&flags.IgnoreSignatures, "ignore-signatures", false, "ignore repository signature verification")
	fs.StringVar(&flags.CPU, "cpu", "", "default CPU resources to use for tests")
	fs.StringVar(&flags.CPUModel, "cpumodel", "", "default CPU model to use for tests")
	fs.StringVar(&flags.Disk, "disk", "", "disk size to use for tests")
	fs.StringVar(&flags.Memory, "memory", "", "default memory resources to use for tests")
	fs.DurationVar(&flags.Timeout, "timeout", 0, "default timeout for tests")
}

// TestFlags holds all parsed test command flags
type TestFlags struct {
	WorkspaceDir      string
	SourceDir         string
	CacheDir          string
	CacheSource       string
	ApkCacheDir       string
	Archstrs          []string
	PipelineDirs      []string
	ExtraKeys         []string
	ExtraRepos        []string
	EnvFile           string
	TestOption        []string
	Debug             bool
	DebugRunner       bool
	Interactive       bool
	Runner            string
	ExtraTestPackages []string
	Remove            bool
	IgnoreSignatures  bool
	CPU               string
	CPUModel          string
	Memory            string
	Disk              string
	Timeout           time.Duration
}

// ParseTestFlags parses test flags from the provided args and returns a TestFlags struct
func ParseTestFlags(args []string) (*TestFlags, []string, error) {
	flags := &TestFlags{}

	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	addTestFlags(fs, flags)

	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}

	return flags, fs.Args(), nil
}

// TestOptions converts TestFlags into a slice of build.TestOption
// This includes all core test options that are directly derived from the flags.
func (flags *TestFlags) TestOptions(ctx context.Context, args ...string) ([]build.TestOption, error) {
	r, err := getRunner(ctx, flags.Runner, flags.Remove)
	if err != nil {
		return nil, err
	}

	options := []build.TestOption{
		build.WithTestWorkspaceDir(flags.WorkspaceDir),
		build.WithTestCacheDir(flags.CacheDir),
		build.WithTestCacheSource(flags.CacheSource),
		build.WithTestPackageCacheDir(flags.ApkCacheDir),
		build.WithTestExtraKeys(flags.ExtraKeys),
		build.WithTestExtraRepos(flags.ExtraRepos),
		build.WithExtraTestPackages(flags.ExtraTestPackages),
		build.WithTestRunner(r),
		build.WithTestEnvFile(flags.EnvFile),
		build.WithTestDebug(flags.Debug),
		build.WithTestDebugRunner(flags.DebugRunner),
		build.WithTestInteractive(flags.Interactive),
		build.WithTestRemove(flags.Remove),
		build.WithTestIgnoreSignatures(flags.IgnoreSignatures),
		build.WithTestCPU(flags.CPU),
		build.WithTestCPUModel(flags.CPUModel),
		build.WithTestMemory(flags.Memory),
		build.WithTestDisk(flags.Disk),
		build.WithTestTimeout(flags.Timeout),
	}

	if len(args) > 0 {
		options = append(options, build.WithTestConfig(args[0]))
	}
	if len(args) > 1 {
		options = append(options, build.WithTestPackage(args[1]))
	}

	if flags.SourceDir != "" {
		options = append(options, build.WithTestSourceDir(flags.SourceDir))
	}

	for i := range flags.PipelineDirs {
		options = append(options, build.WithTestPipelineDir(flags.PipelineDirs[i]))
	}
	options = append(options, build.WithTestPipelineDir(BuiltinPipelineDir))

	if auth, ok := os.LookupEnv("HTTP_AUTH"); !ok {
		// Fine, no auth.
	} else if parts := strings.SplitN(auth, ":", 4); len(parts) != 4 {
		return nil, fmt.Errorf("HTTP_AUTH must be in the form 'basic:REALM:USERNAME:PASSWORD' (got %d parts)", len(parts))
	} else if parts[0] != "basic" {
		return nil, fmt.Errorf("HTTP_AUTH must be in the form 'basic:REALM:USERNAME:PASSWORD' (got %q for first part)", parts[0])
	} else {
		domain, user, pass := parts[1], parts[2], parts[3]
		options = append(options, build.WithTestAuth(domain, user, pass))
	}

	return options, nil
}

func test() *cobra.Command {
	// Create TestFlags struct (defaults are set in addTestFlags)
	flags := &TestFlags{}

	cmd := &cobra.Command{
		Use:     "test",
		Short:   "Test a package with a YAML configuration file",
		Long:    `Test a package from a YAML configuration file containing a test pipeline.`,
		Example: `  melange test <test.yaml> [package-name]`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			archs := apko_types.ParseArchitectures(flags.Archstrs)
			options, err := flags.TestOptions(ctx, args...)
			if err != nil {
				return fmt.Errorf("getting test options from flags: %w", err)
			}

			return TestCmd(cmd.Context(), archs, options...)
		},
	}

	// Register all flags using the helper function
	addTestFlags(cmd.Flags(), flags)

	return cmd
}

func TestCmd(ctx context.Context, archs []apko_types.Architecture, baseOpts ...build.TestOption) error {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "TestCmd")
	defer span.End()

	if len(archs) == 0 {
		archs = apko_types.AllArchs
	}

	// Set up the test contexts before running them.  This avoids various
	// race conditions and the possibility that a context may be garbage
	// collected before it is actually run.
	//
	// Yes, this happens.  Really.
	// https://github.com/distroless/nginx/runs/7219233843?check_suite_focus=true
	bcs := []*build.Test{}
	for _, arch := range archs {
		opts := []build.TestOption{build.WithTestArch(arch)}
		opts = append(opts, baseOpts...)

		bc, err := build.NewTest(ctx, opts...)
		if errors.Is(err, build.ErrSkipThisArch) {
			log.Infof("skipping arch %s", arch)
			continue
		} else if err != nil {
			return err
		}
		defer bc.Close()

		bcs = append(bcs, bc)
	}

	if len(bcs) == 0 {
		log.Warnf("target-architecture and --arch do not overlap, nothing to test")
		return nil
	}

	var errg errgroup.Group

	if bcs[0].Interactive {
		// Concurrent interactive debugging will break your terminal.
		errg.SetLimit(1)
	}

	for _, bc := range bcs {
		errg.Go(func() error {
			if err := bc.TestPackage(ctx); err != nil {
				log.Errorf("ERROR: failed to test package. the test environment has been preserved:")
				bc.SummarizePaths(ctx)

				return fmt.Errorf("failed to test package: %w", err)
			}
			return nil
		})
	}
	return errg.Wait()
}
