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
	// Set test-specific defaults before registering common flags.
	flags.Remove = true
	addCommonFlags(fs, &flags.CommonFlags)

	// Test-specific flags.
	fs.StringSliceVar(&flags.Archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config")
	fs.StringSliceVar(&flags.TestOption, "test-option", []string{}, "build options to enable")
	fs.StringSliceVar(&flags.ExtraTestPackages, "test-package-append", []string{}, "extra packages to install for each of the test environments")
}

// TestFlags holds all parsed test command flags
type TestFlags struct {
	CommonFlags

	Archstrs          []string
	TestOption        []string
	ExtraTestPackages []string
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
		build.WithTestEnvFiles(flags.EnvFiles),
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

			if pc := ProjectConfigFromContext(ctx); pc != nil {
				pc.ApplyToTestFlags(flags, cmd.Flags())
			}

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
		opts := make([]build.TestOption, 0, len(baseOpts)+1)
		opts = append(opts, build.WithTestArch(arch))
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
