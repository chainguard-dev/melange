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
	"chainguard.dev/melange/pkg/build"
	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"
)

func test() *cobra.Command {
	var workspaceDir string
	var sourceDir string
	var cacheDir string
	var cacheSource string
	var apkCacheDir string
	var archstrs []string
	var pipelineDirs []string
	var extraKeys []string
	var extraRepos []string
	var envFile string
	var testOption []string
	var debug bool
	var debugRunner bool
	var interactive bool
	var runner string
	var extraTestPackages []string
	var remove bool
	var ignoreSignatures bool

	cmd := &cobra.Command{
		Use:     "test",
		Short:   "Test a package with a YAML configuration file",
		Long:    `Test a package from a YAML configuration file containing a test pipeline.`,
		Example: `  melange test <test.yaml> [package-name]`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			r, err := getRunner(ctx, runner, remove)
			if err != nil {
				return err
			}

			archs := apko_types.ParseArchitectures(archstrs)
			options := []build.TestOption{
				build.WithTestWorkspaceDir(workspaceDir),
				build.WithTestCacheDir(cacheDir),
				build.WithTestCacheSource(cacheSource),
				build.WithTestPackageCacheDir(apkCacheDir),
				build.WithTestExtraKeys(extraKeys),
				build.WithTestExtraRepos(extraRepos),
				build.WithExtraTestPackages(extraTestPackages),
				build.WithTestRunner(r),
				build.WithTestEnvFile(envFile),
				build.WithTestDebug(debug),
				build.WithTestDebugRunner(debugRunner),
				build.WithTestInteractive(interactive),
				build.WithTestRemove(remove),
				build.WithTestIgnoreSignatures(ignoreSignatures),
			}

			if len(args) > 0 {
				options = append(options, build.WithTestConfig(args[0]))
			}
			if len(args) > 1 {
				options = append(options, build.WithTestPackage(args[1]))
			}

			if sourceDir != "" {
				options = append(options, build.WithTestSourceDir(sourceDir))
			}

			for i := range pipelineDirs {
				options = append(options, build.WithTestPipelineDir(pipelineDirs[i]))
			}
			options = append(options, build.WithTestPipelineDir(BuiltinPipelineDir))

			if auth, ok := os.LookupEnv("HTTP_AUTH"); !ok {
				// Fine, no auth.
			} else if parts := strings.SplitN(auth, ":", 4); len(parts) != 4 {
				return fmt.Errorf("HTTP_AUTH must be in the form 'basic:REALM:USERNAME:PASSWORD' (got %d parts)", len(parts))
			} else if parts[0] != "basic" {
				return fmt.Errorf("HTTP_AUTH must be in the form 'basic:REALM:USERNAME:PASSWORD' (got %q for first part)", parts[0])
			} else {
				domain, user, pass := parts[1], parts[2], parts[3]
				options = append(options, build.WithTestAuth(domain, user, pass))
			}

			return TestCmd(cmd.Context(), archs, options...)
		},
	}

	cmd.Flags().StringVar(&workspaceDir, "workspace-dir", "", "directory used for the workspace at /home/build")
	cmd.Flags().StringSliceVar(&pipelineDirs, "pipeline-dirs", []string{}, "directories used to extend defined built-in pipelines")
	cmd.Flags().StringVar(&sourceDir, "source-dir", "", "directory used for included sources")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "", "directory used for cached inputs")
	cmd.Flags().StringVar(&cacheSource, "cache-source", "", "directory or bucket used for preloading the cache")
	cmd.Flags().StringVar(&apkCacheDir, "apk-cache-dir", "", "directory used for cached apk packages (default is system-defined cache directory)")
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config")
	cmd.Flags().StringSliceVar(&testOption, "test-option", []string{}, "build options to enable")
	cmd.Flags().StringVar(&runner, "runner", "", fmt.Sprintf("which runner to use to enable running commands, default is based on your platform. Options are %q", build.GetAllRunners()))
	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the build environment keyring")
	cmd.Flags().StringVar(&envFile, "env-file", "", "file to use for preloaded environment variables")
	cmd.Flags().BoolVar(&debug, "debug", false, "enables debug logging of test pipelines (sets -x for steps)")
	cmd.Flags().BoolVar(&debugRunner, "debug-runner", false, "when enabled, the builder pod will persist after the build succeeds or fails")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "when enabled, attaches stdin with a tty to the pod on failure")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include in the build environment")
	cmd.Flags().StringSliceVar(&extraTestPackages, "test-package-append", []string{}, "extra packages to install for each of the test environments")
	cmd.Flags().BoolVar(&remove, "rm", true, "clean up intermediate artifacts (e.g. container images, temp dirs)")
	cmd.Flags().BoolVar(&ignoreSignatures, "ignore-signatures", false, "ignore repository signature verification")

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
		bc := bc

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
