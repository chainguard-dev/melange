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
	"log"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"
)

func Test() *cobra.Command {
	var buildDate string
	var workspaceDir string
	var pipelineDir string
	var sourceDir string
	var cacheDir string
	var cacheSource string
	var apkCacheDir string
	var guestDir string
	var signingKey string
	var generateIndex bool
	var emptyWorkspace bool
	var stripOriginName bool
	var outDir string
	var archstrs []string
	var extraKeys []string
	var extraRepos []string
	var dependencyLog string
	var overlayBinSh string
	var breakpointLabel string
	var continueLabel string
	var envFile string
	var varsFile string
	var purlNamespace string
	var buildOption []string
	var logPolicy []string
	var createBuildLog bool
	var debug bool
	var debugRunner bool
	var runner string
	var failOnLintWarning bool

	cmd := &cobra.Command{
		Use:     "test",
		Short:   "Test a package with a YAML configuration file",
		Long:    `Test a package from a YAML configuration file containing a test pipeline.`,
		Example: `  melange test <config.yaml> <package-name>`,
		Args:    cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			archs := apko_types.ParseArchitectures(archstrs)
			options := []build.TestOption{
				build.WithTestWorkspaceDir(workspaceDir),
				build.WithTestPipelineDir(pipelineDir),
				build.WithTestCacheDir(cacheDir),
				build.WithTestCacheSource(cacheSource),
				build.WithTestPackageCacheDir(apkCacheDir),
				build.WithTestGuestDir(guestDir),
				build.WithTestEmptyWorkspace(emptyWorkspace),
				build.WithTestExtraKeys(extraKeys),
				build.WithTestExtraRepos(extraRepos),
				build.WithTestBinShOverlay(overlayBinSh),
				build.WithTestRunner(runner),
			}

			if len(args) > 0 {
				options = append(options, build.WithTestConfig(args[0]))
				options = append(options, build.WithTestPackage(args[1]))
			}

			if sourceDir != "" {
				options = append(options, build.WithTestSourceDir(sourceDir))
			}

			return TestCmd(cmd.Context(), archs, options...)
		},
	}

	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image")
	cmd.Flags().StringVar(&workspaceDir, "workspace-dir", "", "directory used for the workspace at /home/build")
	cmd.Flags().StringVar(&pipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	cmd.Flags().StringVar(&sourceDir, "source-dir", "", "directory used for included sources")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "./melange-cache/", "directory used for cached inputs")
	cmd.Flags().StringVar(&cacheSource, "cache-source", "", "directory or bucket used for preloading the cache")
	cmd.Flags().StringVar(&apkCacheDir, "apk-cache-dir", "", "directory used for cached apk packages (default is system-defined cache directory)")
	cmd.Flags().StringVar(&guestDir, "guest-dir", "", "directory used for the build environment guest")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "key to use for signing")
	cmd.Flags().StringVar(&envFile, "env-file", "", "file to use for preloaded environment variables")
	cmd.Flags().StringVar(&varsFile, "vars-file", "", "file to use for preloaded build configuration variables")
	cmd.Flags().BoolVar(&generateIndex, "generate-index", true, "whether to generate APKINDEX.tar.gz")
	cmd.Flags().BoolVar(&emptyWorkspace, "empty-workspace", false, "whether the build workspace should be empty")
	cmd.Flags().BoolVar(&stripOriginName, "strip-origin-name", false, "whether origin names should be stripped (for bootstrap)")
	cmd.Flags().StringVar(&outDir, "out-dir", "./packages/", "directory where packages will be output")
	cmd.Flags().StringVar(&dependencyLog, "dependency-log", "", "log dependencies to a specified file")
	cmd.Flags().StringVar(&overlayBinSh, "overlay-binsh", "", "use specified file as /bin/sh overlay in build environment")
	cmd.Flags().StringVar(&breakpointLabel, "breakpoint-label", "", "stop build execution at the specified label")
	cmd.Flags().StringVar(&continueLabel, "continue-label", "", "continue build execution at the specified label")
	cmd.Flags().StringVar(&purlNamespace, "namespace", "unknown", "namespace to use in package URLs in SBOM (eg wolfi, alpine)")
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config")
	cmd.Flags().StringSliceVar(&buildOption, "build-option", []string{}, "build options to enable")
	cmd.Flags().StringSliceVar(&logPolicy, "log-policy", []string{"builtin:stderr"}, "logging policy to use")
	cmd.Flags().StringVar(&runner, "runner", string(build.GetDefaultRunner()), fmt.Sprintf("which runner to use to enable running commands, default is based on your platform. Options are %q", build.GetAllRunners()))
	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the build environment keyring")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include in the build environment")
	cmd.Flags().BoolVar(&createBuildLog, "create-build-log", false, "creates a package.log file containing a list of packages that were built by the command")
	cmd.Flags().BoolVar(&debug, "debug", false, "enables debug logging of build pipelines")
	cmd.Flags().BoolVar(&debugRunner, "debug-runner", false, "when enabled, the builder pod will persist after the build succeeds or fails")
	cmd.Flags().BoolVar(&failOnLintWarning, "fail-on-lint-warning", false, "turns linter warnings into failures")

	return cmd
}

func TestCmd(ctx context.Context, archs []apko_types.Architecture, baseOpts ...build.TestOption) error {
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
		opts := append(baseOpts, build.WithTestArch(arch), build.WithTestBuiltinPipelineDirectory(BuiltinPipelineDir))

		bc, err := build.NewTest(ctx, opts...)
		if errors.Is(err, build.ErrSkipThisArch) {
			log.Printf("skipping arch %s", arch)
			continue
		} else if err != nil {
			return err
		}

		bcs = append(bcs, bc)
	}

	if len(bcs) == 0 {
		log.Printf("WARNING: target-architecture and --arch do not overlap, nothing to build")
		return nil
	}

	var errg errgroup.Group
	for _, bc := range bcs {
		bc := bc

		errg.Go(func() error {
			if err := bc.TestPackage(ctx); err != nil {
				log.Printf("ERROR: failed to test package. the test environment has been preserved:")
				bc.SummarizePaths()

				return fmt.Errorf("failed to build package: %w", err)
			}
			return nil
		})
	}
	return errg.Wait()
}
