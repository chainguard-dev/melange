// Copyright 2022 Chainguard, Inc.
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
	"log/slog"
	"path/filepath"
	"runtime"
	"time"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/container"
	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"
)

const BuiltinPipelineDir = "/usr/share/melange/pipelines"

func Build() *cobra.Command {
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
	var interactive bool
	var remove bool
	var runner string
	var failOnLintWarning bool
	var cpu, memory string
	var timeout time.Duration

	cmd := &cobra.Command{
		Use:     "build",
		Short:   "Build a package from a YAML configuration file",
		Long:    `Build a package from a YAML configuration file.`,
		Example: `  melange build [config.yaml]`,
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			r, err := getRunner(ctx, runner)
			if err != nil {
				return err
			}

			archs := apko_types.ParseArchitectures(archstrs)
			options := []build.Option{
				build.WithBuildDate(buildDate),
				build.WithWorkspaceDir(workspaceDir),
				// Order matters, so add any specified pipelineDir before
				// builtin pipelines.
				build.WithPipelineDir(pipelineDir),
				build.WithPipelineDir(BuiltinPipelineDir),
				build.WithCacheDir(cacheDir),
				build.WithCacheSource(cacheSource),
				build.WithPackageCacheDir(apkCacheDir),
				build.WithGuestDir(guestDir),
				build.WithSigningKey(signingKey),
				build.WithGenerateIndex(generateIndex),
				build.WithEmptyWorkspace(emptyWorkspace),
				build.WithOutDir(outDir),
				build.WithExtraKeys(extraKeys),
				build.WithExtraRepos(extraRepos),
				build.WithDependencyLog(dependencyLog),
				build.WithBinShOverlay(overlayBinSh),
				build.WithBreakpointLabel(breakpointLabel),
				build.WithContinueLabel(continueLabel),
				build.WithStripOriginName(stripOriginName),
				build.WithEnvFile(envFile),
				build.WithVarsFile(varsFile),
				build.WithNamespace(purlNamespace),
				build.WithEnabledBuildOptions(buildOption),
				build.WithCreateBuildLog(createBuildLog),
				build.WithDebug(debug),
				build.WithDebugRunner(debugRunner),
				build.WithInteractive(interactive),
				build.WithRemove(remove),
				build.WithLogPolicy(logPolicy),
				build.WithRunner(r),
				build.WithFailOnLintWarning(failOnLintWarning),
				build.WithCPU(cpu),
				build.WithMemory(memory),
				build.WithTimeout(timeout),
			}

			if len(args) > 0 {
				options = append(options, build.WithConfig(args[0]))

				if sourceDir == "" {
					sourceDir = filepath.Dir(args[0])
				}
			}

			if sourceDir != "" {
				options = append(options, build.WithSourceDir(sourceDir))
			}

			return BuildCmd(cmd.Context(), archs, options...)
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
	cmd.Flags().StringVar(&runner, "runner", "", fmt.Sprintf("which runner to use to enable running commands, default is based on your platform. Options are %q", build.GetAllRunners()))
	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the build environment keyring")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include in the build environment")
	cmd.Flags().BoolVar(&createBuildLog, "create-build-log", false, "creates a package.log file containing a list of packages that were built by the command")
	cmd.Flags().BoolVar(&debug, "debug", false, "enables debug logging of build pipelines")
	cmd.Flags().BoolVar(&debugRunner, "debug-runner", false, "when enabled, the builder pod will persist after the build succeeds or fails")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "when enabled, attaches stdin with a tty to the pod on failure")
	cmd.Flags().BoolVar(&remove, "rm", false, "clean up intermediate artifacts (e.g. container images)")
	cmd.Flags().BoolVar(&failOnLintWarning, "fail-on-lint-warning", false, "turns linter warnings into failures")
	cmd.Flags().StringVar(&cpu, "cpu", "", "default CPU resources to use for builds")
	cmd.Flags().StringVar(&memory, "memory", "", "default memory resources to use for builds")
	cmd.Flags().DurationVar(&timeout, "timeout", 0, "default timeout for builds")

	return cmd
}

func getRunner(ctx context.Context, runner string) (container.Runner, error) {
	if runner != "" {
		switch runner {
		case "bubblewrap":
			return container.BubblewrapRunner(), nil
		case "docker":
			return container.DockerRunner(ctx)
		case "kubernetes":
			return container.KubernetesRunner(ctx)
		default:
			return nil, fmt.Errorf("unknown runner: %s", runner)
		}
	}

	switch runtime.GOOS {
	case "linux":
		return container.BubblewrapRunner(), nil
	case "darwin":
		// darwin is the same as default, but we want to keep it explicit
		fallthrough
	default:
		return container.DockerRunner(ctx)
	}
}

func BuildCmd(ctx context.Context, archs []apko_types.Architecture, baseOpts ...build.Option) error {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "BuildCmd")
	defer span.End()

	if len(archs) == 0 {
		archs = apko_types.AllArchs
	}

	// Set up the build contexts before running them.  This avoids various
	// race conditions and the possibility that a context may be garbage
	// collected before it is actually run.
	//
	// Yes, this happens.  Really.
	// https://github.com/distroless/nginx/runs/7219233843?check_suite_focus=true
	bcs := []*build.Build{}
	for _, arch := range archs {
		opts := append(baseOpts, build.WithArch(arch))

		bc, err := build.New(ctx, opts...)
		if errors.Is(err, build.ErrSkipThisArch) {
			log.Warnf("skipping arch %s", arch)
			continue
		} else if err != nil {
			return err
		}
		defer bc.Close(ctx)

		bcs = append(bcs, bc)
	}

	if len(bcs) == 0 {
		log.Warn("WARNING: target-architecture and --arch do not overlap, nothing to build")
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
			log := clog.New(slog.Default().Handler()).With("arch", bc.Arch.ToAPK())
			ctx := clog.WithLogger(ctx, log)

			if err := bc.BuildPackage(ctx); err != nil {
				if !bc.Remove {
					log.Error("ERROR: failed to build package. the build environment has been preserved:")
					bc.SummarizePaths(ctx)
				}

				return fmt.Errorf("failed to build package: %w", err)
			}
			return nil
		})
	}
	return errg.Wait()
}
