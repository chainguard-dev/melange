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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/container"
	"chainguard.dev/melange/pkg/container/docker"
	"chainguard.dev/melange/pkg/linter"
	"github.com/chainguard-dev/clog"
	"github.com/go-git/go-git/v5"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/trace"
	"golang.org/x/sync/errgroup"
)

const BuiltinPipelineDir = "/usr/share/melange/pipelines"

func buildCmd() *cobra.Command {
	var buildDate string
	var workspaceDir string
	var pipelineDir string
	var sourceDir string
	var cacheDir string
	var cacheSource string
	var apkCacheDir string
	var signingKey string
	var generateIndex bool
	var emptyWorkspace bool
	var stripOriginName bool
	var outDir string
	var archstrs []string
	var extraKeys []string
	var extraRepos []string
	var dependencyLog string
	var envFile string
	var varsFile string
	var purlNamespace string
	var buildOption []string
	var createBuildLog bool
	var debug bool
	var debugRunner bool
	var interactive bool
	var remove bool
	var runner string
	var cpu, cpumodel, memory, disk string
	var timeout time.Duration
	var extraPackages []string
	var libc string
	var lintRequire, lintWarn []string
	var ignoreSignatures bool
	var cleanup bool
	var configFileGitCommit string
	var configFileGitRepoURL string
	var configFileLicense string
	var generateProvenance bool

	var traceFile string

	cmd := &cobra.Command{
		Use:     "build",
		Short:   "Build a package from a YAML configuration file",
		Long:    `Build a package from a YAML configuration file.`,
		Example: `  melange build [config.yaml]`,
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			log := clog.FromContext(ctx)

			var buildConfigFilePath string
			if len(args) > 0 {
				buildConfigFilePath = args[0] // e.g. "crane.yaml"
			}

			if traceFile != "" {
				w, err := os.Create(traceFile)
				if err != nil {
					return fmt.Errorf("creating trace file: %w", err)
				}
				defer w.Close()
				exporter, err := stdouttrace.New(stdouttrace.WithWriter(w))
				if err != nil {
					return fmt.Errorf("creating stdout exporter: %w", err)
				}
				tp := trace.NewTracerProvider(trace.WithBatcher(exporter))
				otel.SetTracerProvider(tp)

				defer func() {
					if err := tp.Shutdown(context.WithoutCancel(ctx)); err != nil {
						log.Errorf("shutting down trace provider: %v", err)
					}
				}()

				tctx, span := otel.Tracer("melange").Start(ctx, "build")
				defer span.End()
				ctx = tctx
			}

			r, err := getRunner(ctx, runner, remove)
			if err != nil {
				return err
			}

			// Favor explicit, user-provided information for the git provenance of the
			// melange build definition. As a fallback, detect this from local git state.
			// Git auto-detection should be "best effort" and not fail the build if it
			// fails.
			if configFileGitCommit == "" {
				log.Debugf("git commit for build config not provided, attempting to detect automatically")
				commit, err := detectGitHead(ctx, buildConfigFilePath)
				if err != nil {
					log.Warnf("unable to detect commit for build config file: %v", err)
					configFileGitCommit = "unknown"
				} else {
					configFileGitCommit = commit
				}
			}
			if configFileGitRepoURL == "" {
				log.Warnf("git repository URL for build config not provided")
				configFileGitRepoURL = "https://unknown/unknown/unknown"
			}

			archs := apko_types.ParseArchitectures(archstrs)
			log.Infof("melange version %s with runner %s building %s at commit %s for arches %s", cmd.Version, r.Name(), buildConfigFilePath, configFileGitCommit, archs)
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
				build.WithSigningKey(signingKey),
				build.WithGenerateIndex(generateIndex),
				build.WithEmptyWorkspace(emptyWorkspace),
				build.WithOutDir(outDir),
				build.WithExtraKeys(extraKeys),
				build.WithExtraRepos(extraRepos),
				build.WithExtraPackages(extraPackages),
				build.WithDependencyLog(dependencyLog),
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
				build.WithRunner(r),
				build.WithLintRequire(lintRequire),
				build.WithLintWarn(lintWarn),
				build.WithCPU(cpu),
				build.WithCPUModel(cpumodel),
				build.WithDisk(disk),
				build.WithMemory(memory),
				build.WithTimeout(timeout),
				build.WithLibcFlavorOverride(libc),
				build.WithIgnoreSignatures(ignoreSignatures),
				build.WithConfigFileRepositoryCommit(configFileGitCommit),
				build.WithConfigFileRepositoryURL(configFileGitRepoURL),
				build.WithConfigFileLicense(configFileLicense),
				build.WithGenerateProvenance(generateProvenance),
			}

			if len(args) > 0 {
				options = append(options, build.WithConfig(buildConfigFilePath))

				if sourceDir == "" {
					sourceDir = filepath.Dir(buildConfigFilePath)
				}
			}

			if sourceDir != "" {
				options = append(options, build.WithSourceDir(sourceDir))
			}

			if auth, ok := os.LookupEnv("HTTP_AUTH"); !ok {
				// Fine, no auth.
			} else if parts := strings.SplitN(auth, ":", 4); len(parts) != 4 {
				return fmt.Errorf("HTTP_AUTH must be in the form 'basic:REALM:USERNAME:PASSWORD' (got %d parts)", len(parts))
			} else if parts[0] != "basic" {
				return fmt.Errorf("HTTP_AUTH must be in the form 'basic:REALM:USERNAME:PASSWORD' (got %q for first part)", parts[0])
			} else {
				domain, user, pass := parts[1], parts[2], parts[3]
				options = append(options, build.WithAuth(domain, user, pass))
			}

			return BuildCmd(ctx, archs, options...)
		},
	}

	cmd.Flags().StringVar(&buildDate, "build-date", "", "date used for the timestamps of the files inside the image")
	cmd.Flags().StringVar(&workspaceDir, "workspace-dir", "", "directory used for the workspace at /home/build")
	cmd.Flags().StringVar(&pipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	cmd.Flags().StringVar(&sourceDir, "source-dir", "", "directory used for included sources")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", "./melange-cache/", "directory used for cached inputs")
	cmd.Flags().StringVar(&cacheSource, "cache-source", "", "directory or bucket used for preloading the cache")
	cmd.Flags().StringVar(&apkCacheDir, "apk-cache-dir", "", "directory used for cached apk packages (default is system-defined cache directory)")
	cmd.Flags().StringVar(&signingKey, "signing-key", "", "key to use for signing")
	cmd.Flags().StringVar(&envFile, "env-file", "", "file to use for preloaded environment variables")
	cmd.Flags().StringVar(&varsFile, "vars-file", "", "file to use for preloaded build configuration variables")
	cmd.Flags().BoolVar(&generateIndex, "generate-index", true, "whether to generate APKINDEX.tar.gz")
	cmd.Flags().BoolVar(&emptyWorkspace, "empty-workspace", false, "whether the build workspace should be empty")
	cmd.Flags().BoolVar(&stripOriginName, "strip-origin-name", false, "whether origin names should be stripped (for bootstrap)")
	cmd.Flags().StringVar(&outDir, "out-dir", "./packages/", "directory where packages will be output")
	cmd.Flags().StringVar(&dependencyLog, "dependency-log", "", "log dependencies to a specified file")
	cmd.Flags().StringVar(&purlNamespace, "namespace", "unknown", "namespace to use in package URLs in SBOM (eg wolfi, alpine)")
	cmd.Flags().StringSliceVar(&archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config")
	cmd.Flags().StringVar(&libc, "override-host-triplet-libc-substitution-flavor", "gnu", "override the flavor of libc for ${{host.triplet.*}} substitutions (e.g. gnu,musl) -- default is gnu")
	cmd.Flags().StringSliceVar(&buildOption, "build-option", []string{}, "build options to enable")
	cmd.Flags().StringVar(&runner, "runner", "", fmt.Sprintf("which runner to use to enable running commands, default is based on your platform. Options are %q", build.GetAllRunners()))
	cmd.Flags().StringSliceVarP(&extraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the build environment keyring")
	cmd.Flags().StringSliceVarP(&extraRepos, "repository-append", "r", []string{}, "path to extra repositories to include in the build environment")
	cmd.Flags().StringSliceVar(&extraPackages, "package-append", []string{}, "extra packages to install for each of the build environments")
	cmd.Flags().BoolVar(&createBuildLog, "create-build-log", false, "creates a package.log file containing a list of packages that were built by the command")
	cmd.Flags().BoolVar(&debug, "debug", false, "enables debug logging of build pipelines")
	cmd.Flags().BoolVar(&debugRunner, "debug-runner", false, "when enabled, the builder pod will persist after the build succeeds or fails")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "when enabled, attaches stdin with a tty to the pod on failure")
	cmd.Flags().BoolVar(&remove, "rm", true, "clean up intermediate artifacts (e.g. container images, temp dirs)")
	cmd.Flags().StringVar(&cpu, "cpu", "", "default CPU resources to use for builds")
	cmd.Flags().StringVar(&cpumodel, "cpumodel", "", "default memory resources to use for builds")
	cmd.Flags().StringVar(&disk, "disk", "", "disk size to use for builds")
	cmd.Flags().StringVar(&memory, "memory", "", "default memory resources to use for builds")
	cmd.Flags().DurationVar(&timeout, "timeout", 0, "default timeout for builds")
	cmd.Flags().StringVar(&traceFile, "trace", "", "where to write trace output")
	cmd.Flags().StringSliceVar(&lintRequire, "lint-require", linter.DefaultRequiredLinters(), "linters that must pass")
	cmd.Flags().StringSliceVar(&lintWarn, "lint-warn", linter.DefaultWarnLinters(), "linters that will generate warnings")
	cmd.Flags().BoolVar(&ignoreSignatures, "ignore-signatures", false, "ignore repository signature verification")
	cmd.Flags().BoolVar(&cleanup, "cleanup", true, "when enabled, the temp dir used for the guest will be cleaned up after completion")
	cmd.Flags().StringVar(&configFileGitCommit, "git-commit", "", "commit hash of the git repository containing the build config file (defaults to detecting HEAD)")
	cmd.Flags().StringVar(&configFileGitRepoURL, "git-repo-url", "", "URL of the git repository containing the build config file (defaults to detecting from configured git remotes)")
	cmd.Flags().StringVar(&configFileLicense, "license", "NOASSERTION", "license to use for the build config file itself")
	cmd.Flags().BoolVar(&generateProvenance, "generate-provenance", false, "generate SLSA provenance for builds (included in a separate .attest.tar.gz file next to the APK)")

	_ = cmd.Flags().Bool("fail-on-lint-warning", false, "DEPRECATED: DO NOT USE")
	_ = cmd.Flags().MarkDeprecated("fail-on-lint-warning", "use --lint-require and --lint-warn instead")

	return cmd
}

// Detect the git state from the build config file's parent directory.
func detectGitHead(ctx context.Context, buildConfigFilePath string) (string, error) {
	repoDir := filepath.Dir(buildConfigFilePath)
	clog.FromContext(ctx).Debugf("detecting git state from %q", repoDir)

	repo, err := git.PlainOpenWithOptions(repoDir, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return "", fmt.Errorf("opening git repository: %w", err)
	}

	head, err := repo.Head()
	if err != nil {
		return "", fmt.Errorf("determining HEAD: %w", err)
	}
	commit := head.Hash().String()
	return commit, nil
}

func getRunner(ctx context.Context, runner string, remove bool) (container.Runner, error) {
	if runner != "" {
		switch runner {
		case "bubblewrap":
			return container.BubblewrapRunner(remove), nil
		case "qemu":
			return container.QemuRunner(), nil
		case "docker":
			return docker.NewRunner(ctx)
		default:
			return nil, fmt.Errorf("unknown runner: %s", runner)
		}
	}

	switch runtime.GOOS {
	case "linux":
		return container.BubblewrapRunner(remove), nil
	case "darwin":
		// darwin is the same as default, but we want to keep it explicit
		fallthrough
	default:
		return docker.NewRunner(ctx)
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
		log.Warn("target-architecture and --arch do not overlap, nothing to build")
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
			lctx := ctx
			if len(bcs) != 1 {
				log := clog.New(slog.Default().Handler()).With("arch", bc.Arch.ToAPK())
				lctx = clog.WithLogger(ctx, log)
			}

			if err := bc.BuildPackage(lctx); err != nil {
				if !bc.Remove {
					log.Error("ERROR: failed to build package. the build environment has been preserved:")
					bc.SummarizePaths(lctx)
				}

				return fmt.Errorf("failed to build package: %w", err)
			}
			return nil
		})
	}
	return errg.Wait()
}
