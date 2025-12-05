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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
	"github.com/go-git/go-git/v5"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/trace"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/container"
	"chainguard.dev/melange/pkg/container/docker"
	"chainguard.dev/melange/pkg/linter"
)

const BuiltinPipelineDir = "/usr/share/melange/pipelines"

// addBuildFlags registers all build command flags to the provided FlagSet using the BuildFlags struct
func addBuildFlags(fs *pflag.FlagSet, flags *BuildFlags) {
	fs.StringVar(&flags.BuildDate, "build-date", "", "date used for the timestamps of the files inside the image")
	fs.StringVar(&flags.WorkspaceDir, "workspace-dir", "", "directory used for the workspace at /home/build")
	fs.StringVar(&flags.PipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	fs.StringVar(&flags.SourceDir, "source-dir", "", "directory used for included sources")
	fs.StringVar(&flags.CacheDir, "cache-dir", "./melange-cache/", "directory used for cached inputs")
	fs.StringVar(&flags.CacheSource, "cache-source", "", "directory or bucket used for preloading the cache")
	fs.StringVar(&flags.ApkCacheDir, "apk-cache-dir", "", "directory used for cached apk packages (default is system-defined cache directory)")
	fs.StringVar(&flags.SigningKey, "signing-key", "", "key to use for signing")
	fs.StringVar(&flags.EnvFile, "env-file", "", "file to use for preloaded environment variables")
	fs.StringVar(&flags.VarsFile, "vars-file", "", "file to use for preloaded build configuration variables")
	fs.BoolVar(&flags.GenerateIndex, "generate-index", true, "whether to generate APKINDEX.tar.gz")
	fs.BoolVar(&flags.EmptyWorkspace, "empty-workspace", false, "whether the build workspace should be empty")
	fs.BoolVar(&flags.StripOriginName, "strip-origin-name", false, "whether origin names should be stripped (for bootstrap)")
	fs.StringVar(&flags.OutDir, "out-dir", "./packages/", "directory where packages will be output")
	fs.StringVar(&flags.DependencyLog, "dependency-log", "", "log dependencies to a specified file")
	fs.StringVar(&flags.PurlNamespace, "namespace", "unknown", "namespace to use in package URLs in SBOM (eg wolfi, alpine)")
	fs.StringSliceVar(&flags.Archstrs, "arch", nil, "architectures to build for (e.g., x86_64,ppc64le,arm64) -- default is all, unless specified in config")
	fs.StringVar(&flags.Libc, "override-host-triplet-libc-substitution-flavor", "gnu", "override the flavor of libc for ${{host.triplet.*}} substitutions (e.g. gnu,musl) -- default is gnu")
	fs.StringSliceVar(&flags.BuildOption, "build-option", []string{}, "build options to enable")
	fs.StringVar(&flags.Runner, "runner", "", fmt.Sprintf("which runner to use to enable running commands, default is based on your platform. Options are %q", build.GetAllRunners()))
	fs.StringSliceVarP(&flags.ExtraKeys, "keyring-append", "k", []string{}, "path to extra keys to include in the build environment keyring")
	fs.StringSliceVarP(&flags.ExtraRepos, "repository-append", "r", []string{}, "path to extra repositories to include in the build environment")
	fs.StringSliceVar(&flags.ExtraPackages, "package-append", []string{}, "extra packages to install for each of the build environments")
	fs.BoolVar(&flags.CreateBuildLog, "create-build-log", false, "creates a package.log file containing a list of packages that were built by the command")
	fs.BoolVar(&flags.PersistLintResults, "persist-lint-results", false, "persist lint results to JSON files in packages/{arch}/ directory")
	fs.BoolVar(&flags.Debug, "debug", false, "enables debug logging of build pipelines")
	fs.BoolVar(&flags.DebugRunner, "debug-runner", false, "when enabled, the builder pod will persist after the build succeeds or fails")
	fs.BoolVarP(&flags.Interactive, "interactive", "i", false, "when enabled, attaches stdin with a tty to the pod on failure")
	fs.BoolVar(&flags.Remove, "rm", true, "clean up intermediate artifacts (e.g. container images, temp dirs)")
	fs.StringVar(&flags.CPU, "cpu", "", "default CPU resources to use for builds")
	fs.StringVar(&flags.CPUModel, "cpumodel", "", "default memory resources to use for builds")
	fs.StringVar(&flags.Disk, "disk", "", "disk size to use for builds")
	fs.StringVar(&flags.Memory, "memory", "", "default memory resources to use for builds")
	fs.DurationVar(&flags.Timeout, "timeout", 0, "default timeout for builds")
	fs.StringVar(&flags.TraceFile, "trace", "", "where to write trace output")
	fs.StringSliceVar(&flags.LintRequire, "lint-require", linter.DefaultRequiredLinters(), "linters that must pass")
	fs.StringSliceVar(&flags.LintWarn, "lint-warn", linter.DefaultWarnLinters(), "linters that will generate warnings")
	fs.BoolVar(&flags.IgnoreSignatures, "ignore-signatures", false, "ignore repository signature verification")
	fs.BoolVar(&flags.Cleanup, "cleanup", true, "when enabled, the temp dir used for the guest will be cleaned up after completion")
	fs.StringVar(&flags.ConfigFileGitCommit, "git-commit", "", "commit hash of the git repository containing the build config file (defaults to detecting HEAD)")
	fs.StringVar(&flags.ConfigFileGitRepoURL, "git-repo-url", "", "URL of the git repository containing the build config file (defaults to detecting from configured git remotes)")
	fs.StringVar(&flags.ConfigFileLicense, "license", "NOASSERTION", "license to use for the build config file itself")
	fs.BoolVar(&flags.GenerateProvenance, "generate-provenance", false, "generate SLSA provenance for builds (included in a separate .attest.tar.gz file next to the APK)")

	_ = fs.Bool("fail-on-lint-warning", false, "DEPRECATED: DO NOT USE")
	_ = fs.MarkDeprecated("fail-on-lint-warning", "use --lint-require and --lint-warn instead")
}

// BuildFlags holds all parsed build command flags
type BuildFlags struct {
	BuildDate            string
	WorkspaceDir         string
	PipelineDir          string
	SourceDir            string
	CacheDir             string
	CacheSource          string
	ApkCacheDir          string
	SigningKey           string
	GenerateIndex        bool
	EmptyWorkspace       bool
	StripOriginName      bool
	OutDir               string
	Archstrs             []string
	ExtraKeys            []string
	ExtraRepos           []string
	DependencyLog        string
	EnvFile              string
	VarsFile             string
	PurlNamespace        string
	BuildOption          []string
	CreateBuildLog       bool
	PersistLintResults   bool
	Debug                bool
	DebugRunner          bool
	Interactive          bool
	Remove               bool
	Runner               string
	CPU                  string
	CPUModel             string
	Memory               string
	Disk                 string
	Timeout              time.Duration
	ExtraPackages        []string
	Libc                 string
	LintRequire          []string
	LintWarn             []string
	IgnoreSignatures     bool
	Cleanup              bool
	ConfigFileGitCommit  string
	ConfigFileGitRepoURL string
	ConfigFileLicense    string
	GenerateProvenance   bool
	TraceFile            string
}

// ParseBuildFlags parses build flags from the provided args and returns a BuildFlags struct
func ParseBuildFlags(args []string) (*BuildFlags, []string, error) {
	flags := &BuildFlags{}

	fs := pflag.NewFlagSet("build", pflag.ContinueOnError)
	addBuildFlags(fs, flags)

	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}

	return flags, fs.Args(), nil
}

// BuildOptions converts BuildFlags into a slice of build.Option
// This includes all core build options that are directly derived from the flags.
func (flags *BuildFlags) BuildOptions(ctx context.Context, args ...string) ([]build.Option, error) {
	log := clog.FromContext(ctx)

	// Determine the runner to use
	runner, err := getRunner(context.Background(), flags.Runner, flags.Remove)
	if err != nil {
		return nil, fmt.Errorf("failed to get runner: %w", err)
	}

	// Favor explicit, user-provided information for the git provenance of the
	// melange build definition. As a fallback, detect this from local git state.
	// Git auto-detection should be "best effort" and not fail the build if it
	// fails.
	var buildConfigFilePath string
	if len(args) > 0 {
		buildConfigFilePath = args[0] // e.g. "crane.yaml"
	}
	if flags.ConfigFileGitCommit == "" {
		log.Debugf("git commit for build config not provided, attempting to detect automatically")
		commit, err := detectGitHead(ctx, buildConfigFilePath)
		if err != nil {
			log.Warnf("unable to detect commit for build config file: %v", err)
			flags.ConfigFileGitCommit = "unknown"
		} else {
			flags.ConfigFileGitCommit = commit
		}
	}
	if flags.ConfigFileGitRepoURL == "" {
		log.Warnf("git repository URL for build config not provided")
		flags.ConfigFileGitRepoURL = "https://unknown/unknown/unknown"
	}

	opts := []build.Option{
		build.WithBuildDate(flags.BuildDate),
		build.WithWorkspaceDir(flags.WorkspaceDir),
		// Order matters, so add any specified pipelineDir before
		// builtin pipelines.
		build.WithPipelineDir(flags.PipelineDir),
		build.WithPipelineDir(BuiltinPipelineDir),
		build.WithCacheDir(flags.CacheDir),
		build.WithCacheSource(flags.CacheSource),
		build.WithPackageCacheDir(flags.ApkCacheDir),
		build.WithRunner(runner),
		build.WithSigningKey(flags.SigningKey),
		build.WithGenerateIndex(flags.GenerateIndex),
		build.WithEmptyWorkspace(flags.EmptyWorkspace),
		build.WithOutDir(flags.OutDir),
		build.WithExtraKeys(flags.ExtraKeys),
		build.WithExtraRepos(flags.ExtraRepos),
		build.WithExtraPackages(flags.ExtraPackages),
		build.WithDependencyLog(flags.DependencyLog),
		build.WithStripOriginName(flags.StripOriginName),
		build.WithEnvFile(flags.EnvFile),
		build.WithVarsFile(flags.VarsFile),
		build.WithNamespace(flags.PurlNamespace),
		build.WithEnabledBuildOptions(flags.BuildOption),
		build.WithCreateBuildLog(flags.CreateBuildLog),
		build.WithPersistLintResults(flags.PersistLintResults),
		build.WithDebug(flags.Debug),
		build.WithDebugRunner(flags.DebugRunner),
		build.WithInteractive(flags.Interactive),
		build.WithRemove(flags.Remove),
		build.WithLintRequire(flags.LintRequire),
		build.WithLintWarn(flags.LintWarn),
		build.WithCPU(flags.CPU),
		build.WithCPUModel(flags.CPUModel),
		build.WithDisk(flags.Disk),
		build.WithMemory(flags.Memory),
		build.WithTimeout(flags.Timeout),
		build.WithLibcFlavorOverride(flags.Libc),
		build.WithIgnoreSignatures(flags.IgnoreSignatures),
		build.WithConfigFileRepositoryCommit(flags.ConfigFileGitCommit),
		build.WithConfigFileRepositoryURL(flags.ConfigFileGitRepoURL),
		build.WithConfigFileLicense(flags.ConfigFileLicense),
		build.WithGenerateProvenance(flags.GenerateProvenance),
	}

	if len(args) > 0 {
		opts = append(opts, build.WithConfig(buildConfigFilePath))

		if flags.SourceDir == "" {
			flags.SourceDir = filepath.Dir(buildConfigFilePath)
		}
	}

	if flags.SourceDir != "" {
		opts = append(opts, build.WithSourceDir(flags.SourceDir))
	}

	if auth, ok := os.LookupEnv("HTTP_AUTH"); !ok {
		// Fine, no auth.
	} else if parts := strings.SplitN(auth, ":", 4); len(parts) != 4 {
		return nil, fmt.Errorf("HTTP_AUTH must be in the form 'basic:REALM:USERNAME:PASSWORD' (got %d parts)", len(parts))
	} else if parts[0] != "basic" {
		return nil, fmt.Errorf("HTTP_AUTH must be in the form 'basic:REALM:USERNAME:PASSWORD' (got %q for first part)", parts[0])
	} else {
		domain, user, pass := parts[1], parts[2], parts[3]
		opts = append(opts, build.WithAuth(domain, user, pass))
	}

	return opts, nil
}

func buildCmd() *cobra.Command {
	// Create BuildFlags struct (defaults are set in addBuildFlags)
	flags := &BuildFlags{}

	cmd := &cobra.Command{
		Use:     "build",
		Short:   "Build a package from a YAML configuration file",
		Long:    `Build a package from a YAML configuration file.`,
		Example: `  melange build [config.yaml]`,
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			log := clog.FromContext(ctx)

			if flags.TraceFile != "" {
				w, err := os.Create(flags.TraceFile) // #nosec G304 - User-specified trace file output
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

			archs := apko_types.ParseArchitectures(flags.Archstrs)
			log.Infof("melange version %s with runner %s building %s at commit %s for arches %s", cmd.Version, flags.Runner, args, flags.ConfigFileGitCommit, archs)
			options, err := flags.BuildOptions(ctx, args...)
			if err != nil {
				return fmt.Errorf("getting build options from flags: %w", err)
			}

			return BuildCmd(ctx, archs, options...)
		},
	}

	// Register all flags using the helper function
	addBuildFlags(cmd.Flags(), flags)

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
		opts := append([]build.Option{}, baseOpts...)
		opts = append(opts, build.WithArch(arch))

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
		errg.Go(func() error {
			lctx := ctx
			if len(bcs) != 1 {
				alog := log.With("arch", bc.Arch.ToAPK())
				lctx = clog.WithLogger(ctx, alog)
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
