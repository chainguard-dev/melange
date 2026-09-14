// Copyright 2024 Chainguard, Inc.
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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.opentelemetry.io/otel"

	"chainguard.dev/melange/pkg/build"
)

// CompileFlags holds all parsed compile command flags
type CompileFlags struct {
	CommonFlags

	// Compile-specific fields:
	Arch                 string // single string, required
	BuildDate            string
	PipelineDir          string
	SigningKey           string
	VarsFile             string
	GenerateIndex        bool
	EmptyWorkspace       bool
	StripOriginName      bool
	OutDir               string
	DependencyLog        string
	PurlNamespace        string
	BuildOption          []string
	LogPolicy            []string
	CreateBuildLog       bool
	FailOnLintWarning    bool
	GenerateProvenance   bool
	ConfigFileGitCommit  string
	ConfigFileGitRepoURL string
	ConfigFileLicense    string
}

// addCompileFlags registers all compile command flags to the provided FlagSet using the CompileFlags struct
func addCompileFlags(fs *pflag.FlagSet, flags *CompileFlags) {
	// Set compile-specific defaults before registering common flags.
	// Note: Remove (--rm) intentionally defaults to false for compile,
	// unlike build/test which default to true.
	flags.CacheDir = "./melange-cache/"
	addCommonFlags(fs, &flags.CommonFlags)

	// Compile-specific flags.
	fs.StringVar(&flags.Arch, "arch", "", "architectures to compile for")
	fs.StringVar(&flags.BuildDate, "build-date", "", "date used for the timestamps of the files inside the image")
	fs.StringVar(&flags.PipelineDir, "pipeline-dir", "", "directory used to extend defined built-in pipelines")
	fs.StringVar(&flags.SigningKey, "signing-key", "", "key to use for signing")
	fs.StringVar(&flags.VarsFile, "vars-file", "", "file to use for preloaded build configuration variables")
	fs.BoolVar(&flags.GenerateIndex, "generate-index", true, "whether to generate APKINDEX.tar.gz")
	fs.BoolVar(&flags.EmptyWorkspace, "empty-workspace", false, "whether the build workspace should be empty")
	fs.BoolVar(&flags.StripOriginName, "strip-origin-name", false, "whether origin names should be stripped (for bootstrap)")
	fs.StringVar(&flags.OutDir, "out-dir", "./packages/", "directory where packages will be output")
	fs.StringVar(&flags.DependencyLog, "dependency-log", "", "log dependencies to a specified file")
	fs.StringVar(&flags.PurlNamespace, "namespace", "unknown", "namespace to use in package URLs in SBOM (eg wolfi, alpine)")
	fs.StringSliceVar(&flags.BuildOption, "build-option", []string{}, "build options to enable")
	fs.StringSliceVar(&flags.LogPolicy, "log-policy", []string{"builtin:stderr"}, "logging policy to use")
	fs.BoolVar(&flags.CreateBuildLog, "create-build-log", false, "creates a package.log file containing a list of packages that were built by the command")
	fs.BoolVar(&flags.FailOnLintWarning, "fail-on-lint-warning", false, "turns linter warnings into failures")
	fs.BoolVar(&flags.GenerateProvenance, "generate-provenance", false, "generate SLSA provenance for builds (included in a separate .attest.tar.gz file next to the APK)")
	fs.StringVar(&flags.ConfigFileGitCommit, "git-commit", "", "commit hash of the git repository containing the build config file (defaults to detecting HEAD)")
	fs.StringVar(&flags.ConfigFileGitRepoURL, "git-repo-url", "", "URL of the git repository containing the build config file (defaults to detecting from configured git remotes)")
	fs.StringVar(&flags.ConfigFileLicense, "license", "NOASSERTION", "license to use for the build config file itself")
}

func compile() *cobra.Command {
	flags := &CompileFlags{}

	cmd := &cobra.Command{
		Use:     "compile",
		Short:   "Compile a YAML configuration file",
		Long:    `Compile a YAML configuration file.`,
		Example: `  melange compile [config.yaml]`,
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			log := clog.FromContext(ctx)

			if pc := ProjectConfigFromContext(ctx); pc != nil {
				pc.ApplyToCompileFlags(flags, cmd.Flags())
			}

			var buildConfigFilePath string
			if len(args) > 0 {
				buildConfigFilePath = args[0] // e.g. "crane.yaml"
			}

			// Favor explicit, user-provided information for the git provenance of the
			// melange build definition. As a fallback, detect this from local git state.
			// Git auto-detection should be "best effort" and not fail the build if it
			// fails.
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

			arch := apko_types.ParseArchitecture(flags.Arch)
			options := []build.Option{
				build.WithArch(arch),
				build.WithBuildDate(flags.BuildDate),
				build.WithWorkspaceDir(flags.WorkspaceDir),
				// Order matters, so add any specified pipelineDir before
				// builtin pipelines. Support both --pipeline-dir (singular)
				// and --pipeline-dirs (plural).
				build.WithPipelineDir(flags.PipelineDir),
				build.WithCacheDir(flags.CacheDir),
				build.WithCacheSource(flags.CacheSource),
				build.WithPackageCacheDir(flags.ApkCacheDir),
				build.WithSigningKey(flags.SigningKey),
				build.WithGenerateIndex(flags.GenerateIndex),
				build.WithEmptyWorkspace(flags.EmptyWorkspace),
				build.WithOutDir(flags.OutDir),
				build.WithExtraKeys(flags.ExtraKeys),
				build.WithExtraRepos(flags.ExtraRepos),
				build.WithExtraPackages(flags.ExtraPackages),
				build.WithDependencyLog(flags.DependencyLog),
				build.WithStripOriginName(flags.StripOriginName),
				build.WithEnvFiles(flags.EnvFiles),
				build.WithVarsFile(flags.VarsFile),
				build.WithNamespace(flags.PurlNamespace),
				build.WithEnabledBuildOptions(flags.BuildOption),
				build.WithCreateBuildLog(flags.CreateBuildLog),
				build.WithDebug(flags.Debug),
				build.WithDebugRunner(flags.DebugRunner),
				build.WithInteractive(flags.Interactive),
				build.WithRemove(flags.Remove),
				build.WithCPU(flags.CPU),
				build.WithCPUModel(flags.CPUModel),
				build.WithDisk(flags.Disk),
				build.WithMemory(flags.Memory),
				build.WithTimeout(flags.Timeout),
				build.WithIgnoreSignatures(flags.IgnoreSignatures),
				build.WithConfigFileRepositoryCommit(flags.ConfigFileGitCommit),
				build.WithConfigFileRepositoryURL(flags.ConfigFileGitRepoURL),
				build.WithConfigFileLicense(flags.ConfigFileLicense),
				build.WithGenerateProvenance(flags.GenerateProvenance),
			}

			if len(args) > 0 {
				options = append(options, build.WithConfig(args[0]))

				if flags.SourceDir == "" {
					flags.SourceDir = filepath.Dir(args[0])
				}
			}

			if flags.SourceDir != "" {
				options = append(options, build.WithSourceDir(flags.SourceDir))
			}

			// Add multiple pipeline directories from --pipeline-dirs
			for i := range flags.PipelineDirs {
				options = append(options, build.WithPipelineDir(flags.PipelineDirs[i]))
			}
			// Always append built-in pipeline directory as fallback
			options = append(options, build.WithPipelineDir(BuiltinPipelineDir))

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

			return CompileCmd(ctx, options...)
		},
	}

	addCompileFlags(cmd.Flags(), flags)

	if err := cmd.MarkFlagRequired("arch"); err != nil {
		panic(err)
	}

	return cmd
}

func CompileCmd(ctx context.Context, opts ...build.Option) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "CompileCmd")
	defer span.End()

	bc, err := build.New(ctx, opts...)
	if err != nil {
		return err
	}

	defer bc.Close(ctx)

	if err := bc.Compile(ctx); err != nil {
		return fmt.Errorf("failed to compile %s: %w", bc.ConfigFile, err)
	}

	return json.NewEncoder(os.Stdout).Encode(bc.Configuration)
}
