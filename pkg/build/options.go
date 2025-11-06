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

package build

import (
	"fmt"
	"os"
	"time"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"

	"chainguard.dev/melange/pkg/build/sbom"
	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/container"
)

type Option func(*Build) error

// WithConfig sets the configuration file used for the package build context.
func WithConfig(configFile string) Option {
	return func(b *Build) error {
		b.ConfigFile = configFile
		return nil
	}
}

// WithConfiguration sets the configuration used for the package build context, and the filename that should be reported for that.
func WithConfiguration(config *config.Configuration, filename string) Option {
	return func(b *Build) error {
		b.ConfigFile = filename
		b.Configuration = config
		return nil
	}
}

func WithConfigFileRepositoryURL(u string) Option {
	return func(b *Build) error {
		b.ConfigFileRepositoryURL = u
		return nil
	}
}

func WithConfigFileRepositoryCommit(hash string) Option {
	return func(b *Build) error {
		b.ConfigFileRepositoryCommit = hash
		return nil
	}
}

func WithConfigFileLicense(license string) Option {
	return func(b *Build) error {
		b.ConfigFileLicense = license
		return nil
	}
}

// WithLintRequire sets required linter checks.
func WithLintRequire(linters []string) Option {
	return func(b *Build) error {
		b.LintRequire = linters
		return nil
	}
}

// WithLintWarn sets non-required linter checks.
func WithLintWarn(linters []string) Option {
	return func(b *Build) error {
		b.LintWarn = linters
		return nil
	}
}

// WithBuildDate sets the timestamps for the build context.
// The string is parsed according to RFC3339.
// An empty string is a special case and will default to
// the unix epoch.
func WithBuildDate(s string) Option {
	return func(bc *Build) error {
		// default to 0 for reproducibility
		if s == "" {
			bc.SourceDateEpoch = time.Unix(0, 0)
			return nil
		}

		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return err
		}

		bc.SourceDateEpoch = t
		return nil
	}
}

// WithWorkspaceDir sets the workspace directory to use.
func WithWorkspaceDir(workspaceDir string) Option {
	return func(b *Build) error {
		b.WorkspaceDir = workspaceDir
		return nil
	}
}

// WithWorkspaceIgnore sets the workspace ignore rules file to use.
func WithWorkspaceIgnore(workspaceIgnore string) Option {
	return func(b *Build) error {
		b.WorkspaceIgnore = workspaceIgnore
		return nil
	}
}

// WithEmptyWorkspace sets whether the workspace should be empty.
func WithEmptyWorkspace(emptyWorkspace bool) Option {
	return func(b *Build) error {
		b.EmptyWorkspace = emptyWorkspace
		return nil
	}
}

// WithPipelineDir sets the pipeline directory to extend the built-in pipeline
// directory. These are searched in order, so the first one found is used.
func WithPipelineDir(pipelineDir string) Option {
	return func(b *Build) error {
		if pipelineDir != "" {
			b.PipelineDirs = append(b.PipelineDirs, pipelineDir)
		}
		return nil
	}
}

// WithSourceDir sets the source directory to use.
func WithSourceDir(sourceDir string) Option {
	return func(b *Build) error {
		b.SourceDir = sourceDir
		return nil
	}
}

// WithCacheDir sets the cache directory to use.
func WithCacheDir(cacheDir string) Option {
	return func(b *Build) error {
		b.CacheDir = cacheDir
		return nil
	}
}

// WithCacheSource sets the cache source directory to use.  The cache will be
// pre-populated from this source directory.
func WithCacheSource(sourceDir string) Option {
	return func(b *Build) error {
		b.CacheSource = sourceDir
		return nil
	}
}

// WithSigningKey sets the signing key path to use.
func WithSigningKey(signingKey string) Option {
	return func(b *Build) error {
		if signingKey != "" {
			if _, err := os.Stat(signingKey); err != nil {
				return fmt.Errorf("could not open signing key: %w", err)
			}
		}

		b.SigningKey = signingKey
		return nil
	}
}

// WithGenerateIndex sets whether or not the apk index should be generated.
func WithGenerateIndex(generateIndex bool) Option {
	return func(b *Build) error {
		b.GenerateIndex = generateIndex
		return nil
	}
}

// WithOutDir sets the output directory to use for the packages.
func WithOutDir(outDir string) Option {
	return func(b *Build) error {
		b.OutDir = outDir
		return nil
	}
}

// WithArch sets the build architecture to use for this build context.
func WithArch(arch apko_types.Architecture) Option {
	return func(b *Build) error {
		b.Arch = arch
		return nil
	}
}

// WithExtraKeys adds a set of extra keys to the build context.
func WithExtraKeys(extraKeys []string) Option {
	return func(b *Build) error {
		b.ExtraKeys = extraKeys
		return nil
	}
}

// WithExtraRepos adds a set of extra repos to the build context.
func WithExtraRepos(extraRepos []string) Option {
	return func(b *Build) error {
		b.ExtraRepos = extraRepos
		return nil
	}
}

// WithDependencyLog sets a filename to use for dependency logging.
func WithDependencyLog(logFile string) Option {
	return func(b *Build) error {
		b.DependencyLog = logFile
		return nil
	}
}

// WithBinShOverlay sets a filename to copy from when installing /bin/sh
// into a build environment.
func WithBinShOverlay(binShOverlay string) Option {
	return func(b *Build) error {
		b.BinShOverlay = binShOverlay
		return nil
	}
}

// WithStripOriginName determines whether the origin name should be stripped
// from generated packages.  The APK solver uses origin names to flatten
// possible dependency nodes when solving for a DAG, which means that they
// should be stripped when building "bootstrap" repositories, as the
// cross-sysroot packages will be preferred over the native ones otherwise.
func WithStripOriginName(stripOriginName bool) Option {
	return func(b *Build) error {
		b.StripOriginName = stripOriginName
		return nil
	}
}

// WithEnvFile specifies an environment file to use to preload the build
// environment.  It should contain the CFLAGS and LDFLAGS used by the C
// toolchain as well as any other desired environment settings for the
// build environment.
func WithEnvFile(envFile string) Option {
	return func(b *Build) error {
		b.EnvFile = envFile
		return nil
	}
}

// WithVarsFile specifies a variables file to use to populate the build
// configuration variables block.
func WithVarsFile(varsFile string) Option {
	return func(b *Build) error {
		b.VarsFile = varsFile
		return nil
	}
}

// WithNamespace takes a string to be used as the namespace in PackageURLs
// identifying the built apk in the generated SBOM. If no namespace is provided
// "unknown" will be listed as namespace.
func WithNamespace(namespace string) Option {
	return func(b *Build) error {
		b.Namespace = namespace
		return nil
	}
}

// WithEnabledBuildOptions takes an array of strings representing enabled build
// options.  These options are referenced in the options block of the Configuration,
// and represent patches to the configured build process which are optionally
// applied.
func WithEnabledBuildOptions(enabledBuildOptions []string) Option {
	return func(b *Build) error {
		b.EnabledBuildOptions = enabledBuildOptions
		return nil
	}
}

// WithCreateBuildLog indicates whether to generate a package.log file containing the
// list of packages that were built.  Some packages may have been skipped
// during the build if , so it can be hard to know exactly which packages were built
func WithCreateBuildLog(createBuildLog bool) Option {
	return func(b *Build) error {
		b.CreateBuildLog = createBuildLog
		return nil
	}
}

// WithPersistLintResults indicates whether to persist lint results to JSON files
// in the packages/{arch} directory.
func WithPersistLintResults(persistLintResults bool) Option {
	return func(b *Build) error {
		b.PersistLintResults = persistLintResults
		return nil
	}
}

// WithDebug indicates whether debug logging of pipelines should be enabled.
func WithDebug(debug bool) Option {
	return func(b *Build) error {
		b.Debug = debug
		return nil
	}
}

// WithDebugRunner indicates whether the runner should leave the build environment up on failures
func WithDebugRunner(debug bool) Option {
	return func(b *Build) error {
		b.DebugRunner = debug
		return nil
	}
}

// WithInteractive indicates whether to attach stdin and a tty to the runner on failures
func WithInteractive(interactive bool) Option {
	return func(b *Build) error {
		b.Interactive = interactive
		return nil
	}
}

// WithRemove indicates whether the the build will clean up after itself.
// This includes deleting any intermediate artifacts like container images and temp workspace and guest dirs.
func WithRemove(remove bool) Option {
	return func(b *Build) error {
		b.Remove = remove
		return nil
	}
}

// WithRunner specifies what runner to use to wrap
// the build environment.
func WithRunner(runner container.Runner) Option {
	return func(b *Build) error {
		b.Runner = runner
		return nil
	}
}

func WithPackageCacheDir(apkCacheDir string) Option {
	return func(b *Build) error {
		b.ApkCacheDir = apkCacheDir
		return nil
	}
}

func WithCPU(cpu string) Option {
	return func(b *Build) error {
		b.DefaultCPU = cpu
		return nil
	}
}

func WithCPUModel(cpumodel string) Option {
	return func(b *Build) error {
		b.DefaultCPUModel = cpumodel
		return nil
	}
}

func WithDisk(disk string) Option {
	return func(b *Build) error {
		b.DefaultDisk = disk
		return nil
	}
}

func WithMemory(memory string) Option {
	return func(b *Build) error {
		b.DefaultMemory = memory
		return nil
	}
}

func WithTimeout(dur time.Duration) Option {
	return func(b *Build) error {
		b.DefaultTimeout = dur
		return nil
	}
}

// WithExtraPackages specifies packages that are added to each build by default.
func WithExtraPackages(extraPackages []string) Option {
	return func(b *Build) error {
		b.ExtraPackages = extraPackages
		return nil
	}
}

func WithAuth(domain, user, pass string) Option {
	return func(b *Build) error {
		if b.Auth == nil {
			b.Auth = make(map[string]options.Auth)
		}
		b.Auth[domain] = options.Auth{User: user, Pass: pass}
		return nil
	}
}

// WithLibcFlavorOverride sets the libc flavor for the build.
func WithLibcFlavorOverride(libc string) Option {
	return func(b *Build) error {
		b.Libc = libc
		return nil
	}
}

// WithIgnoreIndexSignatures sets whether to ignore repository signature verification.
func WithIgnoreSignatures(ignore bool) Option {
	return func(b *Build) error {
		b.IgnoreSignatures = ignore
		return nil
	}
}

// WithGenerateProvenance sets whether to generate SLSA provenance during the build.
func WithGenerateProvenance(provenance bool) Option {
	return func(b *Build) error {
		b.GenerateProvenance = provenance
		return nil
	}
}

// WithSBOMGenerator sets a custom SBOM generator for the build.
// If not set, the default generator will be used.
func WithSBOMGenerator(generator sbom.Generator) Option {
	return func(b *Build) error {
		b.SBOMGenerator = generator
		return nil
	}
}
