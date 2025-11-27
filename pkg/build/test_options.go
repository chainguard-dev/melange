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

package build

import (
	"time"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"

	"chainguard.dev/melange/pkg/container"
)

type TestOption func(*Test) error

// WithTestConfig sets the configuration file used for the package test context.
func WithTestConfig(configFile string) TestOption {
	return func(t *Test) error {
		t.ConfigFile = configFile
		return nil
	}
}

// WithWorkspaceDir sets the workspace directory to use.
func WithTestWorkspaceDir(workspaceDir string) TestOption {
	return func(t *Test) error {
		t.WorkspaceDir = workspaceDir
		return nil
	}
}

// WithWorkspaceIgnore sets the workspace ignore rules file to use.
func WithTestWorkspaceIgnore(workspaceIgnore string) TestOption {
	return func(t *Test) error {
		t.WorkspaceIgnore = workspaceIgnore
		return nil
	}
}

// WithPipelineDir sets the pipeline directory to extend the built-in pipeline directory.
func WithTestPipelineDir(pipelineDir string) TestOption {
	return func(t *Test) error {
		t.PipelineDirs = append(t.PipelineDirs, pipelineDir)
		return nil
	}
}

// WithSourceDir sets the source directory to use.
func WithTestSourceDir(sourceDir string) TestOption {
	return func(t *Test) error {
		t.SourceDir = sourceDir
		return nil
	}
}

// WithCacheDir sets the cache directory to use.
func WithTestCacheDir(cacheDir string) TestOption {
	return func(t *Test) error {
		t.CacheDir = cacheDir
		return nil
	}
}

// WithCacheSource sets the cache source directory to use.  The cache will be
// pre-populated from this source directory.
func WithTestCacheSource(sourceDir string) TestOption {
	return func(t *Test) error {
		t.CacheSource = sourceDir
		return nil
	}
}

// WithTestArch sets the build architecture to use for this test context.
func WithTestArch(arch apko_types.Architecture) TestOption {
	return func(t *Test) error {
		t.Arch = arch
		return nil
	}
}

// WithTestExtraKeys adds a set of extra keys to the test context.
func WithTestExtraKeys(extraKeys []string) TestOption {
	return func(t *Test) error {
		t.ExtraKeys = extraKeys
		return nil
	}
}

// WithTestDebug indicates whether debug logging of pipelines should be enabled.
func WithTestDebug(debug bool) TestOption {
	return func(t *Test) error {
		t.Debug = debug
		return nil
	}
}

func WithTestDebugRunner(debugRunner bool) TestOption {
	return func(t *Test) error {
		t.DebugRunner = debugRunner
		return nil
	}
}

// WithTestInteractive indicates whether to attach stdin and a tty to the runner on failures
func WithTestInteractive(interactive bool) TestOption {
	return func(t *Test) error {
		t.Interactive = interactive
		return nil
	}
}

// WithTestExtraRepos adds a set of extra repos to the test context.
func WithTestExtraRepos(extraRepos []string) TestOption {
	return func(t *Test) error {
		t.ExtraRepos = extraRepos
		return nil
	}
}

// WithTestBinShOverlay sets a filename to copy from when installing /bin/sh
// into a test environment.
func WithTestBinShOverlay(binShOverlay string) TestOption {
	return func(t *Test) error {
		t.BinShOverlay = binShOverlay
		return nil
	}
}

// WithTestRunner specifies what runner to use to wrap
// the test environment.
func WithTestRunner(runner container.Runner) TestOption {
	return func(t *Test) error {
		t.Runner = runner
		return nil
	}
}

// WithTestPackage specifies the package to test.
func WithTestPackage(pkg string) TestOption {
	return func(t *Test) error {
		t.Package = pkg
		return nil
	}
}

func WithTestPackageCacheDir(apkCacheDir string) TestOption {
	return func(t *Test) error {
		t.ApkCacheDir = apkCacheDir
		return nil
	}
}

// WithExtraTestPackages specifies packages that are added to each test by
// default.
func WithExtraTestPackages(extraTestPackages []string) TestOption {
	return func(t *Test) error {
		t.ExtraTestPackages = extraTestPackages
		return nil
	}
}

// WithTestEnvFile specifies an environment file to use to preload the build
// environment.  It should contain the CFLAGS and LDFLAGS used by the C
// toolchain as well as any other desired environment settings for the
// build environment.
func WithTestEnvFile(envFile string) TestOption {
	return func(t *Test) error {
		t.EnvFile = envFile
		return nil
	}
}

func WithTestAuth(domain, user, pass string) TestOption {
	return func(t *Test) error {
		if t.Auth == nil {
			t.Auth = make(map[string]options.Auth)
		}
		t.Auth[domain] = options.Auth{User: user, Pass: pass}
		return nil
	}
}

// If true, the test will clean up the test environment after the test is complete.
func WithTestRemove(c bool) TestOption {
	return func(t *Test) error {
		t.Remove = c
		return nil
	}
}

// WithIgnoreSignatures indicates whether to ignore signatures when
// installing packages.
func WithTestIgnoreSignatures(ignore bool) TestOption {
	return func(t *Test) error {
		t.IgnoreSignatures = ignore
		return nil
	}
}

func WithTestCPU(cpu string) TestOption {
	return func(t *Test) error {
		t.DefaultCPU = cpu
		return nil
	}
}

func WithTestCPUModel(cpumodel string) TestOption {
	return func(t *Test) error {
		t.DefaultCPUModel = cpumodel
		return nil
	}
}

func WithTestDisk(disk string) TestOption {
	return func(t *Test) error {
		t.DefaultDisk = disk
		return nil
	}
}

func WithTestMemory(memory string) TestOption {
	return func(t *Test) error {
		t.DefaultMemory = memory
		return nil
	}
}

func WithTestTimeout(dur time.Duration) TestOption {
	return func(t *Test) error {
		t.DefaultTimeout = dur
		return nil
	}
}
