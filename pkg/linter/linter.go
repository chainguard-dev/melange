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

package linter

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"

	"golang.org/x/exp/maps"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/linter/linters"
)

type linterFunc func(ctx context.Context, cfg *config.Configuration, pkgname string, fsys fs.FS) error

type linter struct {
	LinterFunc      linterFunc
	Explain         string
	defaultBehavior defaultBehavior
}

type defaultBehavior int

const (
	// Ignore the linter (default)
	Ignore defaultBehavior = iota
	// Require the linter.
	Require
	// Warn about the linter.
	Warn
)

func DefaultRequiredLinters() []string {
	l := slices.DeleteFunc(maps.Keys(linterMap), func(k string) bool { return linterMap[k].defaultBehavior != Require })
	slices.Sort(l)
	return l
}

func DefaultWarnLinters() []string {
	l := slices.DeleteFunc(maps.Keys(linterMap), func(k string) bool { return linterMap[k].defaultBehavior != Warn })
	slices.Sort(l)
	return l
}

var linterMap = map[string]linter{
	"dev": {
		LinterFunc:      linters.DevLinter,
		Explain:         "If this package is creating /dev nodes, it should use udev instead; otherwise, remove any files in /dev",
		defaultBehavior: Require,
	},
	"documentation": {
		LinterFunc:      linters.DocumentationLinter,
		Explain:         "Place documentation into a separate package or remove it",
		defaultBehavior: Ignore, // TODO: Lots of packages write to READMEs, etc.
	},
	"opt": {
		LinterFunc:      linters.OptLinter,
		Explain:         "This package should be a -compat package",
		defaultBehavior: Warn,
	},
	"object": {
		LinterFunc:      linters.ObjectLinter,
		Explain:         "This package contains intermediate object files (.o files)",
		defaultBehavior: Warn,
	},
	"maninfo": {
		LinterFunc:      linters.ManInfoLinter,
		Explain:         "Place documentation into a separate package or remove it",
		defaultBehavior: Warn,
	},
	"sbom": {
		LinterFunc:      linters.SbomLinter,
		Explain:         "Remove any files in /var/lib/db/sbom from the package",
		defaultBehavior: Warn, // TODO: needs work to be useful
	},
	"setuidgid": {
		LinterFunc:      linters.IsSetUIDOrGIDLinter,
		Explain:         "Unset the setuid/setgid bit on the relevant files, or remove this linter",
		defaultBehavior: Require,
	},
	"srv": {
		LinterFunc:      linters.SrvLinter,
		Explain:         "This package should be a -compat package",
		defaultBehavior: Warn,
	},
	"tempdir": {
		LinterFunc:      linters.TempDirLinter,
		Explain:         "Remove any offending files in temporary dirs in the pipeline",
		defaultBehavior: Require,
	},
	"usrlocal": {
		LinterFunc:      linters.UsrLocalLinter,
		Explain:         "This package should be a -compat package",
		defaultBehavior: Warn,
	},
	"varempty": {
		LinterFunc:      linters.VarEmptyLinter,
		Explain:         "Remove any offending files in /var/empty in the pipeline",
		defaultBehavior: Require,
	},
	"worldwrite": {
		LinterFunc:      linters.WorldWriteableLinter,
		Explain:         "Change the permissions of any permissive files in the package, disable the linter, or make this a -compat package",
		defaultBehavior: Require,
	},
	"strip": {
		LinterFunc:      linters.StrippedLinter,
		Explain:         "Properly strip all binaries in the pipeline",
		defaultBehavior: Warn,
	},
	"infodir": {
		LinterFunc:      linters.InfodirLinter,
		Explain:         "Remove /usr/share/info/dir from the package (run split/infodir)",
		defaultBehavior: Require,
	},
	"empty": {
		LinterFunc:      linters.EmptyLinter,
		Explain:         "Verify that this package is supposed to be empty; if it is, disable this linter; otherwise check the build",
		defaultBehavior: Ignore, // TODO: Needs to ignore packages that specify no-provides.
	},
	"python/docs": {
		LinterFunc:      linters.PythonDocsLinter,
		Explain:         "Remove all docs directories from the package",
		defaultBehavior: Warn,
	},
	"python/multiple": {
		LinterFunc:      linters.PythonMultiplePackagesLinter,
		Explain:         "Split this package up into multiple packages and verify you are not improperly using pip install",
		defaultBehavior: Warn,
	},
	"python/test": {
		LinterFunc:      linters.PythonTestLinter,
		Explain:         "Remove all test directories from the package",
		defaultBehavior: Warn,
	},
	"pkgconf": {
		LinterFunc:      linters.PkgconfTestLinter,
		Explain:         "This package provides files in a pkgconfig directory, please add the pkgconf test pipeline",
		defaultBehavior: Warn,
	},
	"lddcheck": {
		LinterFunc:      linters.LddcheckTestLinter,
		Explain:         "This package provides shared object files, please add the ldd-check test pipeline",
		defaultBehavior: Warn,
	},
	"usrmerge": {
		LinterFunc:      linters.UsrmergeLinter,
		Explain:         "Move binary to /usr/bin",
		defaultBehavior: Require,
	},
	"cudaruntimelib": {
		LinterFunc:      linters.CudaDriverLibLinter,
		Explain:         "CUDA driver-specific libraries should be passed into the container by the host. Installing them in an image could override the host libraries and break GPU support. If this library is needed for build-time linking or ldd-check tests, please use a package containing a stub library instead. For libcuda.so, use nvidia-cuda-cudart-$cuda_version. For libnvidia-ml.so, use nvidia-cuda-nvml-dev-$cuda_version.",
		defaultBehavior: Warn,
	},
	"dll": {
		LinterFunc:      linters.DllLinter,
		Explain:         "This package contains Windows libraries",
		defaultBehavior: Warn,
	},
	"dylib": {
		LinterFunc:      linters.DylibLinter,
		Explain:         "This package contains macOS libraries",
		defaultBehavior: Warn,
	},
	"nonlinux": {
		LinterFunc:      linters.NonLinuxLinter,
		Explain:         "This package contains references to non-Linux paths",
		defaultBehavior: Warn,
	},
	"unsupportedarch": {
		LinterFunc:      linters.UnsupportedArchLinter,
		Explain:         "This package contains references to unsupported architectures (only aarch64/arm64 and amd64/x86_64 are supported)",
		defaultBehavior: Warn,
	},
	"binaryarch": {
		LinterFunc:      linters.BinaryArchLinter,
		Explain:         "This package contains binaries compiled for unsupported architectures (only aarch64/arm64 and amd64/x86_64 binaries are supported)",
		defaultBehavior: Warn,
	},
	"staticarchive": {
		LinterFunc:      linters.StaticArchiveLinter,
		Explain:         "This package contains static archives (.a files)",
		defaultBehavior: Warn,
	},
	"duplicate": {
		LinterFunc:      linters.DuplicateLinter,
		Explain:         "This package contains files with the same name and content in different directories (consider symlinking)",
		defaultBehavior: Warn,
	},
}

func checkLinters(linters []string) error {
	var errs []error
	for _, linterName := range linters {
		if _, found := linterMap[linterName]; !found {
			errs = append(errs, fmt.Errorf("unknown linter: %q", linterName))
		}
	}
	return errors.Join(errs...)
}
