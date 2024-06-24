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

// This subpackage avoids a circular import in config as it needs a list of
// the default linters.

package defaults

import (
	"slices"
)

type LinterClass int

const (
	LinterClassDefault LinterClass = 1 << iota
	LinterClassBuild
	LinterClassApk
)

// Default linters run regardless of whether we are dealing with an APK or build
var defaultLinters = []string{
	"dev",
	"documentation",
	"empty",
	"infodir",
	"object",
	"opt",
	"python/docs",
	"python/multiple",
	"python/test",
	"setuidgid",
	"srv",
	"strip",
	"tempdir",
	"usrlocal",
	"varempty",
	"worldwrite",
}

// Linters run by default on builds but not on APKs
var defaultBuildLinters = []string{
	"sbom",
}

// Linters run by default on APKs but not during build
var defaultApkLinters = []string{}

// Get the set of default linters for a given task
func GetDefaultLinters(linterClass LinterClass) (linters []string) {
	linters = slices.Clone(defaultLinters)
	switch linterClass {
	case LinterClassDefault:
		// Do nothing
	case LinterClassBuild:
		linters = append(linters, slices.Clone(defaultBuildLinters)...)
	case LinterClassApk:
		linters = append(linters, slices.Clone(defaultApkLinters)...)
	default:
		panic("Invalid linter set called")
	}

	return
}
