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

// ListOption describes an optional deviation to a list, for example, a
// list of packages.
type ListOption struct {
	Add    []string `yaml:"add,omitempty"`
	Remove []string `yaml:"remove,omitempty"`
}

// ContentsOption describes an optional deviation to an apko environment's
// contents block.
type ContentsOption struct {
	Packages ListOption `yaml:"packages,omitempty"`
}

// EnvironmentOption describes an optional deviation to an apko environment.
type EnvironmentOption struct {
	Contents ContentsOption `yaml:"contents,omitempty"`
}

// BuildOption describes an optional deviation to a package build.
type BuildOption struct {
	Vars        map[string]string `yaml:"vars,omitempty"`
	Environment EnvironmentOption `yaml:"environment,omitempty"`
}

// Apply applies a patch described by a BuildOption to a package build.
func (bo BuildOption) Apply(b *Build) error {
	// Patch the variables block.
	if b.Configuration.Vars == nil {
		b.Configuration.Vars = make(map[string]string)
	}

	for k, v := range bo.Vars {
		b.Configuration.Vars[k] = v
	}

	// Patch the build environment configuration.
	lo := bo.Environment.Contents.Packages
	b.Configuration.Environment.Contents.Packages = append(b.Configuration.Environment.Contents.Packages, lo.Add...)

	for _, pkg := range lo.Remove {
		pkgList := b.Configuration.Environment.Contents.Packages

		for pos, ppkg := range pkgList {
			if pkg == ppkg {
				pkgList[pos] = pkgList[len(pkgList)-1]
				pkgList = pkgList[:len(pkgList)-1]
			}
		}

		b.Configuration.Environment.Contents.Packages = pkgList
	}

	return nil
}
