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

package config

import (
	"fmt"
	"regexp"

	"chainguard.dev/melange/pkg/util"
)

const (
	SubstitutionPackageName           = "${{package.name}}"
	SubstitutionPackageVersion        = "${{package.version}}"
	SubstitutionPackageFullVersion    = "${{package.full-version}}"
	SubstitutionPackageEpoch          = "${{package.epoch}}"
	SubstitutionPackageDescription    = "${{package.description}}"
	SubstitutionPackageSrcdir         = "${{package.srcdir}}"
	SubstitutionTargetsOutdir         = "${{targets.outdir}}"
	SubstitutionTargetsDestdir        = "${{targets.destdir}}"
	SubstitutionTargetsContextdir     = "${{targets.contextdir}}"
	SubstitutionSubPkgName            = "${{subpkg.name}}"
	SubstitutionSubPkgDir             = "${{targets.subpkgdir}}"
	SubstitutionContextName           = "${{context.name}}"
	SubstitutionHostTripletGnu        = "${{host.triplet.gnu}}"
	SubstitutionHostTripletRust       = "${{host.triplet.rust}}"
	SubstitutionCrossTripletGnuGlibc  = "${{cross.triplet.gnu.glibc}}"
	SubstitutionCrossTripletGnuMusl   = "${{cross.triplet.gnu.musl}}"
	SubstitutionCrossTripletRustGlibc = "${{cross.triplet.rust.glibc}}"
	SubstitutionCrossTripletRustMusl  = "${{cross.triplet.rust.musl}}"
	SubstitutionBuildArch             = "${{build.arch}}"
	SubstitutionBuildGoArch           = "${{build.goarch}}"
)

// Get variables from configuration and return them in a map
func (cfg Configuration) GetVarsFromConfig() (map[string]string, error) {
	nw := map[string]string{}

	for k, v := range cfg.Vars {
		nk := fmt.Sprintf("${{vars.%s}}", k)

		nv, err := util.MutateStringFromMap(nw, v)
		if err != nil {
			return nil, err
		}

		nw[nk] = nv
	}

	return nw, nil
}

// Perform variable substitutions from the configuration on a given map
func (cfg Configuration) PerformVarSubstitutions(nw map[string]string) error {
	for _, v := range cfg.VarTransforms {
		nk := fmt.Sprintf("${{vars.%s}}", v.To)
		from, err := util.MutateStringFromMap(nw, v.From)
		if err != nil {
			return err
		}

		re, err := regexp.Compile(v.Match)
		if err != nil {
			return fmt.Errorf("match value: %s string does not compile into a regex: %w", v.Match, err)
		}

		output := re.ReplaceAllString(from, v.Replace)
		nw[nk] = output
	}

	return nil
}
