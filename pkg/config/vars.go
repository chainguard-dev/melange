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

	"github.com/pkg/errors"

	"chainguard.dev/melange/pkg/util"
)

func GetVarsFromConfig(Configuration *Configuration, nw map[string]string) error {
	for k, v := range Configuration.Vars {
		nk := fmt.Sprintf("${{vars.%s}}", k)

		nv, err := util.MutateStringFromMap(nw, v)
		if err != nil {
			return err
		}

		nw[nk] = nv
	}

	return nil
}

func PerformVarSubstitutions(Configuration *Configuration, nw map[string]string) error {
	for _, v := range Configuration.VarTransforms {
		nk := fmt.Sprintf("${{vars.%s}}", v.To)
		from, err := util.MutateStringFromMap(nw, v.From)
		if err != nil {
			return err
		}

		re, err := regexp.Compile(v.Match)
		if err != nil {
			return errors.Wrapf(err, "match value: %s string does not compile into a regex", v.Match)
		}

		output := re.ReplaceAllString(from, v.Replace)
		nw[nk] = output
	}

	return nil
}
