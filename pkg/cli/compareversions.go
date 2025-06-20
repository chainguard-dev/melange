// Copyright 2025 Chainguard, Inc.
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
	"fmt"
	"os"

	"chainguard.dev/apko/pkg/apk/apk"
	"github.com/spf13/cobra"
)

func compareVersions() *cobra.Command {
	var silent bool

	cmd := &cobra.Command {
		Use:     "compare-versions",
		Short:   "Compare two package versions",
		Long:    `Compare two package versions according to a specified operator.

The operator can be: eq (equal), ne (not-equal),
                     lt (less-than), le (less-than or equal),
                     gt (greater-than), ge (greater-than or equal)`,
		Example: `melange compare-versions version1 operator version2`,
		Args:    cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return compareVersionsCli(cmd.Context(), args[0], args[1], args[2], silent)
		},
	}

	cmd.Flags().BoolVarP(&silent, "silent", "s", false, "don't print anything; use the return code ($?) to signal whether the comparison is true or false")

	return cmd
}

func compareVersionsCli(_ context.Context, version1 string, operator string, version2 string, silent bool) error {
	pkgversion1, err := apk.ParseVersion(version1)
	if err != nil {
		return err
	}

	pkgversion2, err := apk.ParseVersion(version2)
	if err != nil {
		return err
	}

	r := apk.CompareVersions(pkgversion1, pkgversion2)

	var succeeded bool
	var operatorStr string

	switch operator {
	case "eq":
		succeeded = r == 0
		operatorStr = "equal to"
	case "lt":
		succeeded = r < 0
		operatorStr = "less than"
	case "le":
		succeeded = r <= 0
		operatorStr = "less than or equal to"
	case "gt":
		succeeded = r > 0
		operatorStr = "greater than"
	case "ge":
		succeeded = r >= 0
		operatorStr = "greater than or equal to"
	case "ne":
		succeeded = r != 0
		operatorStr = "different than"
	default:
		return fmt.Errorf("invalid operator %q", operator)
	}

	if succeeded {
		if silent {
			os.Exit(0)
		} else {
			fmt.Printf("%q is %s %q\n", version1, operatorStr, version2)
		}
	} else {
		if silent {
			os.Exit(1)
		} else {
			fmt.Printf("%q is NOT %s %q\n", version1, operatorStr, version2)
		}
	}

	return nil
}
