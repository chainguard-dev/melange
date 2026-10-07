// Copyright 2026 Chainguard, Inc.
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
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

func TestAddBuildFlags_ExcludeEnvFromRecordedConfig(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "defaults to empty",
			args: nil,
			want: []string{},
		},
		{
			name: "single key",
			args: []string{"--exclude-env-from-recorded-config=CONFIG_PATH"},
			want: []string{"CONFIG_PATH"},
		},
		{
			name: "repeated flag accumulates keys",
			args: []string{
				"--exclude-env-from-recorded-config=CONFIG_PATH",
				"--exclude-env-from-recorded-config=CREDENTIALS_FILE",
			},
			want: []string{"CONFIG_PATH", "CREDENTIALS_FILE"},
		},
		{
			name: "comma-separated keys",
			args: []string{"--exclude-env-from-recorded-config=CONFIG_PATH,CREDENTIALS_FILE"},
			want: []string{"CONFIG_PATH", "CREDENTIALS_FILE"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := pflag.NewFlagSet("build", pflag.ContinueOnError)
			flags := &BuildFlags{}
			addBuildFlags(fs, flags)

			require.NoError(t, fs.Parse(tt.args))
			require.Equal(t, tt.want, flags.ExcludeEnvFromRecordedConfig)
		})
	}
}
