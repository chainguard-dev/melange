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
	"fmt"
	"testing"

	goapk "chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/sbom/generator/spdx"
	purl "github.com/package-url/packageurl-go"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"chainguard.dev/melange/pkg/build"
	"chainguard.dev/melange/pkg/config"
)

// A rebuild's only cache is the one --source-package provides, so the flag
// without it has nothing to restore from.
func TestRebuildStrictSourcesFromCacheNeedsSourcePackage(t *testing.T) {
	// an empty value is no more a way to ask for nothing than it is a kind
	for _, value := range []string{"git-checkout", ""} {
		flags, _, err := ParseRebuildFlags([]string{"--runner=bubblewrap", "--strict-sources-from-cache=" + value})
		require.NoError(t, err)
		flags.workDir = t.TempDir()
		_, err = flags.RebuildOptions(t.Context(), &goapk.PackageInfo{Name: "hello"}, &config.Configuration{}, &spdx.Package{}, purl.PackageURL{})
		require.ErrorContains(t, err, "--strict-sources-from-cache needs --source-package", value)
		require.NotContains(t, err.Error(), "--cache-dir")
	}
}

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

func TestStrictSourcesFromCacheFlag(t *testing.T) {
	for _, tt := range []struct {
		args    []string
		want    []string
		wantErr string
	}{
		{args: nil, want: nil},
		{args: []string{"--strict-sources-from-cache=git-checkout"}, want: []string{"git-checkout"}},
		{args: []string{"--strict-sources-from-cache=fetch"}, wantErr: `unknown step kind "fetch"; accepted: git-checkout`},
		{args: []string{"--strict-sources-from-cache=bogus"}, wantErr: `unknown step kind "bogus"; accepted: git-checkout`},
		{args: []string{"--strict-sources-from-cache=git-checkout,git-checkout"}, want: []string{"git-checkout"}},
		{args: []string{"--strict-sources-from-cache=git-checkout", "--strict-sources-from-cache=git-checkout"}, want: []string{"git-checkout"}},
		{args: []string{"--strict-sources-from-cache="}, wantErr: "empty"},
		{args: []string{"--strict-sources-from-cache=Git-Checkout"}, wantErr: `unknown step kind "Git-Checkout"`},
		{args: []string{"--strict-sources-from-cache=git-checkout,"}, wantErr: `unknown step kind ""`},
	} {
		t.Run(fmt.Sprint(tt.args), func(t *testing.T) {
			fs := pflag.NewFlagSet("build", pflag.ContinueOnError)
			flags := &BuildFlags{}
			addBuildFlags(fs, flags)
			require.NoError(t, fs.Parse(tt.args))
			opts, err := flags.BuildOptions(t.Context())
			require.NoError(t, err)
			b := &build.Build{}
			err = applyAll(b, opts)

			testFlags, _, err2 := ParseTestFlags(tt.args)
			require.NoError(t, err2)
			topts, err2 := testFlags.TestOptions(t.Context())
			require.NoError(t, err2)
			tst := &build.Test{}
			errTest := applyAllTest(tst, topts)

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				require.ErrorContains(t, errTest, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.NoError(t, errTest)
			require.Equal(t, tt.want, b.StrictSourcesFromCache)
			require.Equal(t, tt.want, tst.StrictSourcesFromCache)
		})
	}
}

func applyAll(b *build.Build, opts []build.Option) error {
	for _, o := range opts {
		if err := o(b); err != nil {
			return err
		}
	}
	return nil
}

func applyAllTest(t *build.Test, opts []build.TestOption) error {
	for _, o := range opts {
		if err := o(t); err != nil {
			return err
		}
	}
	return nil
}
