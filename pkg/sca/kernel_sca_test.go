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

//go:generate go run ./../../ build --generate-index=false --out-dir=./testdata/generated ./testdata/linux.yaml --arch=x86_64

package sca

import (
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
	"github.com/google/go-cmp/cmp"

	"chainguard.dev/melange/pkg/config"
)

func TestKernelSca(t *testing.T) {
	ctx := slogtest.Context(t)

	for _, tc := range []struct {
		apk    string
		yaml   string
		expect config.Dependencies
		name   string
	}{
		{
			name:   "bzimage",
			yaml:   "linux.yaml",
			apk:    "generated/x86_64/linux-bzimage-6.17.7-r0.apk",
			expect: config.Dependencies{Provides: []string{"linux:6.17.7-test"}},
		},
		{
			name:   "vmlinux",
			yaml:   "linux.yaml",
			apk:    "generated/x86_64/linux-vmlinux-6.17.7-r0.apk",
			expect: config.Dependencies{Provides: []string{"linux:6.17.7-test"}},
		},
		{
			name:   "gzipped-vmlinux",
			yaml:   "linux.yaml",
			apk:    "generated/x86_64/linux-gzipped-vmlinux-6.17.7-r0.apk",
			expect: config.Dependencies{Provides: []string{"linux:6.17.7-test"}},
		},
		{
			name:   "uki",
			yaml:   "linux.yaml",
			apk:    "generated/x86_64/linux-uki-6.17.7-r0.apk",
			expect: config.Dependencies{Provides: []string{"linux:6.17.7-test"}},
		},
		{
			name:   "modules",
			yaml:   "linux.yaml",
			apk:    "generated/x86_64/linux-modules-6.17.7-r0.apk",
			expect: config.Dependencies{Runtime: []string{"linux:6.17.7-test"}},
		},
		{
			name:   "modules-gzipped",
			yaml:   "linux.yaml",
			apk:    "generated/x86_64/linux-modules-gzip-6.17.7-r0.apk",
			expect: config.Dependencies{Runtime: []string{"linux:6.17.7-test"}},
		},
		{
			name:   "modules-zstd",
			yaml:   "linux.yaml",
			apk:    "generated/x86_64/linux-modules-zstd-6.17.7-r0.apk",
			expect: config.Dependencies{Runtime: []string{"linux:6.17.7-test"}},
		},
		{
			name:   "modules-xz",
			yaml:   "linux.yaml",
			apk:    "generated/x86_64/linux-modules-xz-6.17.7-r0.apk",
			expect: config.Dependencies{Runtime: []string{"linux:6.17.7-test"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			th := handleFromApk(ctx, t, tc.apk, tc.yaml)
			defer th.exp.Close()

			got := config.Dependencies{}
			if err := Analyze(ctx, th, &got); err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(tc.expect, got); diff != "" {
				t.Errorf("Analyze(): (-want, +got):\n%s", diff)
			}
		})
	}
}
