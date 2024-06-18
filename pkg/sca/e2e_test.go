// Copyright 2024 Chainguard, Inc.
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

//go:build e2e
// +build e2e

package sca

import (
	"fmt"
	"runtime"
	"testing"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/util"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/google/go-cmp/cmp"
)

// test a fips like go binary package for SCA depends
// Chainguard go-fips toolchain generates binaries like these
// which at runtime require openssl and fips provider
func TestGoFipsBinDeps(t *testing.T) {
	ctx := slogtest.TestContextWithLogger(t)

	var ldso, archdir string
	switch runtime.GOARCH {
	case "arm64":
		ldso = "so:ld-linux-aarch64.so.1"
		archdir = "aarch64"
	case "amd64":
		ldso = "so:ld-linux-x86-64.so.2"
		archdir = "x86_64"
	}

	th := handleFromApk(ctx, t, fmt.Sprintf("go-fips-bin/packages/%s/go-fips-bin-v0.0.1-r0.apk", archdir), "go-fips-bin/go-fips-bin.yaml")
	defer th.exp.Close()

	got := config.Dependencies{}
	if err := Analyze(ctx, th, &got); err != nil {
		t.Fatal(err)
	}

	want := config.Dependencies{
		Runtime: []string{
			"openssl-config-fipshardened",
			ldso,
			"so:libc.so.6",
			"so:libcrypto.so.3",
			"so:libssl.so.3",
		},
		Provides: []string{
			"cmd:go-fips-bin=v0.0.1-r0",
		},
	}

	got.Runtime = util.Dedup(got.Runtime)
	got.Provides = util.Dedup(got.Provides)

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Analyze(): (-want, +got):\n%s", diff)
	}
}
