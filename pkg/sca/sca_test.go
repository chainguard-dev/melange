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

package sca

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/util"
	"github.com/chainguard-dev/go-apk/pkg/apk"
	"github.com/chainguard-dev/go-apk/pkg/expandapk"
	"github.com/google/go-cmp/cmp"
	"gopkg.in/ini.v1"
)

type testHandle struct {
	pkg apk.Package
	exp *expandapk.APKExpanded
	cfg *config.Configuration
}

func (th *testHandle) PackageName() string {
	return th.pkg.Name
}

func (th *testHandle) Version() string {
	return th.pkg.Version
}

func (th *testHandle) RelativeNames() []string {
	// TODO: Support subpackages?
	return []string{th.pkg.Origin}
}

func (th *testHandle) FilesystemForRelative(pkgName string) (SCAFS, error) {
	if pkgName != th.PackageName() {
		return nil, fmt.Errorf("TODO: implement FilesystemForRelative, %q != %q", pkgName, th.PackageName())
	}

	return th.exp.TarFS, nil
}

func (th *testHandle) Filesystem() (SCAFS, error) {
	return th.exp.TarFS, nil
}

func (th *testHandle) Options() config.PackageOption {
	return th.cfg.Package.Options
}

func (th *testHandle) BaseDependencies() config.Dependencies {
	return th.cfg.Package.Dependencies
}

// TODO: Loose coupling.
func handleFromApk(ctx context.Context, t *testing.T, apkfile, melangefile string) *testHandle {
	t.Helper()
	file, err := os.Open(filepath.Join("testdata", apkfile))
	if err != nil {
		t.Fatal(err)
	}

	exp, err := expandapk.ExpandApk(ctx, file, "")
	if err != nil {
		t.Fatal(err)
	}

	// Get the package name
	info, err := exp.ControlFS.Open(".PKGINFO")
	if err != nil {
		t.Fatal(err)
	}
	defer info.Close()

	cfg, err := ini.ShadowLoad(info)
	if err != nil {
		t.Fatal(err)
	}

	var pkg apk.Package
	if err = cfg.MapTo(&pkg); err != nil {
		t.Fatal(err)
	}
	pkg.BuildTime = time.Unix(pkg.BuildDate, 0).UTC()
	pkg.InstalledSize = pkg.Size
	pkg.Size = uint64(exp.Size)
	pkg.Checksum = exp.ControlHash

	pkgcfg, err := config.ParseConfiguration(ctx, filepath.Join("testdata", melangefile))
	if err != nil {
		t.Fatal(err)
	}

	return &testHandle{
		pkg: pkg,
		exp: exp,
		cfg: pkgcfg,
	}
}

func TestAnalyze(t *testing.T) {
	ctx := context.Background()
	th := handleFromApk(context.Background(), t, "libcap-2.69-r0.apk", "libcap.yaml")

	got := config.Dependencies{}
	if err := Analyze(ctx, th, &got); err != nil {
		t.Fatal(err)
	}

	want := config.Dependencies{
		Runtime: []string{
			"so:ld-linux-aarch64.so.1",
			"so:libc.so.6",
			"so:libcap.so.2",
			"so:libpsx.so.2",
		},
		Provides: []string{
			"so:libcap.so.2=2",
			"so:libpsx.so.2=2",
		},
	}

	got.Runtime = util.Dedup(got.Runtime)
	got.Provides = util.Dedup(got.Provides)

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Analyze(): (-want, +got):\n%s", diff)
	}
}
