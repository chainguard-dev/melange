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

package sca

import (
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
	"github.com/google/go-cmp/cmp"

	"chainguard.dev/melange/pkg/config"
)

func TestGoFipsBinDeps(t *testing.T) {
	ctx := slogtest.Context(t)
	th := handleFromApk(ctx, t, "generated/x86_64/go-fips-bin-0.0.1-r0.apk", "go-fips-bin/go-fips-bin.yaml")
	defer th.exp.Close()

	got := config.Dependencies{}
	if err := Analyze(ctx, th, &got); err != nil {
		t.Fatal(err)
	}
	want := config.Dependencies{
		Runtime: []string{
			"openssl-config-fipshardened",
			"so:ld-linux-x86-64.so.2",
			"so:libc.so.6",
			"so:libcrypto.so.3",
		},
		Provides: []string{"cmd:go-fips-bin=0.0.1-r0"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Analyze(): (-want, +got):\n%s", diff)
	}
}

func TestAnalyze(t *testing.T) {
	for _, c := range []struct {
		apk     string
		cfgpath string
		want    config.Dependencies
	}{{
		apk:     "py3-seaborn-0.13.2-r0.apk",
		cfgpath: "py3-seaborn.yaml",
		want: config.Dependencies{
			Runtime: []string{
				"so:ld-linux-x86-64.so.2",
				"so:libXau-154567c4.so.6.0.0",
				"so:libbrotlicommon-3ecfe81c.so.1",
				"so:libbrotlidec-ba690955.so.1",
				"so:libc.so.6",
				"so:libdl.so.2",
				"so:libfreetype-f154df84.so.6.20.1",
				"so:libgcc_s.so.1",
				"so:libgfortran-040039e1.so.5.0.0",
				"so:libharfbuzz-2093a78b.so.0.60830.0",
				"so:libjpeg-e44fd0cd.so.62.4.0",
				"so:liblcms2-e69eef39.so.2.0.16",
				"so:liblzma-13fa198c.so.5.4.5",
				"so:libm.so.6",
				"so:libopenjp2-eca49203.so.2.5.0",
				"so:libpng16-78d422d5.so.16.40.0",
				"so:libpthread.so.0",
				"so:libquadmath-96973f99.so.0.0.0",
				"so:libsharpyuv-20f78091.so.0.0.1",
				"so:libstdc++.so.6",
				"so:libtiff-91af027d.so.6.0.2",
				"so:libwebp-850e2bec.so.7.1.8",
				"so:libwebpdemux-df9b36c7.so.2.0.14",
				"so:libwebpmux-9fe05867.so.3.0.13",
				"so:libxcb-f0538cc0.so.1.1.0",
				"so:libz.so.1",
			},
			Provides: []string{
				"cmd:f2py=0.13.2-r0",
				"cmd:fonttools=0.13.2-r0",
				"cmd:pyftmerge=0.13.2-r0",
				"cmd:pyftsubset=0.13.2-r0",
				"cmd:ttx=0.13.2-r0",
			},
			Vendored: []string{
				"so-ver:libXau-154567c4.so.6.0.0=0.13.2-r0",
				"so-ver:libbrotlicommon-3ecfe81c.so.1=0.13.2-r0",
				"so-ver:libbrotlidec-ba690955.so.1=0.13.2-r0",
				"so-ver:libfreetype-f154df84.so.6.20.1=0.13.2-r0",
				"so-ver:libgfortran-040039e1.so.5.0.0=0.13.2-r0",
				"so-ver:libharfbuzz-2093a78b.so.0.60830.0=0.13.2-r0",
				"so-ver:libjpeg-e44fd0cd.so.62.4.0=0.13.2-r0",
				"so-ver:liblcms2-e69eef39.so.2.0.16=0.13.2-r0",
				"so-ver:liblzma-13fa198c.so.5.4.5=0.13.2-r0",
				"so-ver:libopenblas64_p-r0-0cf96a72.3.23.dev.so=0.13.2-r0",
				"so-ver:libopenjp2-eca49203.so.2.5.0=0.13.2-r0",
				"so-ver:libpng16-78d422d5.so.16.40.0=0.13.2-r0",
				"so-ver:libquadmath-96973f99.so.0.0.0=0.13.2-r0",
				"so-ver:libsharpyuv-20f78091.so.0.0.1=0.13.2-r0",
				"so-ver:libtiff-91af027d.so.6.0.2=0.13.2-r0",
				"so-ver:libwebp-850e2bec.so.7.1.8=0.13.2-r0",
				"so-ver:libwebpdemux-df9b36c7.so.2.0.14=0.13.2-r0",
				"so-ver:libwebpmux-9fe05867.so.3.0.13=0.13.2-r0",
				"so-ver:libxcb-f0538cc0.so.1.1.0=0.13.2-r0",
				"so:libXau-154567c4.so.6.0.0=6.0.0",
				"so:libbrotlicommon-3ecfe81c.so.1=1",
				"so:libbrotlidec-ba690955.so.1=1",
				"so:libfreetype-f154df84.so.6.20.1=6.20.1",
				"so:libgfortran-040039e1.so.5.0.0=5.0.0",
				"so:libharfbuzz-2093a78b.so.0.60830.0=0.60830.0",
				"so:libjpeg-e44fd0cd.so.62.4.0=62.4.0",
				"so:liblcms2-e69eef39.so.2.0.16=2.0.16",
				"so:liblzma-13fa198c.so.5.4.5=5.4.5",
				"so:libopenblas64_p-r0-0cf96a72.3.23.dev.so=0",
				"so:libopenjp2-eca49203.so.2.5.0=2.5.0",
				"so:libpng16-78d422d5.so.16.40.0=16.40.0",
				"so:libquadmath-96973f99.so.0.0.0=0.0.0",
				"so:libsharpyuv-20f78091.so.0.0.1=0.0.1",
				"so:libtiff-91af027d.so.6.0.2=6.0.2",
				"so:libwebp-850e2bec.so.7.1.8=7.1.8",
				"so:libwebpdemux-df9b36c7.so.2.0.14=2.0.14",
				"so:libwebpmux-9fe05867.so.3.0.13=3.0.13",
				"so:libxcb-f0538cc0.so.1.1.0=1.1.0",
			},
		},
	}, {
		apk:     "systemd-256.2-r1.apk",
		cfgpath: "systemd.yaml",
		want: config.Dependencies{
			Runtime: []string{
				"so:ld-linux-x86-64.so.2",
				"so:libblkid.so.1",
				"so:libc.so.6",
				"so:libcap.so.2",
				"so:libcrypt.so.1",
				"so:libcrypto.so.3",
				"so:libfdisk.so.1",
				"so:libm.so.6",
				"so:libmount.so.1",
				"so:libssl.so.3",
				"so:libudev.so.1",
			},
			Provides: []string{
				"cmd:bootctl=256.2-r1",
				"cmd:busctl=256.2-r1",
				"cmd:coredumpctl=256.2-r1",
				"cmd:hostnamectl=256.2-r1",
				"cmd:journalctl=256.2-r1",
				"cmd:kernel-install=256.2-r1",
				"cmd:localectl=256.2-r1",
				"cmd:loginctl=256.2-r1",
				"cmd:machinectl=256.2-r1",
				"cmd:networkctl=256.2-r1",
				"cmd:oomctl=256.2-r1",
				"cmd:portablectl=256.2-r1",
				"cmd:resolvectl=256.2-r1",
				"cmd:systemctl=256.2-r1",
				"cmd:systemd-ac-power=256.2-r1",
				"cmd:systemd-analyze=256.2-r1",
				"cmd:systemd-ask-password=256.2-r1",
				"cmd:systemd-cat=256.2-r1",
				"cmd:systemd-cgls=256.2-r1",
				"cmd:systemd-cgtop=256.2-r1",
				"cmd:systemd-creds=256.2-r1",
				"cmd:systemd-delta=256.2-r1",
				"cmd:systemd-detect-virt=256.2-r1",
				"cmd:systemd-dissect=256.2-r1",
				"cmd:systemd-escape=256.2-r1",
				"cmd:systemd-firstboot=256.2-r1",
				"cmd:systemd-hwdb=256.2-r1",
				"cmd:systemd-id128=256.2-r1",
				"cmd:systemd-inhibit=256.2-r1",
				"cmd:systemd-machine-id-setup=256.2-r1",
				"cmd:systemd-mount=256.2-r1",
				"cmd:systemd-notify=256.2-r1",
				"cmd:systemd-nspawn=256.2-r1",
				"cmd:systemd-path=256.2-r1",
				"cmd:systemd-repart=256.2-r1",
				"cmd:systemd-run=256.2-r1",
				"cmd:systemd-socket-activate=256.2-r1",
				"cmd:systemd-stdio-bridge=256.2-r1",
				"cmd:systemd-sysext=256.2-r1",
				"cmd:systemd-sysusers=256.2-r1",
				"cmd:systemd-tmpfiles=256.2-r1",
				"cmd:systemd-tty-ask-password-agent=256.2-r1",
				"cmd:systemd-vmspawn=256.2-r1",
				"cmd:systemd-vpick=256.2-r1",
				"cmd:timedatectl=256.2-r1",
				"cmd:udevadm=256.2-r1",
				"cmd:userdbctl=256.2-r1",
				"cmd:varlinkctl=256.2-r1",
				"so-ver:libnss_myhostname.so.2=256.2-r1",
				"so-ver:libnss_mymachines.so.2=256.2-r1",
				"so-ver:libnss_resolve.so.2=256.2-r1",
				"so-ver:libnss_systemd.so.2=256.2-r1",
				"so-ver:libudev.so.1=256.2-r1",
				"so:libnss_myhostname.so.2=2",
				"so:libnss_mymachines.so.2=2",
				"so:libnss_resolve.so.2=2",
				"so:libnss_systemd.so.2=2",
				"so:libudev.so.1=1",
			},
			Vendored: []string{
				"so-ver:libsystemd-core-256.so=256.2-r1",
				"so-ver:libsystemd-shared-256.so=256.2-r1",
				"so:libsystemd-core-256.so=0",
				"so:libsystemd-shared-256.so=0",
			},
		},
	}} {
		t.Run(c.apk, func(t *testing.T) {
			ctx := slogtest.Context(t)
			url := "https://packages.wolfi.dev/os/x86_64/" + c.apk
			th := handleFromApk(ctx, t, url, c.cfgpath)
			defer th.exp.Close()

			got := config.Dependencies{}
			if err := Analyze(ctx, th, &got); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(c.want, got); diff != "" {
				t.Errorf("Analyze(): (-want, +got):\n%s", diff)
			}
		})
	}
}
