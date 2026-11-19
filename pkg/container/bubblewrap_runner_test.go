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

package container

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog/slogtest"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TestBubblewrapCmd(t *testing.T) {
	tests := []struct {
		name         string
		config       *Config
		expectedArgs string
	}{
		{
			name:         "With default UID and GID",
			config:       new(Config),
			expectedArgs: fmt.Sprintf("--unshare-user --uid %s --gid %s", buildUserID, buildUserID),
		},
		{
			name:         "With config RunAs",
			config:       &Config{RunAsUID: "65535"},
			expectedArgs: fmt.Sprintf("--unshare-user --uid %s --gid %s", "65535", "65535"),
		},
		{
			name:         "With config RunAs with distinct UID and GID",
			config:       &Config{RunAsUID: "65535", RunAsGID: "1000"},
			expectedArgs: fmt.Sprintf("--unshare-user --uid %s --gid %s", "65535", "1000"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := slogtest.Context(t)
			args := make([]string, 0)

			cmd := new(bubblewrap).cmd(ctx, tt.config, false, nil, args...)
			if cmd.Args == nil {
				t.Fatalf("cmd.Args should not be nil")
			}
			if !strings.Contains(strings.Join(cmd.Args, " "), tt.expectedArgs) {
				t.Fatalf("expected %v, found %v", tt.expectedArgs, cmd.Args)
			}
		})
	}
}

// tarLayer is a v1.Layer that serves only Uncompressed, which is all
// LoadImage reads.
type tarLayer struct {
	v1.Layer
	tarball []byte
}

func (l tarLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(l.tarball)), nil
}

// TestBubblewrapLoadImageRootMode verifies that the guest root, which bwrap
// binds as the build environment's /, can be traversed by accounts other than
// its owner, while its parent on the host cannot. The layer has no entry for
// its own root, so only LoadImage can set that mode.
func TestBubblewrapLoadImageRootMode(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "usr/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatalf("writing header: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar: %v", err)
	}

	loader := &bubblewrapOCILoader{}
	ref, err := loader.LoadImage(t.Context(), tarLayer{tarball: buf.Bytes()}, apko_types.ParseArchitecture("amd64"), nil)
	if err != nil {
		t.Fatalf("LoadImage: %v", err)
	}
	fi, err := os.Stat(ref)
	if err != nil {
		t.Fatalf("stat guest dir: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o755 {
		t.Errorf("guest root mode = %04o, want 0755", got)
	}

	parent := filepath.Dir(ref)
	fi, err = os.Stat(parent)
	if err != nil {
		t.Fatalf("stat guest parent: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("guest parent mode = %04o, want 0700", got)
	}

	if err := loader.RemoveImage(t.Context(), ref); err != nil {
		t.Fatalf("RemoveImage: %v", err)
	}
	if _, err := os.Stat(parent); !os.IsNotExist(err) {
		t.Errorf("guest parent still exists after RemoveImage: %v", err)
	}
}
