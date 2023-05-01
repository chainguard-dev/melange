// Copyright 2022, 2023 Chainguard, Inc.
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

package build

import (
	"io/fs"
	"os"
	"path/filepath"

	apkofs "github.com/chainguard-dev/go-apk/pkg/fs"
)

type rlfs struct {
	base string
	f    fs.FS
}

func (f *rlfs) Readlink(name string) (string, error) {
	target, err := os.Readlink(filepath.Join(f.base, name))
	if err != nil {
		return "", err
	}
	return target, nil
}

func (f *rlfs) Open(name string) (fs.File, error) {
	return f.f.Open(name)
}

func (f *rlfs) Stat(name string) (fs.FileInfo, error) {
	return os.Stat(filepath.Join(f.base, name))
}

func readlinkFS(dir string) apkofs.ReadLinkFS {
	return &rlfs{
		base: dir,
		f:    os.DirFS(dir),
	}
}
