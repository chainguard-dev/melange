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

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	"golang.org/x/sys/unix"
)

type rlfs struct {
	apkofs.XattrFS

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

func (f *rlfs) SetXattr(path string, attr string, data []byte) error {
	return unix.Setxattr(filepath.Join(f.base, path), attr, data, 0)
}

func (f *rlfs) GetXattr(path string, attr string) ([]byte, error) {
	realPath := filepath.Join(f.base, path)

	size, err := unix.Getxattr(realPath, attr, nil)
	if err != nil {
		return []byte{}, err
	}

	buf := make([]byte, size)
	_, err = unix.Getxattr(realPath, attr, buf)
	if err != nil {
		return []byte{}, err
	}

	return buf, nil
}

func (f *rlfs) RemoveXattr(path string, attr string) error {
	return unix.Removexattr(filepath.Join(f.base, path), attr)
}

// stringsFromByteSlice converts a sequence of attributes to a []string.
// On Linux, each entry is a NULL-terminated string.
// Taken from golang.org/x/sys/unix/syscall_linux_test.go.
func stringsFromByteSlice(buf []byte) []string {
	var result []string
	off := 0
	for i, b := range buf {
		if b == 0 {
			result = append(result, string(buf[off:i]))
			off = i + 1
		}
	}
	return result
}

// xattrIgnoreList contains a mapping of xattr names used by various
// security features which leak their state into packages.  We need to
// ignore these xattrs because they require special permissions to be
// set when the underlying security features are in use.
var xattrIgnoreList = map[string]bool{
	"com.apple.provenance":          true,
	"security.csm":                  true,
	"security.selinux":              true,
	"com.docker.grpcfuse.ownership": true,
}

func (f *rlfs) ListXattrs(path string) (map[string][]byte, error) {
	realPath := filepath.Join(f.base, path)

	size, err := unix.Listxattr(realPath, nil)
	if err != nil {
		return map[string][]byte{}, err
	}

	// If the xattr list is empty, the size will be 0.
	if size <= 0 {
		return map[string][]byte{}, nil
	}

	buf := make([]byte, size)
	read, err := unix.Listxattr(realPath, buf)
	if err != nil {
		return map[string][]byte{}, err
	}

	xattrMap := map[string][]byte{}
	xattrNames := stringsFromByteSlice(buf[:read])
	for _, xattrName := range xattrNames {
		if _, ok := xattrIgnoreList[xattrName]; ok {
			continue
		}

		result, err := f.GetXattr(path, xattrName)
		if err != nil {
			return map[string][]byte{}, err
		}

		xattrMap[xattrName] = result
	}

	return xattrMap, nil
}

func readlinkFS(dir string) apkofs.ReadLinkFS {
	return &rlfs{
		base: dir,
		f:    os.DirFS(dir),
	}
}
