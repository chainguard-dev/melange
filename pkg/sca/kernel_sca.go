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

package sca

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"regexp"
	"strings"

	"chainguard.dev/melange/pkg/config"

	"github.com/chainguard-dev/clog"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"
)

// BootDirs is the list of directories to search for kernels.
// This is exported so that callers can append to it as needed.
// Scanning lib/modules and usr/lib/modules is done to make this work
// well for bootc, which suggests sticking kernel images at
// /usr/lib/modules/`uname -r`/vmlinuz.
var BootDirs = []string{"boot/...", "lib/modules/...", "usr/lib/modules/..."}

// ModuleDirs is the list of directories to search for kernel modules.
// This is exported so that callers can append to it as needed.
var ModuleDirs = []string{"usr/lib/modules/...", "lib/modules/..."}

func generateKernelDeps(ctx context.Context, hdl SCAHandle, generated *config.Dependencies, extraLibDirs []string) error {
	log := clog.FromContext(ctx)
	log.Infof("scanning for kernel dependencies...")

	fsys, err := hdl.Filesystem()
	if err != nil {
		return err
	}

	var allKernelDirs []string
	allKernelDirs = append(allKernelDirs, BootDirs...)
	allKernelDirs = append(allKernelDirs, ModuleDirs...)

	kernelVersionRe := regexp.MustCompile(`^[0-9.\-_A-Za-z]+`)

	if err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		fi, err := d.Info()
		if err != nil {
			return err
		}

		mode := fi.Mode()

		if !mode.IsRegular() {
			return nil
		}

		if !isInDir(path, allKernelDirs) {
			return nil
		}

		file, err := fsys.Open(path)
		if err != nil {
			log.Warnf("file open err: %v", err)
			return nil
		}
		defer file.Close()

		seekableFile, ok := file.(io.ReadSeeker)
		if !ok {
			log.Warnf("file %s can't be made seekable, not scanning it", path)
			return nil
		}

		if isInDir(path, BootDirs) {
			ver, err := kernelVersion(ctx, seekableFile)
			if err != nil {
				log.Debugf("%s has no kernel version: %v", path, err)
			} else {
				// 6.12.57-example (amelia-crate@framework-16) (gcc (GCC) 14.3.0, GNU ld (GNU Binutils) 2.44) # SMP
				// -> 6.12.57-example
				ver = kernelVersionRe.FindString(ver)
				generated.Provides = append(generated.Provides, "linux:"+ver)
			}
		}

		if isInDir(path, ModuleDirs) {
			ver, err := moduleVermagic(ctx, seekableFile)
			if err != nil {
				log.Debugf("%s has no vermagic: %v", path, err)
			} else {
				// 6.12.57-example SMP
				// -> 6.12.57-example
				ver = kernelVersionRe.FindString(ver)
				generated.Runtime = append(generated.Runtime, "linux:"+ver)
			}
		}

		return nil
	}); err != nil {
		return err
	}

	return nil
}

// moduleVermagic inspects data for a kernel version string
func moduleVermagic(ctx context.Context, r io.ReadSeeker) (string, error) {
	log := clog.FromContext(ctx)

	var err error
	r, err = tryDecompressModule(ctx, r)
	if err != nil {
		return "", err
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	if v, err := scanStreamForPrefix(r, "vermagic="); err == nil {
		return v, nil
	} else {
		log.Debugf("%v", err)
	}

	return "", errors.New("could not locate vermagic")
}

// tryDecompressModule attempts to extract a module, or returns
// the original data if it's not a supported format.
func tryDecompressModule(ctx context.Context, r io.ReadSeeker) (io.ReadSeeker, error) {
	log := clog.FromContext(ctx)
	// We have to move the offset around to try to read compression headers,
	// so restore it at the end.
	originalOffset, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, err := r.Seek(originalOffset, io.SeekStart)
		if err != nil {
			log.Errorf("failed to restore file offset: %v", err)
		}
	}()

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	// Reader header on NewReader() and returns err if it's not a valid
	// gzip header
	gzr, err := gzip.NewReader(r)
	if err == nil {
		defer gzr.Close()
		b, err := io.ReadAll(gzr)
		if err != nil {
			return nil, err
		}
		log.Debugf("found gzipped module")
		return bytes.NewReader(b), nil
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	xzr, err := xz.NewReader(r)
	if err == nil {
		b, err := io.ReadAll(xzr)
		if err != nil {
			return nil, err
		}
		log.Debugf("found xz module")
		return bytes.NewReader(b), nil
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	// This doesn't read data, we don't know if it's valid zstd data until we read it.
	zstr, err := zstd.NewReader(r)
	if err == nil {
		defer zstr.Close()
		b, err := io.ReadAll(zstr)
		if err == nil {
			log.Debugf("found zstd module")
			return bytes.NewReader(b), nil
		}
	}

	log.Debugf("treating module as uncompressed")
	return r, nil
}

// kernelVersion inspects data for a kernel version string
func kernelVersion(ctx context.Context, r io.ReadSeeker) (string, error) {
	log := clog.FromContext(ctx)

	var err error
	r, err = tryUnwrapKernel(ctx, r)
	if err != nil {
		return "", err
	}

	// 1. Check for x86 boot image header
	// works for x86 bzImage
	ok, err := hasHdrS(r)
	if err == nil && ok {
		if v, err := versionFromBootHeader(r); err == nil {
			log.Debugf("found kernel version from x86 boot image header")
			return v, nil
		} else {
			log.Debugf("%v", err)
		}
	}

	// 2. Fallback: scan stream for "Linux version ".
	// works for pretty much anything else
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	if v, err := scanStreamForPrefix(r, "Linux version "); err == nil {
		log.Debugf("found kernel version from fallback search of uncompressed data")
		return v, nil
	} else {
		log.Debugf("%v", err)
	}

	return "", errors.New("could not locate kernel version")
}

// tryUnwrapKernel attempts to un-compress or extract
// a linux kernel from a data stream. If it does not
// appear to be a known format that needs extracting,
// just returns the original data.
func tryUnwrapKernel(ctx context.Context, r io.ReadSeeker) (io.ReadSeeker, error) {
	log := clog.FromContext(ctx)
	// We have to move the offset around to try to read gzip headers,
	// so restore it at the end.
	originalOffset, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, err := r.Seek(originalOffset, io.SeekStart)
		if err != nil {
			log.Errorf("failed to restore file offset: %v", err)
		}
	}()

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	gzr, err := gzip.NewReader(r)
	if err == nil {
		defer gzr.Close()
		b, err := io.ReadAll(gzr)
		if err != nil {
			return nil, err
		}
		log.Debugf("found gzipped kernel")
		return bytes.NewReader(b), nil
	}

	// If this is a UKI, get the kernel out of it.
	ukir, err := unwrapUKI(r.(io.ReaderAt))
	if err == nil {
		log.Debugf("found kernel in UKI")
		return ukir, nil
	}

	log.Debugf("treating kernel as uncompressed")
	return r, nil
}

// unwrap linux binary from UKI
// format may be bzImage, vmlinux, etc
// whatever the creator put into it
func unwrapUKI(r io.ReaderAt) (io.ReadSeeker, error) {
	uki, err := pe.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer uki.Close()

	linux := uki.Section(".linux")
	if linux == nil {
		return nil, fmt.Errorf("no linux section in uki")
	}

	buf, err := linux.Data()
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(buf), nil
}

// hasHdrS checks for "HdrS" at offset 514, indicating that this is an x86 bzImage.
func hasHdrS(r io.ReadSeeker) (bool, error) {
	if _, err := r.Seek(514, io.SeekStart); err != nil {
		return false, err
	}
	buf := make([]byte, 4)
	n, err := io.ReadFull(r, buf)
	if n < 4 || err != nil {
		return false, nil
	}
	return bytes.Equal(buf, []byte("HdrS")), nil
}

// versionFromBootHeader implements the libmagic logic:
//
// >>>526 uleshort >0
// >>>>(526.s+0x200) string >\0 version %s,
//
// i.e. kernel_version is a 16-bit pointer; version string is at
// offset (kernel_version + 0x200), null-terminated.
// See https://github.com/file/file/blob/a05f89f6ec8e8af9bdfcab9ec3a4ae833925e764/magic/Magdir/linux
//
// This only works for x86 bzImage
func versionFromBootHeader(r io.ReadSeeker) (string, error) {
	if _, err := r.Seek(526, io.SeekStart); err != nil {
		return "", err
	}
	ptrBytes := make([]byte, 2)
	if _, err := io.ReadFull(r, ptrBytes); err != nil {
		return "", err
	}
	ptr := binary.LittleEndian.Uint16(ptrBytes)
	if ptr == 0 {
		return "", errors.New("kernel_version pointer is zero")
	}

	abs := int64(ptr) + 0x200
	if abs < 0 {
		return "", fmt.Errorf("kernel_version pointer out of range: 0x%x -> %d", ptr, abs)
	}

	// Seek to version string
	if _, err := r.Seek(abs, io.SeekStart); err != nil {
		return "", err
	}

	// Read until NUL or newline
	var out []byte
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if len(buf) < 1 || n == 0 || errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if buf[0] == 0 || buf[0] == '\n' {
			break
		}
		out = append(out, buf[0])
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "", fmt.Errorf("empty version string in boot header")
	}
	return s, nil
}

// scanStreamForPrefix scans a data stream for the prefix and returns
// the rest of the string, terminated by \n or EOF.
func scanStreamForPrefix(r io.Reader, prefix string) (string, error) {
	br := bufio.NewReader(r)

	var window []byte

	for {
		// Read byte.
		b, err := br.ReadByte()
		if errors.Is(err, io.EOF) {
			return "", fmt.Errorf("%q not found", prefix)
		}
		if err != nil {
			return "", err
		}

		// Shift window to the right if it's greater than prefix.
		window = append(window, b)
		if len(window) > len(prefix) {
			window = window[1:]
		}

		if string(window) == prefix {
			// Collect rest of line
			var out []byte
			for {
				c, err := br.ReadByte()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					return "", err
				}
				if c == 0 || c == '\n' {
					break
				}
				out = append(out, c)
			}
			s := strings.TrimSpace(string(out))
			if s == "" {
				return "", fmt.Errorf("empty %q line", prefix)
			}
			return s, nil
		}
	}
}
