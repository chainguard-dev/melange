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

package linters

import (
	"bytes"
	"context"
	"debug/elf"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/linter/types"
)

func BinaryArchLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	var unsupportedBinaries []types.BinaryArchInfo

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}
		if IsIgnoredPath(path) {
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if info.Size() < int64(len(ElfMagic)) {
			return nil
		}

		ext := filepath.Ext(path)
		mode := info.Mode()
		if mode&0o111 == 0 && !IsObjectFileRegex.MatchString(ext) {
			return nil
		}

		f, err := fsys.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()

		readerAt, ok := f.(io.ReaderAt)
		if !ok {
			return nil
		}

		hdr := make([]byte, len(ElfMagic))
		if _, err := readerAt.ReadAt(hdr, 0); err != nil {
			return nil
		}

		if !bytes.Equal(ElfMagic, hdr) {
			return nil
		}

		elfFile, err := elf.NewFile(readerAt)
		if err != nil {
			return nil
		}
		defer elfFile.Close()

		var archName string
		switch elfFile.Machine {
		case elf.EM_X86_64:
			archName = "amd64"
		case elf.EM_AARCH64:
			archName = "arm64"
		case elf.EM_386:
			archName = "i386"
		case elf.EM_ARM:
			archName = "arm"
		case elf.EM_PPC64:
			archName = "ppc64"
		case elf.EM_S390:
			archName = "s390"
		case elf.EM_MIPS:
			archName = "mips"
		case elf.EM_RISCV:
			archName = "riscv"
		default:
			archName = fmt.Sprintf("unknown (%v)", elfFile.Machine)
		}

		if elfFile.Machine != elf.EM_X86_64 && elfFile.Machine != elf.EM_AARCH64 {
			unsupportedBinaries = append(unsupportedBinaries, types.BinaryArchInfo{
				Path: path,
				Arch: archName,
			})
		}

		return nil
	})
	if err != nil {
		return err
	}

	if len(unsupportedBinaries) > 0 {
		details := &types.BinaryArchDetails{
			Binaries: unsupportedBinaries,
		}

		binaryWord := "binary"
		if len(unsupportedBinaries) > 1 {
			binaryWord = "binaries"
		}
		message := fmt.Sprintf("%s contains %d %s compiled for unsupported architecture(s)", pkgname, len(unsupportedBinaries), binaryWord)
		return types.NewStructuredError(message, details)
	}

	return nil
}
