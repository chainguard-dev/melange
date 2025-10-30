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

func StrippedLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	var unstrippedBinaries []string

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
			// Don't worry about non-files
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if info.Size() < int64(len(ElfMagic)) {
			// This is definitely not an ELF file.
			return nil
		}

		ext := filepath.Ext(path)
		mode := info.Mode()
		if mode&0o111 == 0 && !IsObjectFileRegex.MatchString(ext) {
			// Not an executable or library
			return nil
		}

		f, err := fsys.Open(path)
		if err != nil {
			return fmt.Errorf("opening file: %w", err)
		}
		defer f.Close()

		// Both os.DirFS and go-apk return a file that implements ReaderAt.
		// We don't have any other callers, so this should never fail.
		readerAt, ok := f.(io.ReaderAt)
		if !ok {
			return fmt.Errorf("fs.File does not impl ReaderAt: %T", f)
		}

		hdr := make([]byte, len(ElfMagic))
		if _, err := readerAt.ReadAt(hdr, 0); err != nil {
			return fmt.Errorf("failed to read %d bytes for magic ELF header: %w", len(ElfMagic), err)
		}

		if !bytes.Equal(ElfMagic, hdr) {
			// No magic header, definitely not ELF.
			return nil
		}

		file, err := elf.NewFile(readerAt)
		if err != nil {
			return fmt.Errorf("could not open file %q as executable: %w", path, err)
		}
		defer file.Close()

		// No debug sections allowed
		if file.Section(".debug") != nil || file.Section(".zdebug") != nil {
			unstrippedBinaries = append(unstrippedBinaries, path)
		}
		return nil
	})
	if err != nil {
		return err
	}

	if len(unstrippedBinaries) > 0 {
		details := &types.UnstrippedBinaryDetails{
			Binaries: unstrippedBinaries,
		}

		binaryWord := "binary"
		if len(unstrippedBinaries) > 1 {
			binaryWord = "binaries"
		}
		message := fmt.Sprintf("%s contains %d unstripped %s", pkgname, len(unstrippedBinaries), binaryWord)
		return types.NewStructuredError(message, details)
	}

	return nil
}
