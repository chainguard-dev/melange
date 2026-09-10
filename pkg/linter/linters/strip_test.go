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
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chainguard-dev/clog/slogtest"
)

// elfWithSections builds a minimal little-endian ELF64 executable whose
// section header table names exactly the given sections (plus the mandatory
// null section and .shstrtab). Every named section is zero-length: the linter
// keys off a section's presence, not its contents, so this keeps the fixture
// small enough to read.
func elfWithSections(names ...string) []byte {
	const (
		ehsize    = 64
		shentsize = 64
	)

	// Section header string table: a leading NUL, then each name NUL-terminated.
	var shstrtab []byte
	offsets := make([]uint32, 0, len(names)+1)
	shstrtab = append(shstrtab, 0)
	for _, n := range append(names, ".shstrtab") {
		offsets = append(offsets, uint32(len(shstrtab)))
		shstrtab = append(shstrtab, n...)
		shstrtab = append(shstrtab, 0)
	}

	shstrtabOff := uint64(ehsize)
	shoff := shstrtabOff + uint64(len(shstrtab))
	// One header per named section, plus the null header and .shstrtab's own.
	shnum := len(names) + 2

	buf := make([]byte, shoff+uint64(shnum*shentsize))

	// ELF header.
	copy(buf, ElfMagic)
	buf[4] = byte(elf.ELFCLASS64)
	buf[5] = byte(elf.ELFDATA2LSB)
	buf[6] = byte(elf.EV_CURRENT)
	le := binary.LittleEndian
	le.PutUint16(buf[16:], uint16(elf.ET_EXEC))
	le.PutUint16(buf[18:], uint16(elf.EM_X86_64))
	le.PutUint32(buf[20:], uint32(elf.EV_CURRENT))
	le.PutUint64(buf[40:], shoff)
	le.PutUint16(buf[52:], ehsize)
	le.PutUint16(buf[58:], shentsize)
	le.PutUint16(buf[60:], uint16(shnum))
	le.PutUint16(buf[62:], uint16(shnum-1)) // .shstrtab is last

	copy(buf[shstrtabOff:], shstrtab)

	// Section headers. Index 0 is the null section, left zeroed.
	putHeader := func(idx int, nameOff uint32, typ elf.SectionType, off, size uint64) {
		h := buf[shoff+uint64(idx*shentsize):]
		le.PutUint32(h[0:], nameOff)
		le.PutUint32(h[4:], uint32(typ))
		le.PutUint64(h[24:], off)
		le.PutUint64(h[32:], size)
	}
	for i := range names {
		putHeader(i+1, offsets[i], elf.SHT_PROGBITS, 0, 0)
	}
	putHeader(shnum-1, offsets[len(names)], elf.SHT_STRTAB, shstrtabOff, uint64(len(shstrtab)))

	return buf
}

func TestStrippedLinter(t *testing.T) {
	for _, tt := range []struct {
		name    string
		path    string
		mode    os.FileMode
		content []byte
		want    bool // want the file reported as unstripped
	}{{
		// The regression this test exists for: real DWARF is .debug_info and
		// friends, never a bare ".debug", so an exact-name lookup missed it.
		name:    "dwarf sections are unstripped",
		path:    "usr/bin/dwarf",
		mode:    0o755,
		content: elfWithSections(".text", ".debug_info", ".debug_str", ".debug_line"),
		want:    true,
	}, {
		name:    "compressed dwarf is unstripped",
		path:    "usr/bin/zdwarf",
		mode:    0o755,
		content: elfWithSections(".text", ".zdebug_info"),
		want:    true,
	}, {
		// The only shape the old exact-name check caught; keep catching it.
		name:    "legacy bare .debug is unstripped",
		path:    "usr/bin/legacy",
		mode:    0o755,
		content: elfWithSections(".text", ".debug"),
		want:    true,
	}, {
		name:    "legacy bare .zdebug is unstripped",
		path:    "usr/bin/legacyz",
		mode:    0o755,
		content: elfWithSections(".text", ".zdebug"),
		want:    true,
	}, {
		name:    "stripped binary passes",
		path:    "usr/bin/clean",
		mode:    0o755,
		content: elfWithSections(".text", ".rodata", ".symtab"),
		want:    false,
	}, {
		// Not executable, but an object file, so still inspected.
		name:    "unstripped shared object is caught",
		path:    "usr/lib/libfoo.so",
		mode:    0o644,
		content: elfWithSections(".text", ".debug_abbrev"),
		want:    true,
	}, {
		name:    "non-elf file is skipped",
		path:    "usr/bin/script",
		mode:    0o755,
		content: []byte("#!/bin/sh\necho .debug_info\n"),
		want:    false,
	}, {
		// Neither executable nor an object file.
		name:    "non-executable non-object is skipped",
		path:    "usr/share/foo/data",
		mode:    0o644,
		content: elfWithSections(".debug_info"),
		want:    false,
	}, {
		name:    "sbom paths are ignored",
		path:    "var/lib/db/sbom/foo.json",
		mode:    0o755,
		content: elfWithSections(".debug_info"),
		want:    false,
	}} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := slogtest.Context(t)
			dir := t.TempDir()
			full := filepath.Join(dir, tt.path)
			if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
			if err := os.WriteFile(full, tt.content, tt.mode); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			err := StrippedLinter(ctx, nil, "test-pkg", os.DirFS(dir))
			if tt.want {
				if err == nil {
					t.Fatal("StrippedLinter returned nil, want an unstripped-binary error")
				}
				if !strings.Contains(err.Error(), "unstripped") {
					t.Errorf("error = %q, want it to mention unstripped", err)
				}
				if !strings.Contains(err.Error(), "test-pkg") {
					t.Errorf("error = %q, want it to name the package", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("StrippedLinter = %v, want nil", err)
			}
		})
	}
}

// TestStrippedLinterFixtureIsParseable guards the hand-built ELF: if
// debug/elf cannot read it, every case above would pass for the wrong reason.
func TestStrippedLinterFixtureIsParseable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bin")
	if err := os.WriteFile(path, elfWithSections(".text", ".debug_info"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer f.Close()

	for _, want := range []string{".text", ".debug_info", ".shstrtab"} {
		if f.Section(want) == nil {
			got := make([]string, 0, len(f.Sections))
			for _, s := range f.Sections {
				got = append(got, s.Name)
			}
			t.Errorf("section %q missing; fixture has %v", want, got)
		}
	}
}
