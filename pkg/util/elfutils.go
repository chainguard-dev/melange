// Copyright 2026 Chainguard, Inc.
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

// Utilities to read and manipulate ELF files.

package util

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// align4 computes the padding size for a 4-byte aligned field of size
// N.
func align4(n uint32) uint32 {
	return (n + 3) &^ 3
}

// Representation of the contents of a note inside an ELF note
// section.
//
// A section may contain multiple notes, each one laid out in the
// following format:
//
//	+----------+ <-----+
//	|  namesz  |       |
//	+----------+       |
//	|  descsz  |       |  Header
//	+----------+       |
//	|   type   |       |
//	+----------+ <-----+
//	|   name   |
//	+----------+
//	|   type   |
//	+----------+
//
// We don't store "namesz" nor "descsz" in this struct.
type ELFNote struct {
	Name        string
	Type        uint32
	Description string
}

// Read the contents of the note(s) inside an ELF section.
func ReadElfNotes(section *elf.Section, byteOrder binary.ByteOrder) ([]ELFNote, error) {
	if section.Type != elf.SHT_NOTE {
		return nil, fmt.Errorf("invalid ELF section type")
	}

	data, err := section.Data()
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(data)

	notes := []ELFNote{}

	for reader.Len() > 0 {
		// Read the note header.  It's composed of the name
		// size, description size and note type.
		var namesz, descsz, noteType uint32

		if err := binary.Read(reader, byteOrder, &namesz); err != nil {
			return nil, err
		}
		if int(namesz) > reader.Len() || namesz > 256 {
			return nil, fmt.Errorf("namesz is too big on section %s", section.Name)
		}

		if err := binary.Read(reader, byteOrder, &descsz); err != nil {
			return nil, err
		}
		if int(descsz) > reader.Len() || descsz > 8192 {
			return nil, fmt.Errorf("descsz is too big on section %s", section.Name)
		}

		if err := binary.Read(reader, byteOrder, &noteType); err != nil {
			return nil, err
		}

		// Read the note name.
		name := make([]byte, namesz)
		_, err := reader.Read(name)
		if err != nil {
			return nil, err
		}
		// The note name is 4-byte aligned, so we have to
		// calculate the padding size and skip it.
		if _, err := reader.Seek(int64(align4(namesz)-namesz), io.SeekCurrent); err != nil {
			return nil, err
		}

		// Read the note description.
		desc := make([]byte, descsz)
		_, err = reader.Read(desc)
		if err != nil {
			return nil, err
		}
		// The note description is 4-byte aligned, so we have
		// to calculate the padding size and skip it.
		if _, err := reader.Seek(int64(align4(descsz)-descsz), io.SeekCurrent); err != nil {
			return nil, err
		}

		notes = append(notes, ELFNote{
			Name:        string(bytes.TrimRight(name, "\x00")),
			Type:        noteType,
			Description: string(bytes.TrimRight(desc, "\x00")),
		})
	}

	return notes, nil
}

// Representation of a dlopen dependency as seen in the JSON contents
// inside the note description.
//
// See https://uapi-group.org/specifications/specs/elf_dlopen_metadata/
// for the official specification of the format.
type DlopenDependency struct {
	SOname      []string `json:"soname"`
	Feature     string   `json:"feature,omitempty"`
	Description string   `json:"description,omitempty"`
	Priority    string   `json:"priority,omitempty"`
}

// Implementation of the UnmarshallJSON interface for a
// DlopenDependency.
func (d *DlopenDependency) UnmarshallJSON(data []byte) error {
	// Doing some type aliasing trick to avoid infinite recursion.
	type DlopenAlias DlopenDependency
	rawData := &struct {
		*DlopenAlias
	}{
		DlopenAlias: (*DlopenAlias)(d),
	}

	if err := json.Unmarshal(data, &rawData); err != nil {
		return err
	}

	if rawData.Priority == "" {
		d.Priority = "recommended"
	}

	return nil
}
