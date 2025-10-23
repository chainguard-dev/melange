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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"chainguard.dev/melange/pkg/config"
	"chainguard.dev/melange/pkg/license"
	"chainguard.dev/melange/pkg/linter/types"
	"github.com/dustin/go-humanize"
)

type duplicateInfo struct {
	paths []string
	size  int64
}

func DuplicateLinter(ctx context.Context, _ *config.Configuration, pkgname string, fsys fs.FS) error {
	type fileKey struct {
		hash     string
		basename string
	}
	filesByKey := make(map[fileKey]*duplicateInfo)

	const minFileSizeBytes = 1024 // 1 KB

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err != nil {
			return err
		}

		if d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		basename := filepath.Base(path)

		if isLicense, _ := license.IsLicenseFile(path, true); isLicense {
			return nil
		}

		if info.Size() < minFileSizeBytes {
			return nil
		}

		f, err := fsys.Open(path)
		if err != nil {
			return fmt.Errorf("opening file %s: %w", path, err)
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return fmt.Errorf("hashing file %s: %w", path, err)
		}

		hash := hex.EncodeToString(h.Sum(nil))
		key := fileKey{hash: hash, basename: basename}

		if existing, found := filesByKey[key]; found {
			existing.paths = append(existing.paths, path)
		} else {
			filesByKey[key] = &duplicateInfo{
				paths: []string{path},
				size:  info.Size(),
			}
		}

		return nil
	})

	if err != nil {
		return err
	}

	type duplicateSet struct {
		count    int
		size     int64
		wasted   int64
		paths    []string
		basename string
	}

	var duplicateSets []duplicateSet
	var totalWasted int64

	for key, info := range filesByKey {
		if len(info.paths) > 1 {
			slices.Sort(info.paths)

			wasted := int64(len(info.paths)-1) * info.size
			totalWasted += wasted

			duplicateSets = append(duplicateSets, duplicateSet{
				count:    len(info.paths),
				size:     info.size,
				wasted:   wasted,
				paths:    info.paths,
				basename: key.basename,
			})
		}
	}

	if len(duplicateSets) > 0 {
		slices.SortFunc(duplicateSets, func(a, b duplicateSet) int {
			if a.wasted > b.wasted {
				return -1
			} else if a.wasted < b.wasted {
				return 1
			}
			return 0
		})

		// Build structured details
		duplicates := make([]*types.DuplicateFileInfo, 0, len(duplicateSets))
		for _, ds := range duplicateSets {
			duplicates = append(duplicates, &types.DuplicateFileInfo{
				Basename:    ds.basename,
				Count:       ds.count,
				SizeBytes:   ds.size,
				Size:        humanize.Bytes(uint64(ds.size)),
				WastedBytes: ds.wasted,
				WastedSize:  humanize.Bytes(uint64(ds.wasted)),
				Paths:       ds.paths,
			})
		}

		details := &types.DuplicateFilesDetails{
			TotalDuplicateSets: len(duplicateSets),
			TotalWastedBytes:   totalWasted,
			TotalWastedSize:    humanize.Bytes(uint64(totalWasted)),
			Duplicates:         duplicates,
		}

		// Build human-readable message for logs
		var output []string
		for _, ds := range duplicateSets {
			output = append(output, fmt.Sprintf(
				"  %d copies of '%s' (%s each, wasting %s):",
				ds.count,
				ds.basename,
				humanize.Bytes(uint64(ds.size)),
				humanize.Bytes(uint64(ds.wasted)),
			))

			for _, p := range ds.paths {
				output = append(output, "    "+p)
			}
		}

		summary := fmt.Sprintf("%s contains %d duplicate file(s) with same name in different directories (wasting %s total)", pkgname, len(duplicateSets), humanize.Bytes(uint64(totalWasted)))
		message := fmt.Sprintf("%s:\n%s", summary, strings.Join(output, "\n"))

		return types.NewStructuredError(message, details)
	}

	return nil
}
