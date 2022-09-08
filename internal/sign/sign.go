// Copyright 2022 Chainguard, Inc.
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

package sign

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1" // nolint:gosec
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"chainguard.dev/apko/pkg/tarball"
	"github.com/psanford/memfs"
)

// TODO: solidify this API and move into pkg/
func SignIndex(logger *log.Logger, signingKey string, indexFile string) error {
	if indexIsAlreadySigned(indexFile) {
		logger.Printf("index %s is already signed, doing nothing", indexFile)
		return nil
	}

	logger.Printf("signing index %s with key %s", indexFile, signingKey)

	indexData, indexDigest, err := readAndHashIndex(indexFile)
	if err != nil {
		return err
	}

	sigData, err := RSASignSHA1Digest(indexDigest, signingKey, "")
	if err != nil {
		return fmt.Errorf("unable to sign index: %w", err)
	}

	logger.Printf("appending signature to index %s", indexFile)

	sigFS := memfs.New()
	if err := sigFS.WriteFile(fmt.Sprintf(".SIGN.RSA.%s.pub", filepath.Base(signingKey)), sigData, 0644); err != nil {
		return fmt.Errorf("unable to append signature: %w", err)
	}

	// prepare control.tar.gz
	multitarctx, err := tarball.NewContext(
		tarball.WithOverrideUIDGID(0, 0),
		tarball.WithOverrideUname("root"),
		tarball.WithOverrideGname("root"),
		tarball.WithSkipClose(true),
	)
	if err != nil {
		return fmt.Errorf("unable to build tarball context: %w", err)
	}

	logger.Printf("writing signed index to %s", indexFile)

	var sigBuffer bytes.Buffer
	if err := multitarctx.WriteArchive(&sigBuffer, sigFS); err != nil {
		return fmt.Errorf("unable to write signature tarball: %w", err)
	}

	idx, err := os.Create(indexFile)
	if err != nil {
		return fmt.Errorf("unable to open index for writing: %w", err)
	}
	defer idx.Close()

	if _, err := io.Copy(idx, &sigBuffer); err != nil {
		return fmt.Errorf("unable to write index signature: %w", err)
	}

	if _, err := idx.Write(indexData); err != nil {
		return fmt.Errorf("unable to write index data: %w", err)
	}

	logger.Printf("signed index %s with key %s", indexFile, signingKey)

	return nil
}

func indexIsAlreadySigned(indexFile string) bool {
	index, err := os.Open(indexFile)
	if err != nil {
		log.Fatalf("cannot open index %s: %v", indexFile, err)
	}
	defer index.Close()

	gzi, err := gzip.NewReader(index)
	if err != nil {
		log.Fatalf("cannot open index %s: %v", indexFile, err)
	}
	defer gzi.Close()

	tari := tar.NewReader(gzi)
	for {
		hdr, err := tari.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("cannot read index %s: %v", indexFile, err)
		}

		if strings.HasPrefix(hdr.Name, ".SIGN.RSA") {
			return true
		}
	}

	return false
}

func readAndHashIndex(indexFile string) ([]byte, []byte, error) {
	index, err := os.Open(indexFile)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to open index for signing: %w", err)
	}
	defer index.Close()

	digest := sha1.New() // nolint:gosec
	hasher := io.TeeReader(index, digest)
	indexBuf, err := io.ReadAll(hasher)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read index: %w", err)
	}

	return indexBuf, digest.Sum(nil), nil
}
