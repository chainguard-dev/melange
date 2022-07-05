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

package cli

import (
	"bytes"
	"context"
	"crypto/sha1" // nolint:gosec
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"chainguard.dev/apko/pkg/tarball"
	"chainguard.dev/melange/internal/sign"
	"github.com/psanford/memfs"
	"github.com/spf13/cobra"
)

func SignIndex() *cobra.Command {
	var signingKey string

	cmd := &cobra.Command{
		Use:     "sign-index",
		Short:   "Sign an APK index",
		Long:    `Sign an APK index.`,
		Example: `  melange sign-index [--signing-key=key.rsa] <APKINDEX.tar.gz>`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return SignIndexCmd(cmd.Context(), signingKey, args[0])
		},
	}

	cmd.Flags().StringVar(&signingKey, "signing-key", "melange.rsa", "the signing key to use")

	return cmd
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

func SignIndexCmd(ctx context.Context, signingKey string, indexFile string) error {
	log.Printf("signing index %s with key %s", indexFile, signingKey)

	indexData, indexDigest, err := readAndHashIndex(indexFile)
	if err != nil {
		return err
	}

	sigData, err := sign.RSASignSHA1Digest(indexDigest, signingKey, "")
	if err != nil {
		return fmt.Errorf("unable to sign index: %w", err)
	}

	log.Printf("appending signature to index %s", indexFile)

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

	log.Printf("writing signed index to %s", indexFile)

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

	log.Printf("signed index %s with key %s", indexFile, signingKey)

	return nil
}
