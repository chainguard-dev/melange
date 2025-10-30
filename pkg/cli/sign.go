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
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/chainguard-dev/clog"
	"github.com/klauspost/compress/gzip"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"chainguard.dev/melange/pkg/sign"
)

type signIndexOpts struct {
	Key   string
	Force bool
}

func signIndex() *cobra.Command {
	o := &signIndexOpts{}

	cmd := &cobra.Command{
		Use:   "sign-index",
		Short: "Sign an APK index",
		Long:  `Sign an APK index.`,
		Example: `
    # Re-sign an index with the same signature
    melange sign-index [--signing-key=key.rsa] <APKINDEX.tar.gz>

    # Sign a new index with a new signature
    melange sign-index [--signing-key=key.rsa] <APKINDEX.tar.gz> --force
    `,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.SignIndex(cmd.Context(), args[0])
		},
	}

	cmd.Flags().StringVar(&o.Key, "signing-key", "melange.rsa", "the signing key to use")
	cmd.Flags().BoolVarP(&o.Force, "force", "f", false, "when toggled, overwrites the specified index with a new index using the provided signature")

	return cmd
}

func (o signIndexOpts) SignIndex(ctx context.Context, indexFile string) error {
	log := clog.FromContext(ctx)
	if !o.Force {
		return sign.SignIndex(ctx, o.Key, indexFile)
	}

	idx, err := parseIndexWithoutSignature(ctx, indexFile)
	if err != nil {
		return err
	}

	t, err := os.Create(fmt.Sprintf("%s.new", indexFile))
	if err != nil {
		return err
	}

	if _, err := t.Write(idx); err != nil {
		return err
	}

	if err := t.Sync(); err != nil {
		return err
	}

	if _, err := t.Seek(0, io.SeekStart); err != nil {
		return err
	}

	if err := sign.SignIndex(ctx, o.Key, t.Name()); err != nil {
		return err
	}

	log.Infof("Replacing existing signed index (%s) with signed index with key %s", indexFile, o.Key)
	return os.Rename(t.Name(), indexFile)
}

// parseIndexWithoutSignature takes in an index file and returns the unsigned []byte representation of it
func parseIndexWithoutSignature(_ context.Context, indexFile string) ([]byte, error) {
	orig, err := os.Open(indexFile) // #nosec G304 - User-specified APK index file for signing
	if err != nil {
		return nil, err
	}
	defer orig.Close()

	gr, err := gzip.NewReader(orig)
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	var nb bytes.Buffer

	gw := gzip.NewWriter(&nb)
	tw := tar.NewWriter(gw)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if hdr.Name == "DESCRIPTION" || hdr.Name == "APKINDEX" {
			if err := tw.WriteHeader(hdr); err != nil {
				return nil, err
			}
			// #nosec G110 - Copying specific known files from trusted APK index
			if _, err := io.Copy(tw, tr); err != nil {
				return nil, err
			}
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}

	return nb.Bytes(), nil
}

type signOpts struct {
	Key string
}

func signCmd() *cobra.Command {
	o := &signOpts{}

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign an APK package",
		Long:  "Signs an APK package on disk with the provided key. The package is replaced with the APK containing the new signature.",
		Example: `
		melange sign [--signing-key=key.rsa] package.apk

		melange sign [--signing-key=key.rsa] *.apk
		`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return o.RunAllE(ctx, args...)
		},
	}

	cmd.Flags().StringVarP(&o.Key, "signing-key", "k", "local-melange.rsa", "The signing key to use.")

	return cmd
}

func (o signOpts) RunAllE(ctx context.Context, pkgs ...string) error {
	g, ctx := errgroup.WithContext(ctx)

	for _, pkg := range pkgs {
		p := pkg

		g.Go(func() error {
			return o.run(ctx, p)
		})
	}
	return g.Wait()
}

func (o signOpts) run(ctx context.Context, pkg string) error {
	clog.FromContext(ctx).Infof("Processing apk %s", pkg)
	return sign.APK(ctx, pkg, o.Key)
}
