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
	"fmt"
	"io"
	"log"
	"os"

	"chainguard.dev/melange/pkg/build"
	"github.com/chainguard-dev/go-apk/pkg/apk"
	sign "github.com/chainguard-dev/go-apk/pkg/signature"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

// SignIndex is a constructor that returns a cobra.Command which wraps the SignIndexCmd() function.
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

// SignIndexCmd is the backend implementation of the "melange sign-index" command.
func SignIndexCmd(ctx context.Context, signingKey string, indexFile string) error {
	return sign.SignIndex(ctx, LogDefault(), signingKey, indexFile)
}

type signOpts struct {
	Key string

	logger *log.Logger
}

func Sign() *cobra.Command {
	o := &signOpts{
		logger: log.New(log.Writer(), "melange-sign: ", log.LstdFlags|log.Lmsgprefix),
	}

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

	if err := g.Wait(); err != nil {
		return err
	}

	return nil
}

func (o signOpts) run(ctx context.Context, pkg string) error {
	o.logger.Printf("Processing apk %s", pkg)

	apkr, err := os.Open(pkg)
	if err != nil {
		return err
	}

	eapk, err := apk.ExpandApk(ctx, apkr, "")
	if err != nil {
		return fmt.Errorf("expanding apk: %v", err)
	}
	defer eapk.Close()

	if err := apkr.Close(); err != nil {
		return err
	}

	// Split the streams and then rebuild
	cf, err := os.Open(eapk.ControlFile)
	if err != nil {
		return err
	}

	// Use the control sections ModTime (set to SDE) for the signature
	cfinfo, err := os.Stat(eapk.ControlFile)
	if err != nil {
		return err
	}

	pc := &build.PackageBuild{
		Build: &build.Build{
			SigningKey:        o.Key,
			SigningPassphrase: "",
		},
	}

	cdata, err := os.ReadFile(eapk.ControlFile)
	if err != nil {
		return err
	}

	sigData, err := build.EmitSignature(ctx, pc.Signer(), cdata, cfinfo.ModTime())
	if err != nil {
		return err
	}

	df, err := os.Open(eapk.PackageFile)
	if err != nil {
		return err
	}

	tf, err := os.CreateTemp("", "melange-signer")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tf.Name())

	for _, fp := range []io.Reader{bytes.NewBuffer(sigData), cf, df} {
		if _, err := io.Copy(tf, fp); err != nil {
			return err
		}
	}

	if err := tf.Sync(); err != nil {
		return err
	}

	if _, err := tf.Seek(0, io.SeekStart); err != nil {
		return err
	}

	// Replace the package file with the new one
	f, err := os.Create(pkg)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, tf); err != nil {
		return err
	}

	return nil
}
