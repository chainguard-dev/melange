// Copyright 2024 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package apk

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"chainguard.dev/melange/pkg/build"
	"github.com/chainguard-dev/go-apk/pkg/expandapk"
)

// Sign() signs an APK file with the provided key. The existing APK file is
// replaced with the signed APK file.
func Sign(ctx context.Context, apkPath string, keyPath string) error {
	apkr, err := os.Open(apkPath)
	if err != nil {
		return err
	}

	eapk, err := expandapk.ExpandApk(ctx, apkr, "")
	if err != nil {
		return fmt.Errorf("expanding apk: %w", err)
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
	defer cf.Close()

	// Use the control sections ModTime (set to SDE) for the signature
	cfinfo, err := os.Stat(eapk.ControlFile)
	if err != nil {
		return err
	}

	pc := &build.PackageBuild{
		Build: &build.Build{
			SigningKey:        keyPath,
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
	defer df.Close()

	// Replace the package file with the new one
	f, err := os.Create(apkPath)
	if err != nil {
		return err
	}
	defer f.Close()

	for _, fp := range []io.Reader{bytes.NewBuffer(sigData), cf, df} {
		if _, err := io.Copy(f, fp); err != nil {
			return err
		}
	}

	return nil
}
