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
package sign

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"chainguard.dev/apko/pkg/apk/expandapk"
	"chainguard.dev/apko/pkg/apk/signature"
)

// APK() signs an APK file with the provided key. The existing APK file is
// replaced with the signed APK file.
func APK(_ context.Context, apkPath string, keyPath string) error {
	f, err := os.Open(apkPath) // #nosec G304 - User-specified APK package for signing
	if err != nil {
		return err
	}
	defer f.Close()

	split, err := expandapk.Split(f)
	if err != nil {
		return fmt.Errorf("splitting apk: %w", err)
	}

	cf, df := split[0], split[1]
	if len(split) == 3 {
		// signature section is present
		cf, df = split[1], split[2]
	}

	signer := KeyApkSigner{
		KeyFile:       keyPath,
		KeyPassphrase: "",
	}

	cdata, err := io.ReadAll(cf)
	if err != nil {
		return err
	}

	// Reading and writing to the same file seems risky, so we create a temp file.
	tmpData, err := os.CreateTemp("", "melange-sign-data-section-tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmpData.Name())

	if _, err := io.Copy(tmpData, df); err != nil {
		return err
	}
	if _, err := tmpData.Seek(0, 0); err != nil {
		return err
	}

	// Pull the modtime out of the .PKGINFO
	r := bytes.NewReader(cdata)
	zr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)
	hdr, err := tr.Next()
	if err != nil {
		return err
	}
	if hdr.Name != ".PKGINFO" {
		return fmt.Errorf("unexpected file in control section: %s", hdr.Name)
	}

	sigData, err := EmitSignature(signer, cdata, hdr.ModTime)
	if err != nil {
		return err
	}

	w, err := os.Create(apkPath) // #nosec G304 - Writing signed APK package
	if err != nil {
		return err
	}

	// Replace the package file with the new one
	for _, fp := range []io.Reader{bytes.NewReader(sigData), bytes.NewReader(cdata), tmpData} {
		if _, err := io.Copy(w, fp); err != nil {
			return err
		}
	}

	return w.Close()
}

type ApkSigner interface {
	Sign(controlData []byte) ([]byte, error)
	SignatureName() string
}

func EmitSignature(signer ApkSigner, controlData []byte, sde time.Time) ([]byte, error) {
	sig, err := signer.Sign(controlData)
	if err != nil {
		return nil, err
	}

	var sigbuf bytes.Buffer

	zw := gzip.NewWriter(&sigbuf)
	tw := tar.NewWriter(zw)

	// The signature tarball only contains a single file
	if err := tw.WriteHeader(&tar.Header{
		Name:     signer.SignatureName(),
		Typeflag: tar.TypeReg,
		Size:     int64(len(sig)),
		Mode:     int64(0o644),
		Uid:      0,
		Gid:      0,
		Uname:    "root",
		Gname:    "root",
		ModTime:  sde,
	}); err != nil {
		return nil, err
	}

	if _, err := tw.Write(sig); err != nil {
		return nil, err
	}

	// Don't Close(), we don't want to include the end-of-archive markers since this signature gets prepended to other tarballs
	if err := tw.Flush(); err != nil {
		return nil, err
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}

	return sigbuf.Bytes(), nil
}

// Key base signature (normal) uses a SHA-1 hash on the control digest.
type KeyApkSigner struct {
	KeyFile       string
	KeyPassphrase string
}

func (s KeyApkSigner) Sign(control []byte) ([]byte, error) {
	controlDigest, err := HashData(control, crypto.SHA256)
	if err != nil {
		return nil, err
	}
	return signature.RSASignDigest(controlDigest, crypto.SHA256, s.KeyFile, s.KeyPassphrase)
}

func (s KeyApkSigner) SignatureName() string {
	return fmt.Sprintf(".SIGN.RSA256.%s.pub", filepath.Base(s.KeyFile))
}
