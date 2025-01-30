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
	"strings"
	"testing"

	"chainguard.dev/apko/pkg/apk/expandapk"
	"chainguard.dev/apko/pkg/apk/signature"
)

const (
	testAPK     = "testdata/test.apk"
	testPubkey  = "test.pem.pub"
	testPrivKey = "test.pem"
)

func TestAPK(t *testing.T) {
	tmpDir := t.TempDir()
	ctx := context.Background()
	apkPath := tmpDir + "/out.apk"

	// copy testdata/test.apk to tmpDir
	if err := CopyFile(testAPK, apkPath); err != nil {
		t.Fatal(err)
	}
	// sign the apk
	if err := APK(ctx, apkPath, "testdata/"+testPrivKey); err != nil {
		t.Fatal(err)
	}
	// verify the signature
	controlData, sigName, sig, err := parseAPK(ctx, apkPath)
	if err != nil {
		t.Fatal(err)
	}
	if sigName != ".SIGN.RSA256."+testPubkey {
		t.Fatalf("unexpected signature name %s", sigName)
	}
	digest, err := signature.HashData(controlData, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := os.ReadFile("testdata/" + testPubkey)
	if err != nil {
		t.Fatal(err)
	}
	if err := signature.RSAVerifyDigest(digest, crypto.SHA256, sig, pubKey); err != nil {
		t.Fatal(err)
	}
}

func parseAPK(ctx context.Context, apkPath string) (control []byte, sigName string, sig []byte, err error) {
	apkr, err := os.Open(apkPath)
	if err != nil {
		return nil, "", nil, err
	}
	eapk, err := expandapk.ExpandApk(context.TODO(), apkr, "")
	if err != nil {
		return nil, "", nil, err
	}
	defer eapk.Close()
	gzSig, err := os.ReadFile(eapk.SignatureFile)
	if err != nil {
		return nil, "", nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(gzSig))
	if err != nil {
		return nil, "", nil, err
	}
	tr := tar.NewReader(zr)
	hdr, err := tr.Next()
	if err != nil {
		return nil, "", nil, err
	}
	if !strings.HasPrefix(hdr.Name, ".SIGN.") {
		return nil, "", nil, fmt.Errorf("unexpected header name %s", hdr.Name)
	}
	sig, err = io.ReadAll(tr)
	control, err = os.ReadFile(eapk.ControlFile)
	if err != nil {
		return nil, "", nil, err
	}
	return control, hdr.Name, sig, err
}

func CopyFile(src, dest string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dest, b, 0644); err != nil {
		return err
	}
	return nil
}
