package build_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"chainguard.dev/melange/pkg/build"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

const MockName = "mockiavelli"

func TestEmitSignature(t *testing.T) {
	ctx := context.Background()
	sde := time.Unix(12345678, 0)

	controlData := []byte("donkey")

	signer := &mockSigner{}

	sig, err := build.EmitSignature(ctx, signer, controlData, sde)
	if err != nil {
		t.Fatal(err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(sig))
	if err != nil {
		t.Fatal(err)
	}

	// Decompress the sig to first check for end of archive markers
	dsig, err := io.ReadAll(gr)
	if err != nil {
		t.Fatal(err)
	}

	// Check for end of archive markers
	if bytes.HasSuffix(dsig, make([]byte, 1024)) {
		t.Fatalf("found end of archive makers in the signature tarball")
	}

	// Now create the tar reader from the decompressed sig archive for the remainder of the tests
	tr := tar.NewReader(bytes.NewBuffer(dsig))

	hdr, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}

	// Should only have a single file in here
	hdrWant := &tar.Header{
		Name:     MockName,
		Typeflag: tar.TypeReg,
		Size:     int64(len(controlData)),
		Mode:     int64(os.ModePerm),
		Uid:      0,
		Gid:      0,
		Uname:    "root",
		Gname:    "root",
		ModTime:  sde,
	}
	if diff := cmp.Diff(hdr, hdrWant, cmpopts.IgnoreFields(tar.Header{}, "AccessTime", "ChangeTime", "Format")); diff != "" {
		t.Errorf("Expected %v got %v", hdr, hdrWant)
	}

	if hdr.Name != "mockiavelli" {
		t.Errorf("Unexpected tar header name: got %v want %v", hdr.Name, "mockaveli")
	}

	want, err := io.ReadAll(tr)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(controlData, want) {
		t.Errorf("Unexpected signature contents: got %v want %v", want, controlData)
	}

	_, err = tr.Next()
	//nolint:errorlint
	if err != io.EOF {
		t.Fatalf("Expected tar EOF")
	}
}

type mockSigner struct{}

// Sign implements build.ApkSigner.
func (*mockSigner) Sign(controlData []byte) ([]byte, error) {
	return controlData, nil
}

// SignatureName implements build.ApkSigner.
func (*mockSigner) SignatureName() string {
	return "mockiavelli"
}
