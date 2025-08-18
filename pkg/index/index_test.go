package index

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"chainguard.dev/apko/pkg/apk/apk"
	"chainguard.dev/apko/pkg/apk/expandapk"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/google/go-cmp/cmp"
)

func TestUpdateIndex(t *testing.T) {
	ctx := slogtest.Context(t)

	filename := filepath.Join("..", "sca", "testdata", "libcap-2.69-r0.apk")

	idx, err := New(WithPackageFiles([]string{filename}))
	if err != nil {
		t.Fatal(err)
	}

	if err := idx.UpdateIndex(ctx); err != nil {
		t.Fatal(err)
	}

	if want, got := len(idx.Index.Packages), 1; want != got {
		t.Fatalf("wanted %d packages, got %d", want, got)
	}

	pkg := idx.Index.Packages[0]

	want := &apk.Package{
		Name:          "libcap",
		Version:       "2.69-r0",
		Arch:          "aarch64",
		Description:   "POSIX 1003.1e capabilities",
		License:       "BSD-3-Clause OR GPL-2.0-only",
		Origin:        "libcap",
		Size:          29589,
		InstalledSize: 166451,
		Dependencies:  []string{"so:ld-linux-aarch64.so.1", "so:libc.so.6", "so:libcap.so.2", "so:libpsx.so.2"},
		DataHash:      "fb2e6aef71e85e7eb738d8029b1939d779034b14e23168fd27238e10cd908ed0",
		BuildTime:     time.Unix(0, 0),
		Checksum: []uint8{
			0x19, 0x38, 0xdd, 0x0d, 0x64, 0x80, 0x37, 0xf7, 0xbc, 0x99,
			0x19, 0x93, 0x40, 0xb2, 0xe4, 0x72, 0xcd, 0x2a, 0x46, 0x40,
		},
	}
	if diff := cmp.Diff(want, pkg); diff != "" {
		t.Errorf("UpdateIndex(): (-want, +got):\n%s", diff)
	}
}

func mangleApk(t *testing.T, newDesc string) string {
	t.Helper()
	file, err := os.Open(filepath.Join("..", "sca", "testdata", "libcap-2.69-r0.apk"))
	if err != nil {
		t.Fatal(err)
	}

	exp, err := expandapk.ExpandApk(slogtest.Context(t), file, "")
	if err != nil {
		t.Fatal(err)
	}

	info, err := exp.ControlFS.Open(".PKGINFO")
	if err != nil {
		t.Fatal(err)
	}

	b, err := io.ReadAll(info)
	if err != nil {
		t.Fatal(err)
	}

	b = bytes.ReplaceAll(b, []byte("POSIX 1003.1e capabilities"), []byte(newDesc))

	data, err := os.Open(exp.PackageFile)
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(filepath.Join(t.TempDir(), "libcap-2.69-r0.apk"))
	if err != nil {
		t.Fatal(err)
	}

	zw := gzip.NewWriter(f)
	tw := tar.NewWriter(zw)

	if err := tw.WriteHeader(&tar.Header{
		Name: ".PKGINFO",
		Mode: 0o644,
		Size: int64(len(b)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := tw.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := io.Copy(f, data); err != nil {
		t.Fatal(err)
	}

	return f.Name()
}

func TestMergeIndex(t *testing.T) {
	ctx := slogtest.Context(t)
	newDesc := "This should replace the existing description"

	filename := filepath.Join("..", "sca", "testdata", "libcap-2.69-r0.apk")
	oldindex := filepath.Join(t.TempDir(), "OLDAPKINDEX.tar.gz")

	idx, err := New(WithIndexFile(oldindex), WithPackageFiles([]string{filename}))
	if err != nil {
		t.Fatal(err)
	}

	if err := idx.GenerateIndex(ctx); err != nil {
		t.Fatal(err)
	}

	mangled := mangleApk(t, newDesc)
	idx2, err := New(WithMergeIndexFileFlag(true), WithSourceIndexFile(oldindex), WithPackageFiles([]string{mangled}))
	if err != nil {
		t.Fatal(err)
	}

	if err := idx2.UpdateIndex(ctx); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(newDesc, idx2.Index.Packages[0].Description); diff != "" {
		t.Errorf("UpdateIndex(): (-want, +got):\n%s", diff)
	}
}
