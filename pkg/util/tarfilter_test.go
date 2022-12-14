package util

import (
	"archive/tar"
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestTarFilter(t *testing.T) {
	// create a tar file with several files in it
	tarFile := bytes.NewBuffer(nil)
	tw := tar.NewWriter(tarFile)
	only := "/foo/bar"
	files := []struct {
		inpath  string
		dir     bool
		content []byte
		present bool // whether or not the file should be present
	}{
		{"foo", true, nil, false},
		{"foo/bar", true, nil, false}, // this is the root, so it should not be here
		{"foo/bar/baz", false, []byte("baz"), true},
		{"foo/bar/qux", false, []byte("qux"), true},
		{"foo/bar/sub", true, nil, true},
		{"foo/bar/sub/file", false, []byte("content"), true},
		{"out", true, nil, false},
		{"out/dir", true, nil, false},
		{"out/dir/abc", false, []byte("def"), false},
		{"out/file", false, []byte("hello"), false},
	}

	for _, f := range files {
		hdr := &tar.Header{
			Name: f.inpath,
		}
		if f.dir {
			hdr.Typeflag = tar.TypeDir
			hdr.Mode = 0o755
		} else {
			hdr.Typeflag = tar.TypeReg
			hdr.Size = int64(len(f.content))
			hdr.Mode = 0o644
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if !f.dir {
			if _, err := tw.Write(f.content); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	t.Run("trim", func(t *testing.T) {
		var myTar bytes.Buffer
		myTar.Write(tarFile.Bytes())
		rc := NewTarFilter(io.NopCloser(&myTar), only, true)
		tr := tar.NewReader(rc)
		foundFiles := map[string][]byte{}
		foundDirs := map[string]bool{}
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if hdr.Typeflag == tar.TypeDir {
				foundDirs[hdr.Name] = true
			} else {
				content := bytes.NewBuffer(nil)
				if _, err := io.Copy(content, tr); err != nil {
					t.Fatal(err)
				}
				foundFiles[hdr.Name] = content.Bytes()
			}
		}
		trimmed := strings.TrimPrefix(only, "/")
		for _, f := range files {
			if f.present {
				inpathTrimmed := strings.TrimPrefix(strings.TrimPrefix(f.inpath, trimmed), "/")
				if f.dir {
					if _, ok := foundDirs[inpathTrimmed]; !ok {
						t.Errorf("expected directory %s to be present", inpathTrimmed)
					}
				} else {
					if content, ok := foundFiles[inpathTrimmed]; !ok {
						t.Errorf("expected file %s to be present", inpathTrimmed)
					} else if !bytes.Equal(content, f.content) {
						t.Errorf("expected file %s to have content %q, got %q", inpathTrimmed, f.content, content)
					}
				}
			} else {
				if f.dir {
					if _, ok := foundDirs[f.inpath]; ok {
						t.Errorf("expected directory %s to be absent", f.inpath)
					}
				} else {
					if _, ok := foundFiles[f.inpath]; ok {
						t.Errorf("expected file %s to be absent", f.inpath)
					}
				}
			}
		}
	})
	t.Run("no trim", func(t *testing.T) {
		var myTar bytes.Buffer
		myTar.Write(tarFile.Bytes())
		rc := NewTarFilter(io.NopCloser(&myTar), only, false)
		tr := tar.NewReader(rc)
		foundFiles := map[string][]byte{}
		foundDirs := map[string]bool{}
		for {
			hdr, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if hdr.Typeflag == tar.TypeDir {
				foundDirs[hdr.Name] = true
			} else {
				content := bytes.NewBuffer(nil)
				if _, err := io.Copy(content, tr); err != nil {
					t.Fatal(err)
				}
				foundFiles[hdr.Name] = content.Bytes()
			}
		}
		for _, f := range files {
			if f.present {
				if f.dir {
					if _, ok := foundDirs[f.inpath]; !ok {
						t.Errorf("expected directory %s to be present", f.inpath)
					}
				} else {
					if content, ok := foundFiles[f.inpath]; !ok {
						t.Errorf("expected file %s to be present", f.inpath)
					} else if !bytes.Equal(content, f.content) {
						t.Errorf("expected file %s to have content %q, got %q", f.inpath, f.content, content)
					}
				}
			} else {
				if f.dir {
					if _, ok := foundDirs[f.inpath]; ok {
						t.Errorf("expected directory %s to be absent", f.inpath)
					}
				} else {
					if _, ok := foundFiles[f.inpath]; ok {
						t.Errorf("expected file %s to be absent", f.inpath)
					}
				}
			}
		}
	})
}
