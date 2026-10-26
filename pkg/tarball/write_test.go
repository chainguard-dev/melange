package tarball

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/apko/pkg/apk/fs"
)

func TestWriteTar(t *testing.T) {
	var buf bytes.Buffer
	var (
		m    = fs.NewMemFS()
		dir  = "a"
		file = "a/b"
	)
	err := m.MkdirAll(dir, 0o755)
	require.NoError(t, err, "error creating dir %s", dir)
	err = m.WriteFile(file, []byte("hello world"), 0o644)
	require.NoError(t, err, "error creating file %s", file)

	// set xattrs, then see if the tar gets it
	err = m.SetXattr(dir, "user.dir", []byte("foo"))
	require.NoError(t, err, "error setting xattr on %s", dir)
	err = m.SetXattr(file, "user.file", []byte("bar"))
	require.NoError(t, err, "error setting xattr on %s", file)
	ctx := Context{}
	tw := tar.NewWriter(&buf)
	err = ctx.writeTar(context.TODO(), tw, m, nil, nil)
	require.NoError(t, err, "error writing tar")
	err = tw.Close()
	require.NoError(t, err, "error closing tar writer")

	// now should be able to read the tar and check the xattrs
	tr := tar.NewReader(&buf)
	hdr, err := tr.Next()
	require.NoError(t, err, "error reading dir tar header")
	require.Equal(t, dir, hdr.Name, "tar dir header name mismatch")
	require.Equal(t, "foo", hdr.PAXRecords[xattrTarPAXRecordsPrefix+"user.dir"], "tar header for dir xattr mismatch")

	hdr, err = tr.Next()
	require.NoError(t, err, "error reading file tar header")
	require.Equal(t, file, hdr.Name, "tar file header name mismatch")
	require.Equal(t, "bar", hdr.PAXRecords[xattrTarPAXRecordsPrefix+"user.file"], "tar header for file xattr mismatch")
}

const checksumRecord = "APK-TOOLS.checksum.SHA1"

// hardlinkDir returns a directory holding a/first and b/second, hard links of
// one inode, c/other, a separate file, and d/solo, a file with one link.
func hardlinkDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"a", "b", "c", "d"} {
		require.NoError(t, os.Mkdir(filepath.Join(dir, d), 0o755))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a/first"), []byte("shared"), 0o644))
	require.NoError(t, os.Link(filepath.Join(dir, "a/first"), filepath.Join(dir, "b/second")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "c/other"), []byte("other"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "d/solo"), []byte("solo"), 0o644))
	return dir
}

type entry struct {
	hdr  *tar.Header
	data string
}

func writeEntries(t *testing.T, c *Context, fsys iofs.FS) map[string]entry {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.NoError(t, c.writeTar(t.Context(), tw, fsys, nil, nil))
	require.NoError(t, tw.Close())

	got := map[string]entry{}
	tr := tar.NewReader(&buf)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return got
		}
		require.NoError(t, err)
		data, err := io.ReadAll(tr)
		require.NoError(t, err)
		got[hdr.Name] = entry{hdr: hdr, data: string(data)}
	}
}

func TestWriteTar_Hardlinks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fsys   func(t *testing.T, dir string) iofs.FS
		disk   bool
		linked bool
	}{{
		// apko's DirFS reports a *tar.Header from Sys(), so only the disk lookup sees the link
		name:   "DirFS with disk dir",
		fsys:   func(t *testing.T, dir string) iofs.FS { return fs.DirFS(t.Context(), dir) },
		disk:   true,
		linked: true,
	}, {
		name:   "DirFS without disk dir",
		fsys:   func(t *testing.T, dir string) iofs.FS { return fs.DirFS(t.Context(), dir) },
		linked: false,
	}, {
		// os.DirFS reports a *syscall.Stat_t, so no disk dir is needed
		name:   "os.DirFS without disk dir",
		fsys:   func(_ *testing.T, dir string) iofs.FS { return os.DirFS(dir) },
		linked: true,
	}} {
		for _, checksums := range []bool{false, true} {
			name := tc.name
			if checksums {
				name += " with checksums"
			}
			t.Run(name, func(t *testing.T) {
				dir := hardlinkDir(t)
				opts := []Option{WithUseChecksums(checksums)}
				if tc.disk {
					opts = append(opts, WithDiskDir(dir))
				}
				c, err := NewContext(opts...)
				require.NoError(t, err)

				got := writeEntries(t, c, tc.fsys(t, dir))

				first, second := got["a/first"], got["b/second"]
				require.Equal(t, byte(tar.TypeReg), first.hdr.Typeflag)
				require.Equal(t, "shared", first.data)
				for _, name := range []string{"c/other", "d/solo"} {
					require.Equal(t, byte(tar.TypeReg), got[name].hdr.Typeflag, name)
				}
				require.Equal(t, "other", got["c/other"].data)
				require.Equal(t, "solo", got["d/solo"].data)

				if !tc.linked {
					require.Equal(t, byte(tar.TypeReg), second.hdr.Typeflag)
					require.Equal(t, "shared", second.data)
				} else {
					require.Equal(t, byte(tar.TypeLink), second.hdr.Typeflag)
					require.Equal(t, "a/first", second.hdr.Linkname)
					require.Zero(t, second.hdr.Size)
					require.Empty(t, second.data)
				}

				// a link entry carries no checksum: the contents are not hashed
				// again
				for name, e := range got {
					if e.hdr.Typeflag != tar.TypeReg {
						continue
					}
					if checksums {
						require.NotEmpty(t, e.hdr.PAXRecords[checksumRecord], name)
					} else {
						require.Empty(t, e.hdr.PAXRecords[checksumRecord], name)
					}
				}
				if checksums && tc.linked {
					require.NotContains(t, second.hdr.PAXRecords, checksumRecord)
				}
			})
		}
	}
}

// A path with xattrs is written in full, and is not a target either: apk-tools
// chowning a link would clear security.capability on the shared inode.
func TestWriteTar_HardlinksWithXattrs(t *testing.T) {
	for _, tc := range []struct {
		name    string
		xattrOn string
	}{
		{name: "first path", xattrOn: "a/first"},
		{name: "later path", xattrOn: "b/second"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := hardlinkDir(t)
			fsys := fs.DirFS(t.Context(), dir)
			require.NoError(t, fsys.SetXattr(tc.xattrOn, "security.capability", []byte("cap")))
			c, err := NewContext(WithDiskDir(dir))
			require.NoError(t, err)

			got := writeEntries(t, c, fsys)
			for _, name := range []string{"a/first", "b/second"} {
				require.Equal(t, byte(tar.TypeReg), got[name].hdr.Typeflag, name)
				require.Equal(t, "shared", got[name].data, name)
			}
			require.Equal(t, "cap", got[tc.xattrOn].hdr.PAXRecords[xattrTarPAXRecordsPrefix+"security.capability"])
		})
	}
}

func TestWriteTar_DiskDirMissing(t *testing.T) {
	c, err := NewContext(WithDiskDir(filepath.Join(t.TempDir(), "absent")))
	require.NoError(t, err)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	require.Error(t, c.writeTar(t.Context(), tw, fs.NewMemFS(), nil, nil))
}

// Files kept only in memory by the fs.FS have nothing on disk to link to.
func TestWriteTar_DiskDirFileNotOnDisk(t *testing.T) {
	m := fs.NewMemFS()
	require.NoError(t, m.WriteFile("only-in-memory", []byte("hello"), 0o644))
	c, err := NewContext(WithDiskDir(t.TempDir()))
	require.NoError(t, err)

	got := writeEntries(t, c, m)
	require.Equal(t, byte(tar.TypeReg), got["only-in-memory"].hdr.Typeflag)
	require.Equal(t, "hello", got["only-in-memory"].data)
}

func TestDiskLinks_Inode(t *testing.T) {
	dir := hardlinkDir(t)
	require.NoError(t, os.Symlink("first", filepath.Join(dir, "a/sym")))

	d, err := OpenDiskLinks(dir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, d.Close()) })

	first, linked, err := d.Inode("a/first")
	require.NoError(t, err)
	require.True(t, linked)
	second, linked, err := d.Inode("b/second")
	require.NoError(t, err)
	require.True(t, linked)
	require.Equal(t, first, second)

	for _, name := range []string{
		"c/other",      // one link
		"a",            // directory
		"a/sym",        // symlink: Lstat, so not followed to the linked file
		"missing/gone", // not on disk
	} {
		_, linked, err := d.Inode(name)
		require.NoError(t, err, name)
		require.False(t, linked, name)
	}
}

func TestOpenDiskLinks_Missing(t *testing.T) {
	_, err := OpenDiskLinks(filepath.Join(t.TempDir(), "absent"))
	require.Error(t, err)
}

func TestLinkTargets(t *testing.T) {
	withCap := map[string][]byte{"security.capability": []byte("cap")}

	t.Run("links to the first path of an inode", func(t *testing.T) {
		var l LinkTargets
		_, ok := l.Target(1, "a", nil)
		require.False(t, ok)
		target, ok := l.Target(1, "b", nil)
		require.True(t, ok)
		require.Equal(t, "a", target)
		target, ok = l.Target(1, "c", nil)
		require.True(t, ok)
		require.Equal(t, "a", target)
	})

	t.Run("inodes are independent", func(t *testing.T) {
		var l LinkTargets
		_, ok := l.Target(1, "a", nil)
		require.False(t, ok)
		_, ok = l.Target(2, "b", nil)
		require.False(t, ok)
	})

	t.Run("xattrs on the first path", func(t *testing.T) {
		var l LinkTargets
		_, ok := l.Target(1, "a", withCap)
		require.False(t, ok)
		_, ok = l.Target(1, "b", nil)
		require.False(t, ok)
	})

	t.Run("xattrs on a later path", func(t *testing.T) {
		var l LinkTargets
		_, ok := l.Target(1, "a", nil)
		require.False(t, ok)
		_, ok = l.Target(1, "b", withCap)
		require.False(t, ok)
		target, ok := l.Target(1, "c", nil)
		require.True(t, ok)
		require.Equal(t, "a", target)
	})
}
