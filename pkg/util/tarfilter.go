package util

import (
	"archive/tar"
	"bytes"
	"io"
	"strings"
)

// tarFilter is a filter that can be used to filter out files from a tar.
type tarFilter struct {
	r           io.ReadCloser
	only        string
	trim        bool
	tr          *tar.Reader
	buf         *bytes.Buffer
	currentFile bool
}

// NewTarFilter returns a new tar filter that will only return files that
// start with the value of only. Will strip leading '/' from only to match
// how tar files normally are constructed.
// If trim is true, the prefix will be trimmed from the returned files.
func NewTarFilter(r io.ReadCloser, only string, trim bool) io.ReadCloser {
	// tar usually has the leading / stripped, so we do the same
	only = strings.TrimPrefix(only, "/")
	return &tarFilter{
		r:    r,
		only: only,
		trim: trim,
	}
}

func (t *tarFilter) Read(p []byte) (n int, err error) {
	if t.r == nil {
		return 0, io.EOF
	}
	if t.tr == nil {
		t.buf = &bytes.Buffer{}
		t.tr = tar.NewReader(io.TeeReader(t.r, t.buf))
	}
	// is there anything left in the buffer?
	if t.buf.Len() > 0 {
		return t.buf.Read(p)
	}
	// if we got this far, the buffer is empty
	if t.currentFile {
		// read into buffer
		n, err := io.CopyN(t.buf, t.tr, int64(len(p)))
		_, _ = t.buf.Read(p)
		if err == io.EOF {
			t.currentFile = false
			err = nil
		}
		return int(n), err
	}
	// no current file, so read the next one, first checking if it fits the filter
	for {
		hdr, err := t.tr.Next()
		if err == io.EOF {
			t.r = nil
			n, _ := t.buf.Read(p)
			t.buf = nil
			return n, io.EOF
		}
		if err != nil {
			return 0, err
		}
		if hdr.Name == t.only || !strings.HasPrefix(hdr.Name, t.only) {
			t.removeHeader()
			continue
		}
		if t.trim {
			hdr.Name = strings.TrimPrefix(strings.TrimPrefix(hdr.Name, t.only), "/")
			// replace the contents of the buffer with an updated header
			t.removeHeader()
			// use a temporary buffer, because we do not want to catch the Close(), which writes ending bytes into
			// the tar stream
			var hdrBuf bytes.Buffer
			tw := tar.NewWriter(&hdrBuf)
			_ = tw.WriteHeader(hdr)
			_, _ = t.buf.Write(hdrBuf.Bytes())
			tw.Close()
		}
		// send the header
		t.currentFile = true
		break
	}
	return t.buf.Read(p)
}

func (t *tarFilter) Close() error {
	return t.r.Close()
}

// removeHeader remove the most recent header from the buffer.
// relies on the fact that the header for tar always is 512 bytes
func (t *tarFilter) removeHeader() {
	// remove the most recent 512 bytes from the buffer
	b := t.buf.Bytes()
	t.buf.Reset()
	if len(b) > 512 {
		t.buf.Write(b[:len(b)-512])
	}
}
