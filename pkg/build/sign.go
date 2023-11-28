package build

import (
	"archive/tar"
	"bytes"
	"context"

	//nolint:gosec
	"crypto/sha1"
	"fmt"
	"os"
	"path/filepath"
	"time"

	sign "github.com/chainguard-dev/go-apk/pkg/signature"
	"github.com/klauspost/compress/gzip"
	"go.opentelemetry.io/otel"
)

type ApkSigner interface {
	Sign(controlData []byte) ([]byte, error)

	SignatureName() string
}

func EmitSignature(ctx context.Context, signer ApkSigner, controlData []byte, sde time.Time) ([]byte, error) {
	_, span := otel.Tracer("melange").Start(ctx, "EmitSignature")
	defer span.End()

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
		Mode:     int64(os.ModePerm),
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
	//nolint:gosec
	digest := sha1.New()

	_, err := digest.Write(control)
	if err != nil {
		return nil, err
	}

	return sign.RSASignSHA1Digest(digest.Sum(nil), s.KeyFile, s.KeyPassphrase)
}

func (s KeyApkSigner) SignatureName() string {
	return fmt.Sprintf(".SIGN.RSA.%s.pub", filepath.Base(s.KeyFile))
}
