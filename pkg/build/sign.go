package build

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	sign "github.com/chainguard-dev/go-apk/pkg/signature"

	"github.com/klauspost/compress/gzip"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/options"
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

type SignerOpts struct {
	SigningKey        string
	SigningPassphrase string
}

func Signer(opts SignerOpts) (ApkSigner, error) {
	var signer ApkSigner
	if opts.SigningKey == "" {
		signer = &FulcioApkSigner{}
	} else {
		if strings.Contains(opts.SigningKey, "://") {
			return NewKMSApkSigner(opts.SigningKey)
		} else {
			signer = &KeyApkSigner{
				KeyFile:       opts.SigningKey,
				KeyPassphrase: opts.SigningPassphrase,
			}
		}
	}
	return signer, nil
}

// Key base signature (normal) uses a SHA-1 hash on the control digest.
type KeyApkSigner struct {
	KeyFile       string
	KeyPassphrase string
}

func (s KeyApkSigner) Sign(control []byte) ([]byte, error) {
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

// APKv2+Fulcio style signature is an SHA-256 hash on the control
// digest.
// TODO(kaniini): Emit fulcio signature if signing key not configured.
type FulcioApkSigner struct{}

// Sign implements ApkSigner.
func (*FulcioApkSigner) Sign(control []byte) ([]byte, error) {
	digest := sha256.New()

	_, err := digest.Write(control)
	if err != nil {
		return nil, err
	}

	// TODO: Do the signing
	return nil, fmt.Errorf("APKv2+Fulcio style signature is not yet supported")
}

// SignatureName implements ApkSigner.
func (*FulcioApkSigner) SignatureName() string {
	panic("unimplemented")
}

// KMSApkSigner is a signer that uses KMS.
// This feature should be work when SHA-256 signature is supported.
type KMSApkSigner struct {
	keyName string
	signer  kms.SignerVerifier
}

// NewKMSApkSigner gets KMS signer based on key reference.
func NewKMSApkSigner(keyRef string) (*KMSApkSigner, error) {
	sv, err := kms.Get(context.Background(), keyRef, crypto.SHA1)
	if err != nil {
		return nil, fmt.Errorf("unable to get KMS signer: %w", err)
	}

	keyID := strings.Split(keyRef, "/")

	return &KMSApkSigner{
		signer:  sv,
		keyName: keyID[len(keyID)-1],
	}, nil
}

// Sign implements ApkSigner using KMS.
func (s KMSApkSigner) Sign(control []byte) ([]byte, error) {
	// Note: not all KMS signers supports SHA-1.
	return s.signer.SignMessage(bytes.NewReader(control), options.WithCryptoSignerOpts(crypto.SHA1))
}

func (s KMSApkSigner) SignatureName() string {
	return fmt.Sprintf(".SIGN.RSA.%s.pub", s.keyName)
}
