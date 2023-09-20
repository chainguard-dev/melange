package index

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"path/filepath"
	"strings"

	sign "github.com/chainguard-dev/go-apk/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/kms"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

type IndexSigner interface {
	Sign(digest []byte) ([]byte, error)
	SignatureName() string
}

type SignerOpts struct {
	SigningKey        string
	SigningPassphrase string
}

func Signer(opts SignerOpts) (IndexSigner, error) {
	var signer IndexSigner
	if opts.SigningKey == "" {
		signer = &FulcioIndexSigner{}
	} else {
		if strings.Contains(opts.SigningKey, "://") {
			return NewKMSIndexSigner(opts.SigningKey)
		} else {
			signer = &KeyIndexSigner{
				KeyFile:       opts.SigningKey,
				KeyPassphrase: opts.SigningPassphrase,
			}
		}
	}
	return signer, nil
}

// Key base signature (normal) uses a SHA-1 hash on the digest.
type KeyIndexSigner struct {
	KeyFile       string
	KeyPassphrase string
}

func (s KeyIndexSigner) Sign(digest []byte) ([]byte, error) {
	return sign.RSASignSHA1Digest(digest, s.KeyFile, s.KeyPassphrase)
}

func (s KeyIndexSigner) SignatureName() string {
	return fmt.Sprintf(".SIGN.RSA.%s.pub", filepath.Base(s.KeyFile))
}

// APKv2+Fulcio style signature is an SHA-256 hash on the digest.
// TODO(kaniini): Emit fulcio signature if signing key not configured.
type FulcioIndexSigner struct{}

// Sign implements ApkSigner.
func (*FulcioIndexSigner) Sign(digest []byte) ([]byte, error) {

	// TODO: Do the signing
	return nil, fmt.Errorf("APKv2+Fulcio style signature is not yet supported")
}

// SignatureName implements ApkSigner.
func (*FulcioIndexSigner) SignatureName() string {
	panic("unimplemented")
}

// KMSApkSigner is a signer that uses KMS.
// This feature should be work when SHA-256 signature is supported.
type KMSIndexSigner struct {
	keyName string
	signer  kms.SignerVerifier
}

// NewKMSApkSigner gets KMS signer based on key reference.
func NewKMSIndexSigner(keyRef string) (*KMSIndexSigner, error) {
	sv, err := kms.Get(context.Background(), keyRef, crypto.SHA1)
	if err != nil {
		return nil, fmt.Errorf("unable to get KMS signer: %w", err)
	}

	keyID := strings.Split(keyRef, "/")

	return &KMSIndexSigner{
		signer:  sv,
		keyName: keyID[len(keyID)-1],
	}, nil
}

// Sign implements ApkSigner using KMS.
func (s KMSIndexSigner) Sign(digest []byte) ([]byte, error) {
	// Note: not all KMS signers supports SHA-1.
	return s.signer.SignMessage(bytes.NewReader(digest), options.WithCryptoSignerOpts(crypto.SHA1))
}

func (s KMSIndexSigner) SignatureName() string {
	return fmt.Sprintf(".SIGN.RSA.%s.pub", s.keyName)
}
