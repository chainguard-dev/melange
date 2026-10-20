// Copyright 2026 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package build

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/stretchr/testify/require"
)

// testCertPEM returns a self-signed CA certificate, PEM-encoded.
func testCertPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestWithExtraCACertificates(t *testing.T) {
	dir := t.TempDir()
	one, two := testCertPEM(t, "one"), testCertPEM(t, "two")

	bundle := filepath.Join(dir, "bundle.pem")
	require.NoError(t, os.WriteFile(bundle, []byte("# a comment\n"+one+two), 0o644))
	single := filepath.Join(dir, "single.crt")
	require.NoError(t, os.WriteFile(single, []byte(one), 0o644))
	empty := filepath.Join(dir, "empty.pem")
	require.NoError(t, os.WriteFile(empty, []byte("not a certificate\n"), 0o644))

	existing := apko_types.AdditionalCertificateEntry{Name: "configured", Content: two}
	ic := apko_types.ImageConfiguration{
		Certificates: &apko_types.ImageCertificates{Additional: []apko_types.AdditionalCertificateEntry{existing}},
	}

	t.Run("no paths leaves the configuration alone", func(t *testing.T) {
		got, err := withExtraCACertificates(ic, nil)
		require.NoError(t, err)
		require.Equal(t, ic, got)
	})

	t.Run("one entry per certificate, after the configured ones", func(t *testing.T) {
		got, err := withExtraCACertificates(ic, []string{bundle, single})
		require.NoError(t, err)
		require.Equal(t, []apko_types.AdditionalCertificateEntry{
			existing,
			{Name: "melange-extra-ca-0", Content: one},
			{Name: "melange-extra-ca-1", Content: two},
			{Name: "melange-extra-ca-2", Content: one},
		}, got.Certificates.Additional)
		require.NoError(t, got.Validate())

		// The configuration the package records is untouched.
		require.Equal(t, []apko_types.AdditionalCertificateEntry{existing}, ic.Certificates.Additional)
	})

	t.Run("a file with no certificate is an error", func(t *testing.T) {
		_, err := withExtraCACertificates(ic, []string{empty})
		require.ErrorContains(t, err, "no PEM certificates")
	})

	t.Run("a missing file is an error", func(t *testing.T) {
		_, err := withExtraCACertificates(ic, []string{filepath.Join(dir, "missing.pem")})
		require.Error(t, err)
	})
}

func TestExtraCACertsFromEnv(t *testing.T) {
	t.Setenv(ExtraCACertsEnv, "")
	require.Empty(t, extraCACertsFromEnv())

	t.Setenv(ExtraCACertsEnv, strings.Join([]string{"/a.pem", "", "/b.pem"}, string(os.PathListSeparator)))
	require.Equal(t, []string{"/a.pem", "/b.pem"}, extraCACertsFromEnv())
}

func TestNewReadsExtraCACertsFromEnv(t *testing.T) {
	t.Setenv(ExtraCACertsEnv, "/from/env.pem")
	cfg := filepath.Join(t.TempDir(), "melange.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte("package:\n  name: foo\n  version: 1.0.0\n  epoch: 0\n"), 0o644))

	b, err := New(t.Context(), WithConfig(cfg), WithConfigFileRepositoryURL("https://github.com/wolfi-dev/os"), WithConfigFileRepositoryCommit("c0ffee"))
	require.NoError(t, err)
	require.Equal(t, []string{"/from/env.pem"}, b.ExtraCACertificates)

	// An explicit option wins, even an empty one.
	b, err = New(t.Context(), WithConfig(cfg), WithConfigFileRepositoryURL("https://github.com/wolfi-dev/os"), WithConfigFileRepositoryCommit("c0ffee"), WithExtraCACertificates([]string{}))
	require.NoError(t, err)
	require.Empty(t, b.ExtraCACertificates)
}
