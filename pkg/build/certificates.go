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
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	apko_types "chainguard.dev/apko/pkg/build/types"
)

// ExtraCACertsEnv names the environment variable listing PEM files of extra
// CA certificates for the build and test guests, separated like PATH. It
// applies when no certificates are passed explicitly, so builds started
// without the CLI (go generate, tests) can trust a TLS-intercepting proxy too.
const ExtraCACertsEnv = "MELANGE_EXTRA_CA_CERTS"

// extraCACertsFromEnv returns the paths ExtraCACertsEnv lists, if any.
func extraCACertsFromEnv() []string {
	var paths []string
	for _, p := range filepath.SplitList(os.Getenv(ExtraCACertsEnv)) {
		if p != "" {
			paths = append(paths, p)
		}
	}
	return paths
}

// withExtraCACertificates returns a copy of ic that also trusts every
// certificate in the PEM files at paths. apko takes one certificate per
// entry, so a bundle becomes one entry per certificate.
//
// The copy is only for building the guest: the configuration recorded in
// the package keeps none of these certificates, which describe the machine
// the build ran on rather than the package.
func withExtraCACertificates(ic apko_types.ImageConfiguration, paths []string) (apko_types.ImageConfiguration, error) {
	if len(paths) == 0 {
		return ic, nil
	}

	certs := apko_types.ImageCertificates{}
	if ic.Certificates != nil {
		certs = *ic.Certificates
	}
	certs.Additional = append([]apko_types.AdditionalCertificateEntry{}, certs.Additional...)

	n := 0
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return ic, fmt.Errorf("reading CA certificates: %w", err)
		}
		found := 0
		for {
			var block *pem.Block
			block, data = pem.Decode(data)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			certs.Additional = append(certs.Additional, apko_types.AdditionalCertificateEntry{
				Name:    fmt.Sprintf("melange-extra-ca-%d", n),
				Content: string(pem.EncodeToMemory(block)),
			})
			n++
			found++
		}
		if found == 0 {
			return ic, fmt.Errorf("no PEM certificates in %s", p)
		}
	}

	ic.Certificates = &certs
	return ic, nil
}
