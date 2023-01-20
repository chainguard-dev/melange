// Copyright 2022 Chainguard, Inc.
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

// bom captures the internal data model of the SBOMs melange produces
// into a private, generalized bill of materials model (with relationship
// data) designed to be transcoded to specific formats.
package sbom

import "fmt"

type bom struct {
	Packages []pkg
	Files    []file
}

type element interface {
	ID() string
}

type pkg struct {
	FilesAnalyzed    bool
	id               string
	Name             string
	Version          string
	HomePage         string
	Supplier         string
	DownloadLocation string
	Originator       string
	Copyright        string
	LicenseDeclared  string
	LicenseConcluded string
	Namespace        string
	Arch             string
	Purl             string
	Checksums        map[string]string
	Relationships    []relationship
}

func (p *pkg) ID() string {
	if p.id != "" {
		return fmt.Sprintf("SPDXRef-Package-%s", p.id)
	}
	return "SPDXRef-Package-" + p.Name
}

type file struct {
	id            string
	Name          string
	Version       string
	Checksums     map[string]string
	Relationships []relationship
}

func (f *file) ID() string {
	if f.id != "" {
		return fmt.Sprintf("SPDXRef-File-%s", f.id)
	}
	return "SPDXRef-File-" + f.Name
}

type relationship struct {
	Source element
	Target element
	Type   string
}
