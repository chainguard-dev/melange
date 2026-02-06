// Copyright 2025 Chainguard, Inc.
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
	"os"
	"path/filepath"
	"text/template"
)

var gccLinkTemplate = `*link:
+ --package-metadata={"type":"apk","os":"{{.Namespace}}","name":"{{.Configuration.Package.Name}}","version":"{{.Configuration.Package.FullVersion}}","architecture":"{{.Arch.ToAPK}}"{{if .Configuration.Package.CPE.Vendor}},"appCpe":"{{.Configuration.Package.CPEString}}"{{end}}}
`

// createGccSpecFile creates the GCC spec file with linker settings
func (b *Build) createGccSpecFile() error {
	specFile, err := os.Create(filepath.Join(b.WorkspaceDir, ".melange.gcc.spec"))
	if err != nil {
		return err
	}
	specTemplate := template.New("gccSpecFile")
	if err := template.Must(specTemplate.Parse(gccLinkTemplate)).Execute(specFile, b); err != nil {
		return err
	}
	if err := specFile.Close(); err != nil {
		return err
	}
	return nil
}
