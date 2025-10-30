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

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra/doc"

	"chainguard.dev/melange/pkg/cli"
)

const fmTemplate = `---
title: "%s"
slug: %s
url: %s
draft: false
images: []
type: "article"
toc: true
---
`

func main() {
	melange := cli.New()

	var pathout string
	var baseURL string
	var suffix string
	flag.StringVar(&pathout, "out", "./md", "Path to the output directory.")
	flag.StringVar(&baseURL, "baseurl", "/open-source/melange/reference/", "Base URL for melange-docs on Academy site.")
	flag.StringVar(&suffix, "suffix", "/", "Suffix for the MD files.")
	flag.Parse()

	filePrepender := func(filename string) string {
		name := filepath.Base(filename)
		base := strings.Split(strings.TrimSuffix(name, path.Ext(name)), "/")[:1][0]
		url := baseURL + strings.ToLower(base) + suffix
		return fmt.Sprintf(fmTemplate, strings.ReplaceAll(base, "_", " "), base, url)
	}

	linkHandler := func(name string) string {
		base := strings.TrimSuffix(name, path.Ext(name))
		return baseURL + strings.ToLower(base) + suffix
	}

	if err := os.MkdirAll(pathout, 0o755); err != nil && !os.IsExist(err) {
		log.Fatalf("error creating directory %#v: %#v", pathout, err)
	}

	log.Printf("Generating Markdown documentation into directory %#v\n", pathout)
	err := doc.GenMarkdownTreeCustom(melange, pathout, filePrepender, linkHandler)
	if err != nil {
		log.Fatalf("error creating documentation: %#v", err)
	}
}
