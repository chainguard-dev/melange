/*
Copyright 2026 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package build

import (
	"fmt"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// usesCache memoizes the parsed form of the pipeline definitions loaded by
// `uses:`.
//
// A definition is resolved from the same pipeline directories every time, and
// compiling a tree of package definitions asks for the same few of them over
// and over: a repository whose packages mostly `uses: go/build` parses that
// one file once per package that names it. Parsing the YAML is the expensive
// half of loading it, so the parsed document is what is kept.
//
// What is cached is the document, not a compiled pipeline. Compilation
// substitutes each package's own variables into the definition, so the result
// differs per package and only the parse is shared.
//
// The cache lives for the life of the process and assumes the pipeline
// directories do not change underneath it, which holds for a melange build and
// for the tools that compile a checked-out tree. Nothing invalidates it.
//
// sync.Map rather than a guarded map: once the definitions in use have been
// seen, every access is a read, and callers compile packages in parallel. A
// mutex — even an RWMutex, whose read path still writes a shared counter —
// would put every one of those reads through the same cache line.
var usesCache sync.Map // map[string]*yaml.Node, nil for an empty definition

// usesKey identifies a pipeline definition by the directories it is looked up
// in and the name it is looked up by, which is everything that determines
// which file wins.
func usesKey(pipelineDirs []string, uses string) string {
	return strings.Join(pipelineDirs, "\x00") + "\x00\x00" + uses
}

// usesDocument returns the parsed document for the pipeline definition named
// by uses, calling load to read it only the first time it is asked for.
//
// A nil document means the definition was empty, which yaml.Unmarshal treats
// as a no-op and so does the caller.
//
// Callers decode the returned document onto their own pipeline rather than
// receiving a copy. Decoding a document onto an existing value applies the keys
// the document sets and leaves the rest alone — the same as yaml.Unmarshal, and
// what the caller depends on, since a step's own `with`, `if` and `workdir` have
// to survive loading the definition it names.
func usesDocument(pipelineDirs []string, uses string, load func() ([]byte, error)) (*yaml.Node, error) {
	key := usesKey(pipelineDirs, uses)

	if cached, ok := usesCache.Load(key); ok {
		return cached.(*yaml.Node), nil
	}

	data, err := load()
	if err != nil {
		return nil, err
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("unable to parse pipeline %q: %w", uses, err)
	}

	// An empty definition parses to a document with no content, which Decode
	// rejects. Record it so it is not read again, and let the caller skip it.
	if doc.Kind == 0 || (doc.Kind == yaml.DocumentNode && len(doc.Content) == 0) {
		usesCache.Store(key, (*yaml.Node)(nil))
		return nil, nil
	}

	usesCache.Store(key, &doc)

	return &doc, nil
}
