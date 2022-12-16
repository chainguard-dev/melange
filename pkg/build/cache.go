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

package build

import (
	"fmt"
	"os"

	"github.com/dprotaso/go-yit"
	"gopkg.in/yaml.v3"

	"chainguard.dev/melange/pkg/renovate"
)

// CacheMembershipMap describes a mapping where keys map to 'true'
// if present.
type CacheMembershipMap map[string]bool

// loadConfig loads a configuration into a rootNode.
func loadConfig(configFile string, rootNode *yaml.Node) error {
	configData, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(configData, rootNode); err != nil {
		return err
	}

	return nil
}

// visitFetch processes a fetch node, updating the cache membership map.
func visitFetch(fetchNode *yaml.Node, cmm *CacheMembershipMap) error {
	withNode, err := renovate.NodeFromMapping(fetchNode, "with")
	if err != nil {
		return err
	}

	nodeSHA256, err := renovate.NodeFromMapping(withNode, "expected-sha256")
	if err == nil {
		key := fmt.Sprintf("sha256:%s", nodeSHA256.Value)
		(*cmm)[key] = true
	}

	nodeSHA512, err := renovate.NodeFromMapping(withNode, "expected-sha512")
	if err == nil {
		key := fmt.Sprintf("sha512:%s", nodeSHA512.Value)
		(*cmm)[key] = true
	}

	return nil
}

// cacheItemsForBuild returns the relevant hashes to check against
// a source cache for a given build as a CacheMembershipMap.
func cacheItemsForBuild(configFile string) (CacheMembershipMap, error) {
	cmm := CacheMembershipMap{}

	var rootNode yaml.Node
	if err := loadConfig(configFile, &rootNode); err != nil {
		return cmm, err
	}

	// Find our main pipeline YAML node.
	pipelineNode, err := renovate.NodeFromMapping(rootNode.Content[0], "pipeline")
	if err != nil {
		return cmm, err
	}

	// Look for fetch nodes.
	it := yit.FromNode(pipelineNode).
		RecurseNodes().
		Filter(yit.WithMapValue("fetch"))

	for fetchNode, ok := it(); ok; fetchNode, ok = it() {
		if err := visitFetch(fetchNode, &cmm); err != nil {
			return cmm, err
		}
	}

	return cmm, nil
}
