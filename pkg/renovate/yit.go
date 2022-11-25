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

package renovate

import (
	"fmt"

	"github.com/dprotaso/go-yit"
	"gopkg.in/yaml.v3"
)

// NodeFromMapping takes a yaml.Node (a mapping) and uses yit
// to find a child node in the mapping with the given key.
func NodeFromMapping(parentNode *yaml.Node, key string) (*yaml.Node, error) {
	it := yit.FromNode(parentNode).
		ValuesForMap(yit.WithValue(key), yit.All)

	if childNode, ok := it(); ok {
		return childNode, nil
	}

	return nil, fmt.Errorf("key '%s' not found in mapping", key)
}
