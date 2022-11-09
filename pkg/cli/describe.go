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

package cli

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"chainguard.dev/melange/pkg/build"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func Describe() *cobra.Command {
	var pipelineDir string

	describeCmd := &cobra.Command{
		Use:     "describe",
		Short:   "Describe resource like pipeline",
		Long:    `Describe melange resources: only pipeline resource is supported for now`,
		Example: `  melange describe <resource-type> <resource-name>`,
	}

	describePipelineCmd := &cobra.Command{
		Use:     "pipeline <pipeline-name>",
		Short:   "Describe pipeline resource",
		Long:    `Describe melange resources: pipeline only for now`,
		Example: `  melange describe pipeline autoconf/make`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return DescribePipelineCmd(cmd.Context(), pipelineDir, args[0])
		},
	}

	describePipelineCmd.Flags().StringVar(&pipelineDir, "pipeline-dir", "", "directory used to defined built-in pipelines")

	describeCmd.AddCommand(describePipelineCmd)
	return describeCmd
}

func DescribePipelineCmd(ctx context.Context, pipelineDir string, pipelineName string) error {
	if len(pipelineDir) == 0 {
		pipelineDir = BuiltinPipelineDir
	}
	log.Printf("using pipeline directory: %s", pipelineDir)

	var loadedFrom string
	data, err := os.ReadFile(filepath.Join(pipelineDir, pipelineName+".yaml"))
	if err == nil {
		loadedFrom = pipelineDir
	} else {
		log.Printf("unable to load pipeline from %s: %v", pipelineDir, err)
		log.Printf("falling back to embedded pipelines")
	}

	if errors.Is(err, os.ErrNotExist) {
		// fallback to the builtin pipeline directory search if the given file doesn't exist in the given pipeline directory

		// search the given pipeline within the built-in pipeline directory which is `/usr/share/melange/pipelines` in this case
		data, err = os.ReadFile(filepath.Join(pipelineDir, pipelineName+".yaml"))
		if errors.Is(err, os.ErrNotExist) {
			// fallback to the embedded pipelines compiled into the binary.
			data, err = build.EmbededPipelines.ReadFile("pipelines/" + pipelineName + ".yaml")
			if err != nil {
				return fmt.Errorf("unable to load pipeline: %w", err)
			}
		}
		loadedFrom = "embeded pipelines"
	}
	p, err := build.NewPipeline(&build.PipelineContext{
		Context:    &build.Context{},
		Package:    &build.Package{Name: "dummy"},
		Subpackage: &build.Subpackage{Name: "dummy-subpackage"},
	})
	if err := yaml.Unmarshal(data, p); err != nil {
		return fmt.Errorf("unable to parse pipeline: %w", err)
	}
	log.Printf("Pipeline [%s] content:\n", pipelineName)
	log.Printf("%s\n", string(data))
	log.Printf("Loaded [%s] from: %s", pipelineName, loadedFrom)

	return nil
}
