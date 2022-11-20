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
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"chainguard.dev/melange/pkg/build"
	"github.com/spf13/cobra"
)

func Pipeline() *cobra.Command {
	var pipelineDir string

	pipelineCmd := &cobra.Command{
		Use:   "pipeline",
		Short: "List/get pipeline",
		Long:  `List/get melange pipelines`,
		Example: `  melange pipeline list
  melange pipeline get cmake/install`,
		Args: cobra.MinimumNArgs(1),
	}

	pipelineGetCmd := &cobra.Command{
		Use:     "get <pipeline-name>",
		Short:   "get a specific pipeline",
		Long:    `Describe melange pipeline`,
		Example: `  melange pipeline get autoconf/make`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return GetPipelineCmd(cmd.Context(), pipelineDir, args[0])
		},
	}

	pipelineGetCmd.Flags().StringVar(&pipelineDir, "pipeline-dir", "", "directory used to defined built-in pipelines")

	pipelineListCmd := &cobra.Command{
		Use:     "list",
		Short:   "List all pipelines",
		Long:    `List all melange pipelines`,
		Example: `  melange pipeline list`,
		Args:    cobra.MinimumNArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ListPipelineCmd(cmd.Context(), pipelineDir)
		},
	}
	pipelineListCmd.Flags().StringVar(&pipelineDir, "pipeline-dir", "", "directory used to defined built-in pipelines")

	pipelineCmd.AddCommand(pipelineGetCmd)
	pipelineCmd.AddCommand(pipelineListCmd)
	return pipelineCmd
}

func GetPipelineCmd(ctx context.Context, pipelineDir string, pipelineName string) error {
	if len(pipelineDir) == 0 {
		pipelineDir = BuiltinPipelineDir
	}
	log.Printf("using pipeline directory: %s", pipelineDir)

	var loadedFrom string
	data, err := os.ReadFile(filepath.Join(pipelineDir, pipelineName+".yaml"))
	if err == nil {
		loadedFrom = pipelineDir
	} else {
		log.Printf("error reading from pipeline-dir, falling back to embedded pipelines: %v", err)
		loadedFrom = "embeded pipelines"

		data, err = build.EmbededPipelines.ReadFile("pipelines/" + pipelineName + ".yaml")
		if err != nil {
			return fmt.Errorf("failed to get pipeline: %w", err)
		}
	}

	fmt.Printf("\n%s\n", string(data))
	log.Printf("Loaded [%s] from: %s", pipelineName, loadedFrom)

	return nil
}

func ListPipelineCmd(ctx context.Context, pipelineDir string) error {
	if len(pipelineDir) == 0 {
		pipelineDir = BuiltinPipelineDir
	}

	if stat, err := os.Stat(pipelineDir); err == nil && stat.IsDir() {
		log.Printf("listing pipelines from %s", pipelineDir)
		pipelines := listPipelinesFromDir(pipelineDir, ".yaml")
		for _, p := range pipelines {
			fmt.Printf("%+v\n", p)
		}

		return nil
	} else {
		log.Printf("listing embeded pipelines")
		pipelines, err := listEmbededPipelines(&build.EmbededPipelines, "pipelines")

		if err != nil {
			return fmt.Errorf("failed to list pipelines: %w", err)
		}

		for _, p := range pipelines {
			fmt.Printf("%+v\n", p)
		}

		return nil
	}
}

func listPipelinesFromDir(dir, ext string) []string {
	var matched []string
	normalizedPath := strings.Clone(dir)
	if dir[len(dir)-1] != '/' {
		normalizedPath += string('/')
	}

	filepath.WalkDir(dir, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if filepath.Ext(d.Name()) == ext {
			// remove pipeline-dir prefix and file extension
			trimmed := removePrefixAndExtFromPath(path, dir)
			matched = append(matched, trimmed)
		}
		return nil
	})

	return matched
}

func listEmbededPipelines(fs *embed.FS, dir string) (out []string, err error) {
	entries, err := fs.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		fp := path.Join(dir, entry.Name())
		if entry.IsDir() {
			res, err := listEmbededPipelines(fs, fp)
			if err != nil {
				return nil, err
			}

			out = append(out, res...)

			continue
		}

		var fpWithoutExt = removePrefixAndExtFromPath(fp, "pipelines/")
		var _, final, _ = strings.Cut(fpWithoutExt, "/")
		out = append(out, final)
	}

	return
}

func removePrefixAndExtFromPath(path string, prefix string) string {
	normalizedPrefix := strings.Clone(prefix)
	if prefix[len(prefix)-1] != '/' {
		normalizedPrefix += string('/')
	}

	withoutPrefix := strings.TrimPrefix(path, normalizedPrefix)
	extension := filepath.Ext(withoutPrefix)
	pathWithoutExt := path[0 : len(path)-len(extension)]
	return pathWithoutExt
}
