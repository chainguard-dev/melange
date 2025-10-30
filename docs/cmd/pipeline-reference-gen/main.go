package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"sigs.k8s.io/yaml"

	"chainguard.dev/melange/pkg/config"

	_ "embed"
)

var (
	pipelineDir = flag.String("pipeline-dir", "", "The directory to search for pipeline files")

	tmpl = template.Must(template.New("").Funcs(template.FuncMap{
		"anchor": func(s string) string {
			out := strings.ReplaceAll(s, "/", "")
			return out
		},
	}).Parse(tmplRaw))

	//go:embed template.md.tmpl
	tmplRaw string
)

type PipelineDoc struct {
	Name     string
	Pipeline *config.Pipeline
}

func main() {
	flag.Parse()

	if *pipelineDir == "" {
		panic("pipeline-dir is required")
	}

	if err := filepath.Walk(*pipelineDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Only walk directories - we group READMEs with their respective directories.
		if !info.IsDir() {
			return nil // Skip directories
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}

		doc := []*PipelineDoc{}
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) != ".yaml" {
				continue
			}

			// Parse the file
			p := filepath.Join(path, entry.Name())
			pipeline, err := parseFile(p)
			if err != nil {
				return err
			}
			for key, inputs := range pipeline.Inputs {
				inputs.Description = strings.ReplaceAll(inputs.Description, "\n", " ")
				inputs.Description = strings.ReplaceAll(inputs.Description, "\r", " ")

				pipeline.Inputs[key] = inputs
			}

			name := strings.TrimSuffix(entry.Name(), ".yaml")
			if base := strings.TrimPrefix(path, *pipelineDir); base != "" {
				name = strings.Join([]string{base, name}, "/")
			}
			name = strings.TrimPrefix(name, "/")
			doc = append(doc, &PipelineDoc{
				Name:     name,
				Pipeline: pipeline,
			})
		}

		if err := writeFile(path, doc); err != nil {
			return err
		}

		return nil
	}); err != nil {
		panic(err)
	}
}

func parseFile(path string) (*config.Pipeline, error) {
	b, err := os.ReadFile(path) // #nosec G304 - Reading pipeline definition for documentation
	if err != nil {
		return nil, err
	}

	out := new(config.Pipeline)
	if err := yaml.Unmarshal(b, out); err != nil {
		return nil, err
	}

	return out, nil
}

var regex = regexp.MustCompile(`(?s)<!-- start:pipeline-reference-gen -->\n(.*?)<!-- end:pipeline-reference-gen -->`)

func writeFile(path string, doc []*PipelineDoc) error {
	out := new(bytes.Buffer)
	if err := tmpl.Execute(out, doc); err != nil {
		return err
	}

	path = filepath.Join(path, "README.md")
	content, err := os.ReadFile(path) // #nosec G304 - Reading README for documentation generation
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	// File doesn't exist, write as-is.
	if os.IsNotExist(err) {
		// #nosec G306 - Documentation file should be world-readable
		return os.WriteFile(path, out.Bytes(), 0o644)
	}

	// Remove existing content
	if regex.Match(content) {
		content = regex.ReplaceAll(content, []byte(""))
	}

	// Append to the end
	content = append(content, out.Bytes()...)
	fmt.Println("Wrote", path)
	// #nosec G306 - Documentation file should be world-readable
	return os.WriteFile(path, content, 0o644)
}
