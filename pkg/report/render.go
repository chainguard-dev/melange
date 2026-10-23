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

package report

import (
	_ "embed"
	"fmt"
	htmltemplate "html/template"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	texttemplate "text/template"
	"time"
)

// reportView is what the templates render.
type reportView struct {
	*Report
	JSONFile string
}

// flatten lists steps depth-first; their IDs carry the nesting.
func flatten(steps []*Step) []*Step {
	var out []*Step
	for _, st := range steps {
		out = append(out, st)
		out = append(out, flatten(st.Steps)...)
	}
	return out
}

var funcs = map[string]any{
	"ms": func(ms int64) string {
		return (time.Duration(ms) * time.Millisecond).String()
	},
	"keys": func(m map[string]string) []string {
		return slices.Sorted(maps.Keys(m))
	},
	"clock": func(t time.Time) string {
		return t.Format("15:04:05.000")
	},
	"flat": flatten,
	// cell makes a value safe for a Markdown table cell.
	"cell": func(s string) string {
		return strings.NewReplacer("|", `\|`, "\n", " ").Replace(s)
	},
	"trim": func(s string) string {
		return strings.TrimRight(s, "\n")
	},
	"upper": func(s Status) string {
		return strings.ToUpper(string(s))
	},
}

//go:embed report.html.tmpl
var htmlSource string

//go:embed report.md.tmpl
var markdownSource string

var (
	htmlTemplate     = htmltemplate.Must(htmltemplate.New("report").Funcs(funcs).Parse(htmlSource))
	markdownTemplate = texttemplate.Must(texttemplate.New("report").Funcs(funcs).Parse(markdownSource))
)

// template is satisfied by both html/template and text/template.
type template interface {
	Execute(w io.Writer, data any) error
}

func render(path string, tmpl template, view reportView) error {
	f, err := os.Create(path) // #nosec G304 - User-specified report directory
	if err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	defer f.Close()
	if err := tmpl.Execute(f, view); err != nil {
		return fmt.Errorf("rendering %s: %w", path, err)
	}
	return nil
}
