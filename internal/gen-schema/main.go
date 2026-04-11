package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"log"
	"os"

	"github.com/invopop/jsonschema"

	"chainguard.dev/melange/pkg/config"
)

var outputFlag = flag.String("o", "", "output path")

func main() {
	flag.Parse()

	if *outputFlag == "" {
		log.Fatal("output path is required")
	}

	r := new(jsonschema.Reflector)
	if err := r.AddGoComments("chainguard.dev/melange/pkg/build", "../../pkg/config"); err != nil {
		log.Fatal(err)
	}
	schema := r.Reflect(config.Configuration{})
	b := new(bytes.Buffer)
	enc := json.NewEncoder(b)
	enc.SetIndent("", "  ")
	if err := enc.Encode(schema); err != nil {
		log.Fatal(err)
	}
	// #nosec G306 - Generated schema file should be world-readable
	if err := os.WriteFile(*outputFlag, b.Bytes(), 0o644); err != nil {
		log.Fatal(err)
	}
}
