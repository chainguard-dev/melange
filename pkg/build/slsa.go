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
	"encoding/json"
	"fmt"

	provenancev1 "github.com/in-toto/attestation/go/predicates/provenance/v1"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"sigs.k8s.io/release-utils/version"
)

const (
	intotoStatementType         = "https://in-toto.io/Statement/v1"
	slsaProvenanceStatementType = "https://slsa.dev/provenance/v1"
	melangeBuilder              = "https://chainguard.dev/prod/builders/melange/v1"
	melangeBuildType            = "https://chainguard.dev/buildtypes/melange/v1"
)

func (pc *PackageBuild) generateSLSA() ([]byte, error) {
	slsaBuilder := &provenancev1.Builder{
		Id: melangeBuilder,
		Version: map[string]string{
			"melange": version.GetVersionInfo().GitVersion,
		},
	}

	cfg, err := structToMap(pc.Build.Configuration)
	if err != nil {
		return nil, fmt.Errorf("converting contents to generic map: %w", err)
	}
	externalParameters, err := structpb.NewStruct(map[string]any{
		"package-configuration": cfg,
	})
	if err != nil {
		return nil, err
	}

	predicate := &provenancev1.Provenance{
		BuildDefinition: &provenancev1.BuildDefinition{
			BuildType:          melangeBuildType,
			ExternalParameters: externalParameters,
		},
		RunDetails: &provenancev1.RunDetails{
			Builder: slsaBuilder,
			Metadata: &provenancev1.BuildMetadata{
				StartedOn:  timestamppb.New(pc.Build.Start),
				FinishedOn: timestamppb.New(pc.Build.End),
			},
		},
	}

	pbJson, err := protojson.Marshal(predicate)
	if err != nil {
		return nil, err
	}

	var pbMap map[string]any
	if err := json.Unmarshal(pbJson, &pbMap); err != nil {
		return nil, err
	}

	pbStruct, err := structpb.NewStruct(pbMap)
	if err != nil {
		return nil, err
	}

	subject := []*intoto.ResourceDescriptor{
		{
			Name: pc.Identity() + ".apk",
			Digest: map[string]string{
				"sha256": pc.DataHash,
			},
		},
	}

	statement := &intoto.Statement{
		Type:          intotoStatementType,
		PredicateType: slsaProvenanceStatementType,
		Subject:       subject,
		Predicate:     pbStruct,
	}

	slsa, err := json.MarshalIndent(statement, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling provenance: %w", err)
	}

	return slsa, nil
}

// structToMap converts a struct to a map[string]any. It assumes that the struct
// can be marshaled to JSON and unmarshaled back to a map.
func structToMap(val any) (map[string]any, error) {
	contents, err := json.Marshal(val)
	if err != nil {
		return nil, fmt.Errorf("marshaling struct: %w", err)
	}
	var genericValue map[string]any
	if err := json.Unmarshal(contents, &genericValue); err != nil {
		return nil, fmt.Errorf("unmarshaling struct: %w", err)
	}
	return genericValue, nil
}
