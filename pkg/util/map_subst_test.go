// Copyright 2024 Chainguard, Inc.
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

package util

import (
	"testing"
)

func TestMutateStringFromMap(t *testing.T) {
	for _, c := range []struct {
		desc    string
		with    map[string]string
		input   string
		want    string
		wantErr bool
	}{{
		desc: "simple",
		with: map[string]string{
			"foo": "bar",
		},
		input: "foo is ${{foo}}",
		want:  "foo is bar",
	}, {
		desc: "fail",
		with: map[string]string{
			"foo": "bar",
		},
		input:   "foo is ${{notbar}}",
		wantErr: true,
	}} {
		t.Run(c.desc, func(t *testing.T) {
			got, err := MutateStringFromMap(c.with, c.input)
			gotErr := err != nil
			if gotErr != c.wantErr {
				t.Fatalf("got error %v, want error %v", gotErr, c.wantErr)
			}

			if got != c.want {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
