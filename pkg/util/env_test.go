// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package util

import (
	"testing"
	"time"
)

func TestSourceDateEpoch(t *testing.T) {
	tests := []struct {
		name            string
		sourceDateEpoch string
		defaultTime     time.Time
		want            time.Time
		wantErr         bool
	}{
		{
			name:        "empty",
			defaultTime: time.Time{},
			want:        time.Time{},
		},
		{
			name:            "strings",
			sourceDateEpoch: "    ",
			defaultTime:     time.Time{},
			want:            time.Time{},
		},
		{
			name:        "defaultTime",
			defaultTime: time.Unix(1234567890, 0),
			want:        time.Unix(1234567890, 0),
		},
		{
			name:            "0",
			sourceDateEpoch: "0",
			defaultTime:     time.Unix(1234567890, 0),
			want:            time.Unix(0, 0),
		},
		{
			name:            "1234567890",
			sourceDateEpoch: "1234567890",
			defaultTime:     time.Unix(0, 0),
			want:            time.Unix(1234567890, 0),
		},
		{
			name:            "invalid date",
			sourceDateEpoch: "tacocat",
			defaultTime:     time.Unix(0, 0),
			wantErr:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.sourceDateEpoch != "" {
				t.Setenv("SOURCE_DATE_EPOCH", tt.sourceDateEpoch)
			}
			got, err := SourceDateEpoch(tt.defaultTime)
			if err != nil {
				if !tt.wantErr {
					t.Fatalf("SourceDateEpoch() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if !got.Equal(tt.want) {
				t.Errorf("SourceDateEpoch() = %v, want %v", got, tt.want)
			}
		})
	}
}
