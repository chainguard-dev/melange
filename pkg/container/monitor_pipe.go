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

package container

import (
	"bufio"
	"context"
	"io"
	"log/slog"

	"github.com/chainguard-dev/clog"
)

func monitorPipe(ctx context.Context, level slog.Level, pipe io.Reader) error {
	log := clog.FromContext(ctx)

	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		switch level {
		case slog.LevelInfo:
			log.Info(scanner.Text())
		case slog.LevelWarn:
			log.Warn(scanner.Text())
		default:
		}
	}

	return scanner.Err()
}
