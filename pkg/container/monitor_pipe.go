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
	"bytes"
	"context"
	"io"
	"log/slog"

	"github.com/chainguard-dev/clog"
)

func logWriters(ctx context.Context) (stdout, stderr io.WriteCloser) {
	return logWriter(ctx, slog.LevelInfo), logWriter(ctx, slog.LevelWarn)
}

func logWriter(ctx context.Context, level slog.Level) io.WriteCloser {
	log := clog.FromContext(ctx)
	f := log.Info
	if level == slog.LevelWarn {
		f = log.Warn
	}
	buf := new(bytes.Buffer)
	return &levelWriter{f, buf}
}

type levelWriter struct {
	log func(string, ...any)
	buf *bytes.Buffer
}

func (l *levelWriter) Write(p []byte) (int, error) {
	n, err := l.buf.Write(p)

	for {
		line, lerr := l.buf.ReadString('\n')
		if lerr != nil {
			l.buf.WriteString(line)
			break
		}
		line = line[:len(line)-1] // trim the newline at the end
		l.log(line)
	}

	return n, err
}

func (l *levelWriter) Close() error {
	if l.buf.Len() != 0 {
		l.log(l.buf.String())
	}
	return nil
}

type contextReader struct {
	r   io.Reader
	ctx context.Context
}

func (c *contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := c.r.Read(p)
	return n, err
}
