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

package logwriter

import (
	"bytes"
	"io"
)

func New(log func(string, ...any)) io.WriteCloser {
	buf := new(bytes.Buffer)
	return &levelWriter{log, buf}
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
