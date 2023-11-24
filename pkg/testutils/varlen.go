// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package testutils

import (
	"bufio"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/ebpfevents/pkg/endian"
	"github.com/elastic/ebpfevents/pkg/varlen"
)

func WriteVarlenFields(t *testing.T, w *bufio.Writer, m varlen.Map) {
	t.Helper()

	var (
		size       uint64
		nfields    uint32
		fieldSizes = make(map[varlen.Field]uint32)
	)

	for k, v := range m {
		size += 4 // `type`
		size += 4 // varlen_field `size`

		fieldSizes[k] = 0
		switch k {
		case varlen.Cwd, varlen.Filename, varlen.CgroupPath,
			varlen.Path, varlen.OldPath, varlen.NewPath, varlen.TTYOutput,
			varlen.SymlinkTargetPath:
			fieldSizes[k] += uint32(len(v.(string))) + 1 // null terminator
		case varlen.Argv:
			for _, str := range v.([]string) {
				fieldSizes[k] += uint32(len(str)) + 1 // null terminator
			}
		case varlen.Env:
			for key, value := range v.(map[string]string) {
				fieldSizes[k] += uint32(len(key))
				fieldSizes[k] += 1 // equal sign
				fieldSizes[k] += uint32(len(value))
				fieldSizes[k] += 1 // null terminator
			}
		default:
			t.Fatalf("unsupported varlen type: %d", k)
		}

		size += uint64(fieldSizes[k])
		nfields++
	}

	assert.Nil(t, binary.Write(w, endian.Native, nfields))
	assert.Nil(t, binary.Write(w, endian.Native, size))

	for k, v := range m {
		assert.Nil(t, binary.Write(w, endian.Native, k))
		assert.Nil(t, binary.Write(w, endian.Native, fieldSizes[k]))

		switch k {
		case varlen.Cwd, varlen.Filename, varlen.CgroupPath,
			varlen.Path, varlen.OldPath, varlen.NewPath, varlen.TTYOutput,
			varlen.SymlinkTargetPath:
			_, err := w.WriteString(v.(string))
			assert.Nil(t, err)
			assert.Nil(t, w.WriteByte(0))
		case varlen.Argv:
			for _, str := range v.([]string) {
				_, err := w.WriteString(str)
				assert.Nil(t, err)
				assert.Nil(t, w.WriteByte(0))
			}
		case varlen.Env:
			for key, value := range v.(map[string]string) {
				_, err := w.WriteString(key)
				assert.Nil(t, err)
				assert.Nil(t, w.WriteByte('='))
				_, err = w.WriteString(value)
				assert.Nil(t, err)
				assert.Nil(t, w.WriteByte(0))
			}
		default:
			t.Fatalf("unsupported varlen type: %d", k)
		}
	}

	assert.Nil(t, w.Flush())
}
