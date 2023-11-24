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

package varlen_test

import (
	"bufio"
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/ebpfevents/pkg/testutils"
	"github.com/elastic/ebpfevents/pkg/varlen"
)

func TestDeserializeVarlenFields(t *testing.T) {
	buf := bytes.NewBuffer(nil)

	expectedMap := varlen.Map{
		varlen.Cwd:               "test_cwd",
		varlen.Argv:              []string{"a", "r", "g", "v"},
		varlen.Env:               map[string]string{"a": "b", "c": "d"},
		varlen.Filename:          "test_filename",
		varlen.Path:              "test_path",
		varlen.OldPath:           "test_oldpath",
		varlen.NewPath:           "test_newpath",
		varlen.TTYOutput:         "test_tty",
		varlen.CgroupPath:        "test_cgroup",
		varlen.SymlinkTargetPath: "test_symlink",
	}
	testutils.WriteVarlenFields(t, bufio.NewWriter(buf), expectedMap)

	m, err := varlen.DeserializeVarlenFields(bytes.NewReader(buf.Bytes()))
	assert.Nil(t, err)

	assert.Equal(t, expectedMap, m)
}
