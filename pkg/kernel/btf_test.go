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

package kernel

import (
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
)

func TestFieldExists(t *testing.T) {
	spec, err := btf.LoadKernelSpec()
	assert.Nil(t, err)

	assert.True(t, FieldExists(spec, "tty_struct", "link"))
	assert.False(t, FieldExists(spec, "tty_struct", "qwerty"))
}

func TestFuncExists(t *testing.T) {
	spec, err := btf.LoadKernelSpec()
	assert.Nil(t, err)

	assert.True(t, FuncExists(spec, "do_filp_open"))
	assert.False(t, FuncExists(spec, "qwerty"))
}

func TestArgExists(t *testing.T) {
	spec, err := btf.LoadKernelSpec()
	assert.Nil(t, err)

	assert.True(t, ArgExists(spec, "do_filp_open", "pathname"))
	assert.False(t, ArgExists(spec, "do_filp_open", "qwerty"))
}

func TestArgIdxByFunc(t *testing.T) {
	spec, err := btf.LoadKernelSpec()
	assert.Nil(t, err)

	expectedIdx := uint32(1)
	idx, err := ArgIdxByFunc(spec, "do_filp_open", "pathname")
	assert.Nil(t, err)
	assert.Equal(t, expectedIdx, idx)
}

func TestFieldOffset(t *testing.T) {
	spec, err := btf.LoadKernelSpec()
	assert.Nil(t, err)

	expectedOffset := uint32(17) // 4xint + 1xchar
	off, err := FieldOffset(spec, "termios", "c_cc")
	assert.Nil(t, err)
	assert.Equal(t, expectedOffset, off)
}
