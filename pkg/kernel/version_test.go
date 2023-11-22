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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewVersion(t *testing.T) {
	tests := []struct {
		vstring         string
		maj, min, patch int
	}{
		{"1.0.0", 1, 0, 0},
		{"1.2.3", 1, 2, 3},
		{"0.0.0", 0, 0, 0},
		{"1.2", 1, 2, 0},
		{"1", 1, 0, 0},
		{"1.2.3.4.5", 1, 2, 3},
		{"", 0, 0, 0},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("test new version #%d", i), func(t *testing.T) {
			v, err := new(tt.vstring)
			assert.NoError(t, err)
			assert.Equal(t, v.maj, tt.maj)
			assert.Equal(t, v.min, tt.min)
			assert.Equal(t, v.patch, tt.patch)
		})
	}
}

func TestNewVersionError(t *testing.T) {
	tests := []string{
		"1.-1.0",
		".1.0",
		"1.1.",
	}

	for i, s := range tests {
		t.Run(fmt.Sprintf("test new version error #%d", i), func(t *testing.T) {
			_, err := new(s)
			assert.Error(t, err)
		})
	}
}
