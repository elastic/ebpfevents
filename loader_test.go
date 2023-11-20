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

package ebpfevents_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/ebpfevents"
)

func TestNewLoader(t *testing.T) {
	l, err := ebpfevents.NewLoader()
	assert.Nil(t, err)
	defer l.Close()

	events := make(chan ebpfevents.Event, 3)
	errors := make(chan error, 3)
	go l.EventLoop(context.Background(), events, errors)

	// trigger an event
	fname := "testloader"
	_, err = os.Create(fname)
	assert.Nil(t, err)
	defer os.Remove(fname)

	time.Sleep(time.Second)

	assert.NotEmpty(t, events)
	assert.Empty(t, errors)
}
