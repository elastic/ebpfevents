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
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/go-faker/faker/v4"
	"github.com/stretchr/testify/assert"

	"github.com/elastic/ebpfevents"
	"github.com/elastic/ebpfevents/pkg/endian"
	"github.com/elastic/ebpfevents/pkg/testutils"
	"github.com/elastic/ebpfevents/pkg/varlen"
)

func writeProcessFork(t *testing.T, w *bufio.Writer, ev ebpfevents.ProcessFork) {
	t.Helper()

	assert.Nil(t, binary.Write(w, endian.Native, ev.ParentPids))
	assert.Nil(t, binary.Write(w, endian.Native, ev.ChildPids))
	assert.Nil(t, binary.Write(w, endian.Native, ev.Creds))
	testutils.WriteVarlenFields(t, w, varlen.Map{
		varlen.CgroupPath: ev.CgroupPath,
	})

	assert.Nil(t, w.Flush())
}

func TestProcessFork(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	w := bufio.NewWriter(buf)

	var expectedEvent ebpfevents.ProcessFork
	assert.Nil(t, faker.FakeData(&expectedEvent))
	writeProcessFork(t, w, expectedEvent)

	var newEvent ebpfevents.ProcessFork
	assert.Nil(t, newEvent.Unmarshal(bytes.NewReader(buf.Bytes())))
	assert.Equal(t, expectedEvent, newEvent)
}

func writeProcessExec(t *testing.T, w *bufio.Writer, ev ebpfevents.ProcessExec) {
	t.Helper()

	assert.Nil(t, binary.Write(w, endian.Native, ev.Pids))
	assert.Nil(t, binary.Write(w, endian.Native, ev.Creds))
	assert.Nil(t, binary.Write(w, endian.Native, ev.CTTY))
	testutils.WriteVarlenFields(t, w, varlen.Map{
		varlen.Cwd:        ev.Cwd,
		varlen.Argv:       ev.Argv,
		varlen.Env:        ev.Env,
		varlen.Filename:   ev.Filename,
		varlen.CgroupPath: ev.CgroupPath,
	})

	assert.Nil(t, w.Flush())
}

func TestProcessExec(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	w := bufio.NewWriter(buf)

	var expectedEvent ebpfevents.ProcessExec
	assert.Nil(t, faker.FakeData(&expectedEvent))
	writeProcessExec(t, w, expectedEvent)

	var newEvent ebpfevents.ProcessExec
	assert.Nil(t, newEvent.Unmarshal(bytes.NewReader(buf.Bytes())))
	assert.Equal(t, expectedEvent, newEvent)
}

func writeProcessExit(t *testing.T, w *bufio.Writer, ev ebpfevents.ProcessExit) {
	t.Helper()

	assert.Nil(t, binary.Write(w, endian.Native, ev.Pids))
	assert.Nil(t, binary.Write(w, endian.Native, ev.ExitCode))
	testutils.WriteVarlenFields(t, w, varlen.Map{
		varlen.CgroupPath: ev.CgroupPath,
	})

	assert.Nil(t, w.Flush())
}

func TestProcessExit(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	w := bufio.NewWriter(buf)

	var expectedEvent ebpfevents.ProcessExit
	assert.Nil(t, faker.FakeData(&expectedEvent))
	writeProcessExit(t, w, expectedEvent)

	var newEvent ebpfevents.ProcessExit
	assert.Nil(t, newEvent.Unmarshal(bytes.NewReader(buf.Bytes())))
	assert.Equal(t, expectedEvent, newEvent)
}

func writeProcessSetsid(t *testing.T, w *bufio.Writer, ev ebpfevents.ProcessSetsid) {
	t.Helper()

	assert.Nil(t, binary.Write(w, endian.Native, ev.Pids))

	assert.Nil(t, w.Flush())
}

func TestProcessSetsid(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	w := bufio.NewWriter(buf)

	var expectedEvent ebpfevents.ProcessSetsid
	assert.Nil(t, faker.FakeData(&expectedEvent))
	writeProcessSetsid(t, w, expectedEvent)

	var newEvent ebpfevents.ProcessSetsid
	assert.Nil(t, newEvent.Unmarshal(bytes.NewReader(buf.Bytes())))
	assert.Equal(t, expectedEvent, newEvent)
}

func writeProcessSetuid(t *testing.T, w *bufio.Writer, ev ebpfevents.ProcessSetuid) {
	t.Helper()

	assert.Nil(t, binary.Write(w, endian.Native, ev.Pids))
	assert.Nil(t, binary.Write(w, endian.Native, ev.NewRuid))
	assert.Nil(t, binary.Write(w, endian.Native, ev.NewEuid))
	assert.Nil(t, binary.Write(w, endian.Native, ev.NewRgid))
	assert.Nil(t, binary.Write(w, endian.Native, ev.NewEgid))

	assert.Nil(t, w.Flush())
}

func TestProcessSetuid(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	w := bufio.NewWriter(buf)

	var expectedEvent ebpfevents.ProcessSetuid
	assert.Nil(t, faker.FakeData(&expectedEvent))
	writeProcessSetuid(t, w, expectedEvent)

	var newEvent ebpfevents.ProcessSetuid
	assert.Nil(t, newEvent.Unmarshal(bytes.NewReader(buf.Bytes())))
	assert.Equal(t, expectedEvent, newEvent)
}

func writeProcessSetgid(t *testing.T, w *bufio.Writer, ev ebpfevents.ProcessSetgid) {
	t.Helper()

	assert.Nil(t, binary.Write(w, endian.Native, ev.Pids))
	assert.Nil(t, binary.Write(w, endian.Native, ev.NewRgid))
	assert.Nil(t, binary.Write(w, endian.Native, ev.NewEgid))
	assert.Nil(t, binary.Write(w, endian.Native, ev.NewRuid))
	assert.Nil(t, binary.Write(w, endian.Native, ev.NewEuid))

	assert.Nil(t, w.Flush())
}

func TestProcessSetgid(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	w := bufio.NewWriter(buf)

	var expectedEvent ebpfevents.ProcessSetgid
	assert.Nil(t, faker.FakeData(&expectedEvent))
	writeProcessSetgid(t, w, expectedEvent)

	var newEvent ebpfevents.ProcessSetgid
	assert.Nil(t, newEvent.Unmarshal(bytes.NewReader(buf.Bytes())))
	assert.Equal(t, expectedEvent, newEvent)
}

func writeProcessTTYWrite(t *testing.T, w *bufio.Writer, ev ebpfevents.ProcessTTYWrite) {
	t.Helper()

	assert.Nil(t, binary.Write(w, endian.Native, ev.Pids))
	assert.Nil(t, binary.Write(w, endian.Native, ev.Truncated))
	assert.Nil(t, binary.Write(w, endian.Native, ev.CTTY))
	assert.Nil(t, binary.Write(w, endian.Native, ev.TTY))
	_, err := w.WriteString(ev.Comm)
	assert.Nil(t, err)
	assert.Nil(t, w.WriteByte(0))
	testutils.WriteVarlenFields(t, w, varlen.Map{
		varlen.TTYOutput: ev.Output,
	})

	assert.Nil(t, w.Flush())
}

func TestProcessTTYWrite(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	w := bufio.NewWriter(buf)

	var expectedEvent ebpfevents.ProcessTTYWrite
	assert.Nil(t, faker.FakeData(&expectedEvent))
	writeProcessTTYWrite(t, w, expectedEvent)

	var newEvent ebpfevents.ProcessTTYWrite
	assert.Nil(t, newEvent.Unmarshal(bytes.NewReader(buf.Bytes())))
	assert.Equal(t, expectedEvent, newEvent)
}
