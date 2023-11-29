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
	"net/netip"
	"testing"
	"time"

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
	expectedEvent.Comm = expectedEvent.Comm[:ebpfevents.TaskCommLen-1]
	writeProcessTTYWrite(t, w, expectedEvent)

	var newEvent ebpfevents.ProcessTTYWrite
	assert.Nil(t, newEvent.Unmarshal(bytes.NewReader(buf.Bytes())))
	assert.Equal(t, expectedEvent, newEvent)
}

func writeFileInfo(t *testing.T, w *bufio.Writer, fi ebpfevents.FileInfo) {
	t.Helper()

	assert.Nil(t, binary.Write(w, endian.Native, fi.Type))
	assert.Nil(t, binary.Write(w, endian.Native, fi.Inode))
	assert.Nil(t, binary.Write(w, endian.Native, uint16(fi.Mode)))
	assert.Nil(t, binary.Write(w, endian.Native, fi.Size))
	assert.Nil(t, binary.Write(w, endian.Native, fi.Uid))
	assert.Nil(t, binary.Write(w, endian.Native, fi.Gid))
	assert.Nil(t, binary.Write(w, endian.Native, uint64(fi.Atime.Nanosecond())))
	assert.Nil(t, binary.Write(w, endian.Native, uint64(fi.Mtime.Nanosecond())))
	assert.Nil(t, binary.Write(w, endian.Native, uint64(fi.Ctime.Nanosecond())))

	assert.Nil(t, w.Flush())
}

func writeFileCreate(t *testing.T, w *bufio.Writer, ev ebpfevents.FileCreate) {
	t.Helper()

	assert.Nil(t, binary.Write(w, endian.Native, ev.Pids))
	writeFileInfo(t, w, ev.Finfo)
	assert.Nil(t, binary.Write(w, endian.Native, ev.MountNs))
	_, err := w.WriteString(ev.Comm)
	assert.Nil(t, err)
	assert.Nil(t, w.WriteByte(0))
	testutils.WriteVarlenFields(t, w, varlen.Map{
		varlen.Path:              ev.Path,
		varlen.SymlinkTargetPath: ev.SymlinkTargetPath,
	})

	assert.Nil(t, w.Flush())
}

func TestFileCreate(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	w := bufio.NewWriter(buf)

	var expectedEvent ebpfevents.FileCreate
	assert.Nil(t, faker.FakeData(&expectedEvent))
	expectedEvent.Comm = expectedEvent.Comm[:ebpfevents.TaskCommLen-1]
	expectedEvent.Finfo.Atime = time.Unix(0, int64(1))
	expectedEvent.Finfo.Mtime = time.Unix(0, int64(2))
	expectedEvent.Finfo.Ctime = time.Unix(0, int64(3))
	writeFileCreate(t, w, expectedEvent)

	var newEvent ebpfevents.FileCreate
	assert.Nil(t, newEvent.Unmarshal(bytes.NewReader(buf.Bytes())))
	assert.Equal(t, expectedEvent, newEvent)
}

func writeFileRename(t *testing.T, w *bufio.Writer, ev ebpfevents.FileRename) {
	t.Helper()

	assert.Nil(t, binary.Write(w, endian.Native, ev.Pids))
	writeFileInfo(t, w, ev.Finfo)
	assert.Nil(t, binary.Write(w, endian.Native, ev.MountNs))
	_, err := w.WriteString(ev.Comm)
	assert.Nil(t, err)
	assert.Nil(t, w.WriteByte(0))
	testutils.WriteVarlenFields(t, w, varlen.Map{
		varlen.OldPath:           ev.OldPath,
		varlen.NewPath:           ev.NewPath,
		varlen.SymlinkTargetPath: ev.SymlinkTargetPath,
	})

	assert.Nil(t, w.Flush())
}

func TestFileRename(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	w := bufio.NewWriter(buf)

	var expectedEvent ebpfevents.FileRename
	assert.Nil(t, faker.FakeData(&expectedEvent))
	expectedEvent.Comm = expectedEvent.Comm[:ebpfevents.TaskCommLen-1]
	expectedEvent.Finfo.Atime = time.Unix(0, int64(1))
	expectedEvent.Finfo.Mtime = time.Unix(0, int64(2))
	expectedEvent.Finfo.Ctime = time.Unix(0, int64(3))
	writeFileRename(t, w, expectedEvent)

	var newEvent ebpfevents.FileRename
	assert.Nil(t, newEvent.Unmarshal(bytes.NewReader(buf.Bytes())))
	assert.Equal(t, expectedEvent, newEvent)
}

func writeFileDelete(t *testing.T, w *bufio.Writer, ev ebpfevents.FileDelete) {
	t.Helper()

	assert.Nil(t, binary.Write(w, endian.Native, ev.Pids))
	writeFileInfo(t, w, ev.Finfo)
	assert.Nil(t, binary.Write(w, endian.Native, ev.MountNs))
	_, err := w.WriteString(ev.Comm)
	assert.Nil(t, err)
	assert.Nil(t, w.WriteByte(0))
	testutils.WriteVarlenFields(t, w, varlen.Map{
		varlen.Path:              ev.Path,
		varlen.SymlinkTargetPath: ev.SymlinkTargetPath,
	})

	assert.Nil(t, w.Flush())
}

func TestFileDelete(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	w := bufio.NewWriter(buf)

	var expectedEvent ebpfevents.FileDelete
	assert.Nil(t, faker.FakeData(&expectedEvent))
	expectedEvent.Comm = expectedEvent.Comm[:ebpfevents.TaskCommLen-1]
	expectedEvent.Finfo.Atime = time.Unix(0, int64(1))
	expectedEvent.Finfo.Mtime = time.Unix(0, int64(2))
	expectedEvent.Finfo.Ctime = time.Unix(0, int64(3))
	writeFileDelete(t, w, expectedEvent)

	var newEvent ebpfevents.FileDelete
	assert.Nil(t, newEvent.Unmarshal(bytes.NewReader(buf.Bytes())))
	assert.Equal(t, expectedEvent, newEvent)
}

func writeNetInfo(t *testing.T, w *bufio.Writer, ni ebpfevents.NetInfo) {
	t.Helper()

	assert.Nil(t, binary.Write(w, endian.Native, uint32(ni.Transport)))
	assert.Nil(t, binary.Write(w, endian.Native, uint32(ni.Family)))
	assert.Nil(t, binary.Write(w, endian.Native, ni.SourceAddress.AsSlice()))
	assert.Nil(t, binary.Write(w, endian.Native, ni.DestinationAddress.AsSlice()))
	assert.Nil(t, binary.Write(w, endian.Native, ni.SourcePort))
	assert.Nil(t, binary.Write(w, endian.Native, ni.DestinationPort))
	assert.Nil(t, binary.Write(w, endian.Native, ni.NetNs))
	assert.Nil(t, binary.Write(w, endian.Native, ni.BytesSent))
	assert.Nil(t, binary.Write(w, endian.Native, ni.BytesReceived))

	assert.Nil(t, w.Flush())
}

func writeNetEvent(t *testing.T, w *bufio.Writer, ev ebpfevents.NetEvent) {
	t.Helper()

	assert.Nil(t, binary.Write(w, endian.Native, ev.Pids))
	writeNetInfo(t, w, ev.Net)
	_, err := w.WriteString(ev.Comm)
	assert.Nil(t, err)
	assert.Nil(t, w.WriteByte(0))

	assert.Nil(t, w.Flush())
}

func TestNetEvent(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	w := bufio.NewWriter(buf)

	var expectedEvent ebpfevents.NetEvent
	assert.Nil(t, faker.FakeData(&expectedEvent))
	expectedEvent.Comm = expectedEvent.Comm[:ebpfevents.TaskCommLen-1]
	switch expectedEvent.Net.Family {
	case ebpfevents.AFInet:
		expectedEvent.Net.SourceAddress = netip.MustParseAddr("1.2.3.4")
		expectedEvent.Net.DestinationAddress = netip.MustParseAddr("5.6.7.8")
	case ebpfevents.AFInet6:
		expectedEvent.Net.SourceAddress = netip.MustParseAddr("2001:0db8:85a3:0000:0000:8a2e:0370:7333")
		expectedEvent.Net.DestinationAddress = netip.MustParseAddr("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
	}
	writeNetEvent(t, w, expectedEvent)

	var newEvent ebpfevents.NetEvent
	assert.Nil(t, newEvent.Unmarshal(bytes.NewReader(buf.Bytes())))
	assert.Equal(t, expectedEvent, newEvent)
}
