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
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/ebpfevents"
)

// The round-trip tests in event_test.go encode an event with a writer that
// mirrors the Go decoder, so a field the decoder skips is skipped by the
// writer too. That is how ProcessExit could miss comm and ns for as long as it
// did: the test passed while every real exit event failed to decode.
//
// This test takes its layout from the C side instead. Every size below is
// transcribed from GPL/Events/EbpfEventProto.h in elastic/ebpf (all structs are
// __attribute__((packed))). Each decoder is fed exactly one C event body, plus
// an empty varlen section where the C struct has one, and must consume all of
// it: a decoder that reads too little leaves bytes behind, one that reads too
// much runs out of input. When the C structs change, update this table from
// the header, not from the Go code.
const (
	cPidInfo      = 8 + 5*4                          // struct ebpf_pid_info
	cCredInfo     = 6*4 + 2*8                        // struct ebpf_cred_info
	cTTYDev       = 2 + 2 + (2 + 2) + 4*4            // struct ebpf_tty_dev: minor, major, winsize, termios
	cComm         = 16                               // char comm[TASK_COMM_LEN]
	cNamespace    = 7 * 4                            // struct ebpf_namespace_info
	cFileInfo     = 4 + 8 + 2 + 8 + 4 + 4 + 3*8      // struct ebpf_file_info
	cNetInfo      = 4 + 4 + 16 + 16 + 2 + 2 + 4 + 16 // struct ebpf_net_info, tcp.close union
	cVarlenHeader = 4 + 8                            // struct ebpf_varlen_fields_start: nfields, size
)

type decoder interface {
	Unmarshal(r *bytes.Reader) error
}

func TestEventDecodersMatchCLayout(t *testing.T) {
	cases := []struct {
		cStruct string
		dec     decoder
		body    int  // fixed part after struct ebpf_event_header
		varlen  bool // ends in struct ebpf_varlen_fields_start
	}{
		{"ebpf_process_fork_event", &ebpfevents.ProcessFork{}, 2*cPidInfo + cCredInfo + cTTYDev + cComm + cNamespace, true},
		{"ebpf_process_exec_event", &ebpfevents.ProcessExec{}, cPidInfo + cCredInfo + cTTYDev + cComm + cNamespace + 4 + 4, true},
		{"ebpf_process_exit_event", &ebpfevents.ProcessExit{}, cPidInfo + cCredInfo + cTTYDev + cComm + cNamespace + 4, true},
		{"ebpf_process_setsid_event", &ebpfevents.ProcessSetsid{}, cPidInfo, false},
		{"ebpf_process_setuid_event", &ebpfevents.ProcessSetuid{}, cPidInfo + 4*4, false},
		{"ebpf_process_setgid_event", &ebpfevents.ProcessSetgid{}, cPidInfo + 4*4, false},
		{"ebpf_process_tty_write_event", &ebpfevents.ProcessTTYWrite{}, cPidInfo + 8 + 2*cTTYDev + cComm, true},
		{"ebpf_file_delete_event", &ebpfevents.FileDelete{}, cPidInfo + cCredInfo + cFileInfo + 4 + cComm, true},
		{"ebpf_file_create_event", &ebpfevents.FileCreate{}, cPidInfo + cCredInfo + cFileInfo + 4 + cComm, true},
		{"ebpf_file_rename_event", &ebpfevents.FileRename{}, cPidInfo + cCredInfo + cFileInfo + 4 + cComm, true},
		{"ebpf_file_modify_event", &ebpfevents.FileModify{}, cPidInfo + cCredInfo + cFileInfo + 4 + 4 + cComm, true},
		{"ebpf_net_event", &ebpfevents.NetEvent{}, cPidInfo + cNetInfo + cComm, false},
	}

	for _, tc := range cases {
		t.Run(tc.cStruct, func(t *testing.T) {
			size := tc.body
			if tc.varlen {
				size += cVarlenHeader // nfields = 0, size = 0: no varlen fields
			}
			r := bytes.NewReader(make([]byte, size))

			require.NoError(t, tc.dec.Unmarshal(r), "decoding a %d-byte %s", size, tc.cStruct)
			assert.Zero(t, r.Len(), "%s: the decoder left %d of %d bytes unread", tc.cStruct, r.Len(), size)
		})
	}
}

// A comm buffer is TASK_COMM_LEN bytes, and only the part before the first NUL
// is the name: the event buffer is reused, so the rest can hold leftovers.
func TestProcessExitCommStopsAtNUL(t *testing.T) {
	body := make([]byte, cPidInfo+cCredInfo+cTTYDev+cComm+cNamespace+4+cVarlenHeader)
	comm := body[cPidInfo+cCredInfo+cTTYDev:]
	copy(comm, "sleep\x00{K\xbcBH\xbfp")

	var ev ebpfevents.ProcessExit
	r := bytes.NewReader(body)
	require.NoError(t, ev.Unmarshal(r))
	assert.Equal(t, "sleep", ev.Comm)
	assert.Zero(t, r.Len())
}
