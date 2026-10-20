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
	"errors"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/ebpfevents"
)

// The round-trip tests in event_test.go encode an event with a writer that
// mirrors the Go decoder, so a field the decoder skips is skipped by the
// writer too. That is how ProcessExit could miss comm and ns for as long as it
// did: the test passed while every real exit event failed to decode.
//
// This test takes its layout from the C side instead: struct sizes are read
// from the BTF of the compiled objects bpf2go embeds, so they are what the
// probes actually write, packing included. Each decoder is fed exactly one C
// event body, plus an empty varlen section where the C struct has one, and
// must consume all of it: a decoder that reads too little leaves bytes behind,
// one that reads too much runs out of input.
//
// clang only keeps BTF for the types the programs still reference after
// optimisation. That covers every building block below, but of the event
// structs themselves only ebpf_net_event, so how the other events compose
// those blocks is transcribed from GPL/Events/EbpfEventProto.h in elastic/ebpf.
// When an event struct changes, update its row from the header, not from the
// Go code. Where the event struct is in the BTF, its row is checked against it.
var cObjects = []string{"bpf_x86_bpfel.o", "bpf_arm64_bpfel.o"}

// cLayout holds the sizes of the C structs events are built from.
type cLayout struct {
	spec         *btf.Spec
	header       int // struct ebpf_event_header
	pidInfo      int // struct ebpf_pid_info
	credInfo     int // struct ebpf_cred_info
	ttyDev       int // struct ebpf_tty_dev
	comm         int // char comm[TASK_COMM_LEN]
	namespace    int // struct ebpf_namespace_info
	fileInfo     int // struct ebpf_file_info
	netInfo      int // struct ebpf_net_info
	varlenHeader int // struct ebpf_varlen_fields_start: nfields, size
}

func loadCLayout(t *testing.T, obj string) cLayout {
	t.Helper()
	spec, err := btf.LoadSpec(obj)
	require.NoError(t, err, "reading BTF from %s", obj)

	return cLayout{
		spec:         spec,
		header:       cStructSize(t, spec, "ebpf_event_header"),
		pidInfo:      cStructSize(t, spec, "ebpf_pid_info"),
		credInfo:     cStructSize(t, spec, "ebpf_cred_info"),
		ttyDev:       cStructSize(t, spec, "ebpf_tty_dev"),
		comm:         cMemberSize(t, spec, "ebpf_net_event", "comm"),
		namespace:    cStructSize(t, spec, "ebpf_namespace_info"),
		fileInfo:     cStructSize(t, spec, "ebpf_file_info"),
		netInfo:      cStructSize(t, spec, "ebpf_net_info"),
		varlenHeader: cStructSize(t, spec, "ebpf_varlen_fields_start"),
	}
}

func cStruct(t *testing.T, spec *btf.Spec, name string) *btf.Struct {
	t.Helper()
	var s *btf.Struct
	require.NoError(t, spec.TypeByName(name, &s), "struct %s", name)
	return s
}

func cStructSize(t *testing.T, spec *btf.Spec, name string) int {
	t.Helper()
	return int(cStruct(t, spec, name).Size)
}

func cMemberSize(t *testing.T, spec *btf.Spec, structName, member string) int {
	t.Helper()
	for _, m := range cStruct(t, spec, structName).Members {
		if m.Name == member {
			size, err := btf.Sizeof(m.Type)
			require.NoError(t, err, "sizing %s.%s", structName, member)
			return size
		}
	}
	require.FailNow(t, "member not found", "struct %s has no member %s", structName, member)
	return 0
}

type decoder interface {
	Unmarshal(r *bytes.Reader) error
}

func TestEventDecodersMatchCLayout(t *testing.T) {
	for _, obj := range cObjects {
		t.Run(obj, func(t *testing.T) {
			c := loadCLayout(t, obj)

			cases := []struct {
				cStruct string
				dec     decoder
				body    int  // fixed part after struct ebpf_event_header
				varlen  bool // ends in struct ebpf_varlen_fields_start
			}{
				{"ebpf_process_fork_event", &ebpfevents.ProcessFork{}, 2*c.pidInfo + c.credInfo + c.ttyDev + c.comm + c.namespace, true},
				{"ebpf_process_exec_event", &ebpfevents.ProcessExec{}, c.pidInfo + c.credInfo + c.ttyDev + c.comm + c.namespace + 4 + 4, true},
				{"ebpf_process_exit_event", &ebpfevents.ProcessExit{}, c.pidInfo + c.credInfo + c.ttyDev + c.comm + c.namespace + 4, true},
				{"ebpf_process_setsid_event", &ebpfevents.ProcessSetsid{}, c.pidInfo, false},
				{"ebpf_process_setuid_event", &ebpfevents.ProcessSetuid{}, c.pidInfo + 4*4, false},
				{"ebpf_process_setgid_event", &ebpfevents.ProcessSetgid{}, c.pidInfo + 4*4, false},
				{"ebpf_process_tty_write_event", &ebpfevents.ProcessTTYWrite{}, c.pidInfo + 8 + 2*c.ttyDev + c.comm, true},
				{"ebpf_file_delete_event", &ebpfevents.FileDelete{}, c.pidInfo + c.credInfo + c.fileInfo + 4 + c.comm, true},
				{"ebpf_file_create_event", &ebpfevents.FileCreate{}, c.pidInfo + c.credInfo + c.fileInfo + 4 + c.comm, true},
				{"ebpf_file_rename_event", &ebpfevents.FileRename{}, c.pidInfo + c.credInfo + c.fileInfo + 4 + c.comm, true},
				{"ebpf_file_modify_event", &ebpfevents.FileModify{}, c.pidInfo + c.credInfo + c.fileInfo + 4 + 4 + c.comm, true},
				{"ebpf_net_event", &ebpfevents.NetEvent{}, c.pidInfo + c.netInfo + c.comm, false},
			}

			for _, tc := range cases {
				t.Run(tc.cStruct, func(t *testing.T) {
					size := tc.body
					if tc.varlen {
						size += c.varlenHeader // nfields = 0, size = 0: no varlen fields
					}

					var s *btf.Struct
					switch err := c.spec.TypeByName(tc.cStruct, &s); {
					case err == nil:
						assert.Equal(t, int(s.Size), c.header+size, "%s: the row does not add up to the C struct", tc.cStruct)
					case !errors.Is(err, btf.ErrNotFound):
						require.NoError(t, err)
					}

					r := bytes.NewReader(make([]byte, size))
					require.NoError(t, tc.dec.Unmarshal(r), "decoding a %d-byte %s", size, tc.cStruct)
					assert.Zero(t, r.Len(), "%s: the decoder left %d of %d bytes unread", tc.cStruct, r.Len(), size)
				})
			}
		})
	}
}

// A comm buffer is TASK_COMM_LEN bytes, and only the part before the first NUL
// is the name: the event buffer is reused, so the rest can hold leftovers.
func TestProcessExitCommStopsAtNUL(t *testing.T) {
	c := loadCLayout(t, cObjects[0])
	body := make([]byte, c.pidInfo+c.credInfo+c.ttyDev+c.comm+c.namespace+4+c.varlenHeader)
	comm := body[c.pidInfo+c.credInfo+c.ttyDev:]
	copy(comm, "sleep\x00{K\xbcBH\xbfp")

	var ev ebpfevents.ProcessExit
	r := bytes.NewReader(body)
	require.NoError(t, ev.Unmarshal(r))
	assert.Equal(t, "sleep", ev.Comm)
	assert.Zero(t, r.Len())
}
