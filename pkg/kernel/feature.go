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
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

func HasBpfTramp() bool {
	prog, err := ebpf.NewProgramWithOptions(
		&ebpf.ProgramSpec{
			Name:       "fp_bpftramp",
			Type:       ebpf.Tracing,
			AttachType: ebpf.AttachTraceFEntry,
			AttachTo:   "inet_dgram_connect",
			Instructions: asm.Instructions{
				asm.Mov.Imm(asm.R0, 0),
				asm.Return(),
			},
			License: "GPL",
		},
		ebpf.ProgramOptions{LogDisabled: true},
	)
	if err != nil {
		return false
	}
	defer prog.Close()

	link, err := link.AttachTracing(link.TracingOptions{
		Program:    prog,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		return false
	}
	defer link.Close()

	return true
}
