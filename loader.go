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

package ebpfevents

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/elastic/ebpfevents/internal/kernel"
)

type Loader struct {
	// features
	hasBpfTramp bool

	// bpf objects
	kbtf   *btf.Spec
	objs   bpfObjects
	links  []link.Link
	reader *ringbuf.Reader

	// .rodata constants
	constants map[string]any
}

func NewLoader() (*Loader, error) {
	l := &Loader{
		constants: make(map[string]any),
		links:     make([]link.Link, 0),
	}
	l.constants["consumer_pid"] = uint32(os.Getpid())

	if err := kernel.CheckSupported(); err != nil {
		return nil, fmt.Errorf("check kernel version: %v", err)
	}

	kbtf, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("load kernel btf: %v", err)
	}
	l.kbtf = kbtf

	if err = features.HaveProgramType(ebpf.Tracing); err == nil {
		l.hasBpfTramp = true
	}

	if err := l.fillIndexes(); err != nil {
		return nil, fmt.Errorf("fill indexes: %v", err)
	}
	if err := l.loadBpf(); err != nil {
		return nil, fmt.Errorf("load bpf: %v", err)
	}

	return l, nil
}

func (l *Loader) loadBpf() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("rlimit remove memlock: %v", err)
	}

	spec, err := loadBpf()
	if err != nil {
		return fmt.Errorf("load collection: %v", err)
	}
	if err := spec.RewriteConstants(l.constants); err != nil {
		return fmt.Errorf("rewrite constants: %v", err)
	}
	spec.Maps["event_buffer_map"].MaxEntries = uint32(runtime.NumCPU())

	var opts ebpf.CollectionOptions
	opts.Programs.LogSize = 1 << 26
	opts.Programs.LogLevel = ebpf.LogLevelInstruction

	if err := spec.LoadAndAssign(&l.objs, &opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			for _, line := range ve.Log {
				fmt.Println(line)
			}
			return fmt.Errorf("verifier error: %w", err)
		}
		return fmt.Errorf("error loading bpf probes: %v", err)
	}
	defer func() {
		btf.FlushKernelSpec()
		runtime.GC()
	}()

	rd, err := ringbuf.NewReader(l.objs.bpfMaps.Ringbuf)
	if err != nil {
		return fmt.Errorf("error opening ringbuf reader: %v", err)
	}
	l.reader = rd

	if err := l.attachBpfProgs(); err != nil {
		return fmt.Errorf("error attaching bpf programs: %v", err)
	}

	return nil
}

func (l *Loader) attachBpfProgs() error {
	attachTracing := func(at ebpf.AttachType, prog *ebpf.Program) error {
		lnk, err := link.AttachTracing(link.TracingOptions{
			Program:    prog,
			AttachType: at,
		})
		if err != nil {
			return fmt.Errorf("attach tracing %q: %v", prog.String(), err)
		}
		l.links = append(l.links, lnk)
		return nil
	}
	attachFentry := func(prog *ebpf.Program) error {
		return attachTracing(ebpf.AttachTraceFEntry, prog)
	}
	attachFexit := func(prog *ebpf.Program) error {
		return attachTracing(ebpf.AttachTraceFExit, prog)
	}
	attachRawTp := func(prog *ebpf.Program) error {
		return attachTracing(ebpf.AttachTraceRawTp, prog)
	}
	attachKprobe := func(sym string, prog *ebpf.Program) error {
		lnk, err := link.Kprobe(sym, prog, nil)
		if err != nil {
			return fmt.Errorf("attach kprobe %q: %v", prog.String(), err)
		}
		l.links = append(l.links, lnk)
		return nil
	}
	attachKretprobe := func(sym string, prog *ebpf.Program) error {
		lnk, err := link.Kretprobe(sym, prog, nil)
		if err != nil {
			return fmt.Errorf("attach kretprobe %q: %v", prog.String(), err)
		}
		l.links = append(l.links, lnk)
		return nil
	}
	attachTracepoint := func(group, name string, prog *ebpf.Program) error {
		lnk, err := link.Tracepoint(group, name, prog, nil)
		if err != nil {
			return fmt.Errorf("attach tracepoint '%s/%s': %v", group, name, err)
		}
		l.links = append(l.links, lnk)
		return nil
	}

	attach := func(errs *[]error, err error) {
		if err != nil {
			*errs = append(*errs, err)
		}
	}
	var errs []error

	// do_renameat2
	if l.hasBpfTramp && kernel.FuncExists(l.kbtf, "do_renameat2") {
		attach(&errs, attachFentry(l.objs.FentryDoRenameat2))
	} else {
		attach(&errs, attachKprobe("do_renameat2", l.objs.KprobeDoRenameat2))
	}

	// tcp_v6_connect
	if l.hasBpfTramp && kernel.FuncExists(l.kbtf, "tcp_v6_connect") {
		attach(&errs, attachFexit(l.objs.FexitTcpV6Connect))
	} else {
		attach(&errs, attachKprobe("tcp_v6_connect", l.objs.KprobeTcpV6Connect))
		attach(&errs, attachKretprobe("tcp_v6_connect", l.objs.KretprobeTcpV6Connect))
	}

	// tty_write
	if l.hasBpfTramp && kernel.FuncExists(l.kbtf, "tty_write") {
		attach(&errs, attachFentry(l.objs.FentryTtyWrite))
	} else {
		attach(&errs, attachKprobe("tty_write", l.objs.KprobeTtyWrite))
	}

	// generic bpf trampoline
	if l.hasBpfTramp {
		attach(&errs, attachFentry(l.objs.FentryDoUnlinkat))
		attach(&errs, attachFentry(l.objs.FentryMntWantWrite))
		attach(&errs, attachFentry(l.objs.FentryVfsUnlink))
		attach(&errs, attachFexit(l.objs.FexitVfsUnlink))
		attach(&errs, attachFexit(l.objs.FexitDoFilpOpen))
		attach(&errs, attachFentry(l.objs.FentryVfsRename))
		attach(&errs, attachFexit(l.objs.FexitVfsRename))
		attach(&errs, attachFentry(l.objs.FentryTaskstatsExit))
		attach(&errs, attachFentry(l.objs.FentryCommitCreds))
		attach(&errs, attachFexit(l.objs.FexitInetCskAccept))
		attach(&errs, attachFexit(l.objs.FexitTcpV4Connect))
		attach(&errs, attachFentry(l.objs.FentryTcpClose))
	} else {
		attach(&errs, attachKprobe("do_unlinkat", l.objs.KprobeDoUnlinkat))
		attach(&errs, attachKprobe("mnt_want_write", l.objs.KprobeMntWantWrite))
		attach(&errs, attachKprobe("vfs_unlink", l.objs.KprobeVfsUnlink))
		attach(&errs, attachKretprobe("vfs_unlink", l.objs.KretprobeVfsUnlink))
		attach(&errs, attachKretprobe("do_filp_open", l.objs.KretprobeDoFilpOpen))
		attach(&errs, attachKprobe("vfs_rename", l.objs.KprobeVfsRename))
		attach(&errs, attachKretprobe("vfs_rename", l.objs.KretprobeVfsRename))
		attach(&errs, attachKprobe("taskstats_exit", l.objs.KprobeTaskstatsExit))
		attach(&errs, attachKprobe("commit_creds", l.objs.KprobeCommitCreds))
		attach(&errs, attachKretprobe("inet_csk_accept", l.objs.KretprobeInetCskAccept))
		attach(&errs, attachKprobe("tcp_v4_connect", l.objs.KprobeTcpV4Connect))
		attach(&errs, attachKretprobe("tcp_v4_connect", l.objs.KretprobeTcpV4Connect))
		attach(&errs, attachKprobe("tcp_close", l.objs.KprobeTcpClose))
	}

	attach(&errs, attachRawTp(l.objs.SchedProcessExec))
	attach(&errs, attachRawTp(l.objs.SchedProcessFork))
	attach(&errs, attachTracepoint("syscalls", "sys_exit_setsid", l.objs.TracepointSyscallsSysExitSetsid))

	if len(errs) != 0 {
		msg := "bpf program(s) attach failed: "
		for _, err := range errs {
			msg += err.Error()
			msg += ";"
		}
		return errors.New(msg)
	}

	return nil
}

func (l *Loader) EventLoop(ctx context.Context, out chan<- Event, errs chan<- error) {
	in := make(chan ringbuf.Record)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := l.reader.Read()
				if errors.Is(err, ringbuf.ErrClosed) {
					break
				}
				if err != nil {
					continue
				}
				in <- record
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case record := <-in:
			event, err := NewEvent(record.RawSample)
			if err != nil {
				errs <- err
				continue
			}
			out <- *event
		}
	}
}

func (l *Loader) Close() error {
	if l.reader != nil {
		l.reader.Close()
	}
	for _, lnk := range l.links {
		lnk.Close()
	}
	return nil
}
