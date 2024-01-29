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

//go:build linux && (amd64 || arm64)

package ebpfevents

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/elastic/ebpfevents/pkg/kernel"
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

const rbTimeout = 3 * time.Second

const (
	argIdxFmt      = "arg__%s__%s__"    // func, arg
	retIdxFmt      = "ret__%s__"        // func
	argExistsFmt   = "exists__%s__%s__" // func, arg
	fieldOffsetFmt = "off__%s__%s__"    // struct, field
)

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

	// Try to load all with default logsize
	if err := spec.LoadAndAssign(&l.objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// If we hit a verifier error, try to load all
			// with an increased logsize. This heavily impacts
			// load times, so do this only if already asserted
			// the probe is failing to load.
			var opts ebpf.CollectionOptions
			opts.Programs.LogSize = 1 << 26
			opts.Programs.LogLevel = ebpf.LogLevelInstruction

			if err2 := spec.LoadAndAssign(&l.objs, &opts); err2 != nil {
				var ve2 *ebpf.VerifierError
				if errors.As(err2, &ve2) {
					for _, line := range ve2.Log {
						fmt.Println(line)
					}
					return fmt.Errorf("verifier error: %w", err2)
				}
				return fmt.Errorf("error loading bpf probes: %v", err2)
			}
			return errors.New("expected error (???), probes load successfully at the second try")
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

	var err error

	// do_renameat2
	if l.hasBpfTramp && kernel.FuncExists(l.kbtf, "do_renameat2") {
		err = errors.Join(err, attachFentry(l.objs.FentryDoRenameat2))
	} else {
		err = errors.Join(err, attachKprobe("do_renameat2", l.objs.KprobeDoRenameat2))
	}

	// tcp_v6_connect
	if l.hasBpfTramp && kernel.FuncExists(l.kbtf, "tcp_v6_connect") {
		err = errors.Join(err, attachFexit(l.objs.FexitTcpV6Connect))
	} else {
		err = errors.Join(err, attachKprobe("tcp_v6_connect", l.objs.KprobeTcpV6Connect))
		err = errors.Join(err, attachKretprobe("tcp_v6_connect", l.objs.KretprobeTcpV6Connect))
	}

	// tty_write
	if l.hasBpfTramp && kernel.FuncExists(l.kbtf, "tty_write") {
		err = errors.Join(err, attachFentry(l.objs.FentryTtyWrite))
	} else {
		err = errors.Join(err, attachKprobe("tty_write", l.objs.KprobeTtyWrite))
	}

	// vfs_writev
	if l.hasBpfTramp && kernel.FuncExists(l.kbtf, "vfs_writev") {
		err = errors.Join(err, attachFexit(l.objs.FexitVfsWritev))
	} else {
		err = errors.Join(err, attachKprobe("vfs_writev", l.objs.KprobeVfsWritev))
		err = errors.Join(err, attachKretprobe("vfs_writev", l.objs.KretprobeVfsWritev))
	}

	// generic bpf trampoline
	if l.hasBpfTramp {
		err = errors.Join(err, attachFentry(l.objs.FentryDoUnlinkat))
		err = errors.Join(err, attachFentry(l.objs.FentryMntWantWrite))
		err = errors.Join(err, attachFentry(l.objs.FentryVfsUnlink))
		err = errors.Join(err, attachFexit(l.objs.FexitVfsUnlink))
		err = errors.Join(err, attachFexit(l.objs.FexitDoFilpOpen))
		err = errors.Join(err, attachFentry(l.objs.FentryVfsRename))
		err = errors.Join(err, attachFexit(l.objs.FexitVfsRename))
		err = errors.Join(err, attachFentry(l.objs.FentryTaskstatsExit))
		err = errors.Join(err, attachFentry(l.objs.FentryCommitCreds))
		err = errors.Join(err, attachFexit(l.objs.FexitInetCskAccept))
		err = errors.Join(err, attachFexit(l.objs.FexitTcpV4Connect))
		err = errors.Join(err, attachFentry(l.objs.FentryTcpClose))
		err = errors.Join(err, attachFexit(l.objs.FexitChmodCommon))
		err = errors.Join(err, attachFexit(l.objs.FexitDoTruncate))
		err = errors.Join(err, attachFexit(l.objs.FexitVfsWrite))
		err = errors.Join(err, attachFexit(l.objs.FexitChownCommon))
	} else {
		err = errors.Join(err, attachKprobe("do_unlinkat", l.objs.KprobeDoUnlinkat))
		err = errors.Join(err, attachKprobe("mnt_want_write", l.objs.KprobeMntWantWrite))
		err = errors.Join(err, attachKprobe("vfs_unlink", l.objs.KprobeVfsUnlink))
		err = errors.Join(err, attachKretprobe("vfs_unlink", l.objs.KretprobeVfsUnlink))
		err = errors.Join(err, attachKretprobe("do_filp_open", l.objs.KretprobeDoFilpOpen))
		err = errors.Join(err, attachKprobe("vfs_rename", l.objs.KprobeVfsRename))
		err = errors.Join(err, attachKretprobe("vfs_rename", l.objs.KretprobeVfsRename))
		err = errors.Join(err, attachKprobe("taskstats_exit", l.objs.KprobeTaskstatsExit))
		err = errors.Join(err, attachKprobe("commit_creds", l.objs.KprobeCommitCreds))
		err = errors.Join(err, attachKretprobe("inet_csk_accept", l.objs.KretprobeInetCskAccept))
		err = errors.Join(err, attachKprobe("tcp_v4_connect", l.objs.KprobeTcpV4Connect))
		err = errors.Join(err, attachKretprobe("tcp_v4_connect", l.objs.KretprobeTcpV4Connect))
		err = errors.Join(err, attachKprobe("tcp_close", l.objs.KprobeTcpClose))
		err = errors.Join(err, attachKprobe("chmod_common", l.objs.KprobeChmodCommon))
		err = errors.Join(err, attachKretprobe("chmod_common", l.objs.KretprobeChmodCommon))
		err = errors.Join(err, attachKprobe("do_truncate", l.objs.KprobeDoTruncate))
		err = errors.Join(err, attachKretprobe("do_truncate", l.objs.KretprobeDoTruncate))
		err = errors.Join(err, attachKprobe("vfs_write", l.objs.KprobeVfsWrite))
		err = errors.Join(err, attachKretprobe("vfs_write", l.objs.KretprobeVfsWrite))
		err = errors.Join(err, attachKprobe("chown_common", l.objs.KprobeChownCommon))
		err = errors.Join(err, attachKretprobe("chown_common", l.objs.KretprobeChownCommon))
	}

	err = errors.Join(err, attachRawTp(l.objs.SchedProcessExec))
	err = errors.Join(err, attachRawTp(l.objs.SchedProcessFork))
	err = errors.Join(err, attachTracepoint("syscalls", "sys_exit_setsid", l.objs.TracepointSyscallsSysExitSetsid))

	return err
}

func (l *Loader) EventLoop(ctx context.Context, out chan<- Record) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			var r Record

			l.reader.SetDeadline(time.Now().Add(rbTimeout))
			record, err := l.reader.Read()
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			if err != nil {
				r.Error = err
				out <- r
				continue
			}

			event, err := NewEvent(record.RawSample)
			if err != nil {
				r.Error = err
			}
			r.Event = event

			out <- r
		}
	}
}

func (l *Loader) BufferLen() uint32 {
	return l.objs.bpfMaps.Ringbuf.MaxEntries()
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

func (l *Loader) fillArgIndex(funcName, argName string) error {
	name := fmt.Sprintf(argIdxFmt, funcName, argName)

	idx, err := kernel.ArgIdxByFunc(l.kbtf, funcName, argName)
	if err != nil {
		return fmt.Errorf("fill %s: %v", name, err)
	}
	l.constants[name] = idx

	return nil
}

func (l *Loader) fillRetIndex(funcName string) error {
	name := fmt.Sprintf(retIdxFmt, funcName)

	idx, err := kernel.RetIdxByFunc(l.kbtf, funcName)
	if err != nil {
		return fmt.Errorf("fill %s: %v", name, err)
	}
	l.constants[name] = idx

	return nil
}

func (l *Loader) fillArgExists(funcName, argName string) error {
	name := fmt.Sprintf(argExistsFmt, funcName, argName)
	l.constants[name] = kernel.ArgExists(l.kbtf, funcName, argName)
	return nil
}

func (l *Loader) fillFieldOffset(structName, fieldName string) error {
	name := fmt.Sprintf(fieldOffsetFmt, structName, fieldName)

	off, err := kernel.FieldOffset(l.kbtf, structName, fieldName)
	if err != nil {
		return fmt.Errorf("fill %s: %v", name, err)
	}
	l.constants[name] = off

	return nil
}

func (l *Loader) fillIndexes() error {
	err := l.fillArgIndex("vfs_unlink", "dentry")
	err = errors.Join(err, l.fillRetIndex("vfs_unlink"))

	if kernel.ArgExists(l.kbtf, "vfs_rename", "rd") {
		err = errors.Join(err, l.fillArgExists("vfs_rename", "rd"))
	} else {
		err = errors.Join(err, l.fillArgIndex("vfs_rename", "old_dentry"))
		err = errors.Join(err, l.fillArgIndex("vfs_rename", "new_dentry"))
	}

	err = errors.Join(err, l.fillRetIndex("vfs_rename"))

	if kernel.FieldExists(l.kbtf, "iov_iter", "__iov") {
		err = errors.Join(err, l.fillFieldOffset("iov_iter", "__iov"))
	}

	err = errors.Join(err, l.fillArgIndex("do_truncate", "filp"))
	err = errors.Join(err, l.fillRetIndex("do_truncate"))

	if kernel.FieldExists(l.kbtf, "inode", "__i_atime") {
		err = errors.Join(err, l.fillFieldOffset("inode", "__i_atime"))
	}
	if kernel.FieldExists(l.kbtf, "inode", "__i_mtime") {
		err = errors.Join(err, l.fillFieldOffset("inode", "__i_mtime"))
	}
	if kernel.FieldExists(l.kbtf, "inode", "__i_ctime") {
		err = errors.Join(err, l.fillFieldOffset("inode", "__i_ctime"))
	}

	return err
}
