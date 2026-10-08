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
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
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
	coll   *ebpf.Collection
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

	cache := btf.NewCache()
	kbtf, err := cache.Kernel()
	if err != nil {
		return nil, fmt.Errorf("load kernel btf: %v", err)
	}
	l.kbtf = kbtf
	l.hasBpfTramp = kernel.HasBpfTramp()

	if err := l.fillIndexes(); err != nil {
		return nil, fmt.Errorf("fill indexes: %v", err)
	}
	if err := l.loadBpf(cache); err != nil {
		return nil, fmt.Errorf("load bpf: %v", err)
	}

	// Kernel BTF is only needed during load. Drop the last reference to
	// the parsed spec (~20MiB) and collect it promptly.
	cache = nil
	runtime.GC()

	return l, nil
}

func (l *Loader) rewriteConstants(spec *ebpf.CollectionSpec) error {
	var missing []string
	for n, c := range l.constants {
		v, ok := spec.Variables[n]
		if !ok {
			missing = append(missing, n)
			continue
		}

		if !v.Constant() {
			return fmt.Errorf("variable %s is not a constant", n)
		}

		if err := v.Set(c); err != nil {
			return fmt.Errorf("rewriting constant %s: %w", n, err)
		}
	}

	if len(missing) != 0 {
		return fmt.Errorf("rewrite constants: %+v", missing)
	}

	return nil
}

func (l *Loader) pruneUnusedProgs(spec *ebpf.CollectionSpec) {
	del := func(names ...string) {
		for _, name := range names {
			delete(spec.Programs, name)
		}
	}

	// do_renameat2
	if l.hasBpfTramp && kernel.FuncExists(l.kbtf, "do_renameat2") {
		del("kprobe__do_renameat2")
	} else {
		del("fentry__do_renameat2")
	}

	// tcp_v6_connect
	if l.hasBpfTramp && kernel.FuncExists(l.kbtf, "tcp_v6_connect") {
		del("kprobe__tcp_v6_connect", "kretprobe__tcp_v6_connect")
	} else {
		del("fexit__tcp_v6_connect")
	}

	// tty_write
	if l.hasBpfTramp && kernel.FuncExists(l.kbtf, "tty_write") {
		del("kprobe__tty_write")
	} else {
		del("fentry__tty_write")
	}

	// vfs_writev
	if l.hasBpfTramp && kernel.FuncExists(l.kbtf, "vfs_writev") {
		del("kprobe__vfs_writev", "kretprobe__vfs_writev")
	} else {
		del("fexit__vfs_writev")
	}

	// Generic bpf trampoline group: all programs switch together.
	if l.hasBpfTramp {
		del(
			"kprobe__do_unlinkat",
			"kprobe__mnt_want_write",
			"kprobe__vfs_unlink", "kretprobe__vfs_unlink",
			"kretprobe__do_filp_open",
			"kprobe__vfs_rename", "kretprobe__vfs_rename",
			"kprobe__disassociate_ctty",
			"kprobe__commit_creds",
			"kretprobe__inet_csk_accept",
			"kprobe__tcp_v4_connect", "kretprobe__tcp_v4_connect",
			"kprobe__tcp_close",
			"kprobe__chmod_common", "kretprobe__chmod_common",
			"kprobe__do_truncate", "kretprobe__do_truncate",
			"kprobe__vfs_write", "kretprobe__vfs_write",
			"kprobe__chown_common", "kretprobe__chown_common",
		)
	} else {
		del(
			"fentry__do_unlinkat",
			"fentry__mnt_want_write",
			"fentry__vfs_unlink", "fexit__vfs_unlink",
			"fexit__do_filp_open",
			"fentry__vfs_rename", "fexit__vfs_rename",
			"fentry__disassociate_ctty",
			"fentry__commit_creds",
			"fexit__inet_csk_accept",
			"fexit__tcp_v4_connect",
			"fentry__tcp_close",
			"fexit__chmod_common",
			"fexit__do_truncate",
			"fexit__vfs_write",
			"fexit__chown_common",
		)
	}
}

func (l *Loader) prepareSpec() (*ebpf.CollectionSpec, error) {
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("load collection: %v", err)
	}
	if err := l.rewriteConstants(spec); err != nil {
		return nil, fmt.Errorf("rewrite constants: %v", err)
	}
	spec.Maps["event_buffer_map"].MaxEntries = uint32(runtime.NumCPU())
	// Remove the unused variant of each conditional program pair before loading.
	// Fentry/fexit programs resolve their CO-RE relocations at load time, so they
	// fail if the target function is absent from kernel BTF, before the runtime
	// guard in attachBpfProgs can fall back to the kprobe variant.
	// NewCollectionWithOptions loads every program remaining in the spec, so only
	// the chosen variant must remain.
	l.pruneUnusedProgs(spec)
	return spec, nil
}

// pruneRawTpProgs removes all BPF_TRACE_RAW_TP (tp_btf) programs from spec.
// These programs have no kprobe fallback, so if they fail CO-RE relocation they
// must be dropped entirely rather than retried with an alternative.
func pruneRawTpProgs(spec *ebpf.CollectionSpec) {
	for name, prog := range spec.Programs {
		if prog.Type == ebpf.Tracing && prog.AttachType == ebpf.AttachTraceRawTp {
			delete(spec.Programs, name)
		}
	}
}

func (l *Loader) loadBpf(cache *btf.Cache) error {
	// Best-effort: not needed on kernels >= 5.11. On older kernels it
	// requires CAP_SYS_RESOURCE, which may not be available in containers.
	// If the default memlock limit is insufficient, LoadAndAssign will fail
	// with a more specific error.
	_ = rlimit.RemoveMemlock()

	spec, err := l.prepareSpec()
	if err != nil {
		return err
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Cache: cache})
	if err != nil {
		if !strings.Contains(err.Error(), "bad CO-RE relocation") {
			return fmt.Errorf("load bpf collection: %w", err)
		}
		// Fentry/fexit or tp_btf programs have CO-RE relocations that can't be
		// resolved on this kernel. Fall back to kprobe variants by clearing
		// hasBpfTramp and reloading a fresh spec (the first attempt already pruned
		// the kprobe programs). Also drop tp_btf programs which have no kprobe
		// fallback.
		l.hasBpfTramp = false
		spec, err = l.prepareSpec()
		if err != nil {
			return err
		}
		pruneRawTpProgs(spec)
		coll, err = ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Cache: cache})
		if err != nil {
			return fmt.Errorf("load bpf collection: %w", err)
		}
	}
	l.coll = coll
	l.populateObjs()

	rd, err := ringbuf.NewReader(l.objs.Ringbuf)
	if err != nil {
		return fmt.Errorf("error opening ringbuf reader: %v", err)
	}
	l.reader = rd

	if err := l.attachBpfProgs(); err != nil {
		return fmt.Errorf("error attaching bpf programs: %v", err)
	}

	// Kernel BTF is only needed up to this point, release it so the
	// decoded spec (~20MiB) can be garbage collected.
	l.kbtf = nil

	return nil
}

// populateObjs copies map and program pointers from l.coll into l.objs.
// It replaces spec.LoadAndAssign, which fails when programs have been deleted
// from the spec (struct tags reference names that are no longer present).
func (l *Loader) populateObjs() {
	l.objs.ElasticEbpfEventsInitBuffer = l.coll.Maps["elastic_ebpf_events_init_buffer"]
	l.objs.ElasticEbpfEventsScratchSpace = l.coll.Maps["elastic_ebpf_events_scratch_space"]
	l.objs.ElasticEbpfEventsState = l.coll.Maps["elastic_ebpf_events_state"]
	l.objs.ElasticEbpfEventsTrustedPids = l.coll.Maps["elastic_ebpf_events_trusted_pids"]
	l.objs.EventBufferMap = l.coll.Maps["event_buffer_map"]
	l.objs.PathResolverDentryScratchMap = l.coll.Maps["path_resolver_dentry_scratch_map"]
	l.objs.PathResolverKernfsNodeScratchMap = l.coll.Maps["path_resolver_kernfs_node_scratch_map"]
	l.objs.Ringbuf = l.coll.Maps["ringbuf"]
	l.objs.RingbufStats = l.coll.Maps["ringbuf_stats"]
	l.objs.SkToTgid = l.coll.Maps["sk_to_tgid"]

	for name, prog := range l.coll.Programs {
		switch name {
		case "fentry__commit_creds":
			l.objs.FentryCommitCreds = prog
		case "fentry__do_renameat2":
			l.objs.FentryDoRenameat2 = prog
		case "fentry__do_unlinkat":
			l.objs.FentryDoUnlinkat = prog
		case "fentry__mnt_want_write":
			l.objs.FentryMntWantWrite = prog
		case "fentry__disassociate_ctty":
			l.objs.FentryDisassociateCtty = prog
		case "fentry__tcp_close":
			l.objs.FentryTcpClose = prog
		case "fentry__tty_write":
			l.objs.FentryTtyWrite = prog
		case "fentry__vfs_rename":
			l.objs.FentryVfsRename = prog
		case "fentry__vfs_unlink":
			l.objs.FentryVfsUnlink = prog
		case "fexit__chmod_common":
			l.objs.FexitChmodCommon = prog
		case "fexit__chown_common":
			l.objs.FexitChownCommon = prog
		case "fexit__do_filp_open":
			l.objs.FexitDoFilpOpen = prog
		case "fexit__do_truncate":
			l.objs.FexitDoTruncate = prog
		case "fexit__inet_csk_accept":
			l.objs.FexitInetCskAccept = prog
		case "fexit__tcp_v4_connect":
			l.objs.FexitTcpV4Connect = prog
		case "fexit__tcp_v6_connect":
			l.objs.FexitTcpV6Connect = prog
		case "fexit__vfs_rename":
			l.objs.FexitVfsRename = prog
		case "fexit__vfs_unlink":
			l.objs.FexitVfsUnlink = prog
		case "fexit__vfs_write":
			l.objs.FexitVfsWrite = prog
		case "fexit__vfs_writev":
			l.objs.FexitVfsWritev = prog
		case "kprobe__chmod_common":
			l.objs.KprobeChmodCommon = prog
		case "kprobe__chown_common":
			l.objs.KprobeChownCommon = prog
		case "kprobe__commit_creds":
			l.objs.KprobeCommitCreds = prog
		case "kprobe__do_renameat2":
			l.objs.KprobeDoRenameat2 = prog
		case "kprobe__do_truncate":
			l.objs.KprobeDoTruncate = prog
		case "kprobe__do_unlinkat":
			l.objs.KprobeDoUnlinkat = prog
		case "kprobe__mnt_want_write":
			l.objs.KprobeMntWantWrite = prog
		case "kprobe__disassociate_ctty":
			l.objs.KprobeDisassociateCtty = prog
		case "kprobe__tcp_close":
			l.objs.KprobeTcpClose = prog
		case "kprobe__tcp_v4_connect":
			l.objs.KprobeTcpV4Connect = prog
		case "kprobe__tcp_v6_connect":
			l.objs.KprobeTcpV6Connect = prog
		case "kprobe__tty_write":
			l.objs.KprobeTtyWrite = prog
		case "kprobe__vfs_rename":
			l.objs.KprobeVfsRename = prog
		case "kprobe__vfs_unlink":
			l.objs.KprobeVfsUnlink = prog
		case "kprobe__vfs_write":
			l.objs.KprobeVfsWrite = prog
		case "kprobe__vfs_writev":
			l.objs.KprobeVfsWritev = prog
		case "kretprobe__chmod_common":
			l.objs.KretprobeChmodCommon = prog
		case "kretprobe__chown_common":
			l.objs.KretprobeChownCommon = prog
		case "kretprobe__do_filp_open":
			l.objs.KretprobeDoFilpOpen = prog
		case "kretprobe__do_truncate":
			l.objs.KretprobeDoTruncate = prog
		case "kretprobe__inet_csk_accept":
			l.objs.KretprobeInetCskAccept = prog
		case "kretprobe__tcp_v4_connect":
			l.objs.KretprobeTcpV4Connect = prog
		case "kretprobe__tcp_v6_connect":
			l.objs.KretprobeTcpV6Connect = prog
		case "kretprobe__vfs_rename":
			l.objs.KretprobeVfsRename = prog
		case "kretprobe__vfs_unlink":
			l.objs.KretprobeVfsUnlink = prog
		case "kretprobe__vfs_write":
			l.objs.KretprobeVfsWrite = prog
		case "kretprobe__vfs_writev":
			l.objs.KretprobeVfsWritev = prog
		case "sched_process_exec":
			l.objs.SchedProcessExec = prog
		case "sched_process_fork":
			l.objs.SchedProcessFork = prog
		case "tracepoint_syscalls_sys_exit_setsid":
			l.objs.TracepointSyscallsSysExitSetsid = prog
		}
	}
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
		err = errors.Join(err, attachFentry(l.objs.FentryDisassociateCtty))
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
		err = errors.Join(err, attachKprobe("disassociate_ctty", l.objs.KprobeDisassociateCtty))
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

	if l.objs.SchedProcessExec != nil {
		err = errors.Join(err, attachRawTp(l.objs.SchedProcessExec))
	}
	if l.objs.SchedProcessFork != nil {
		err = errors.Join(err, attachRawTp(l.objs.SchedProcessFork))
	}
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
	return l.objs.Ringbuf.MaxEntries()
}

func (l *Loader) Close() error {
	var errs []error
	if l.reader != nil {
		errs = append(errs, l.reader.Close())
	}
	for _, lnk := range l.links {
		errs = append(errs, lnk.Close())
	}
	if l.coll != nil {
		l.coll.Close()
	}
	return errors.Join(errs...)
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
	var err error

	err = errors.Join(err, l.fillRetIndex("inet_csk_accept"))

	err = errors.Join(err, l.fillArgIndex("vfs_unlink", "dentry"))
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

	// The probes read inode timestamps, kernfs_node.__parent and
	// tty_driver.type/.subtype through CO-RE flavors (vmlinux_extra.h) and
	// declare no offset constants for them. Filling a constant the object
	// doesn't declare fails rewriteConstants.

	return err
}
