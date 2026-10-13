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
	"maps"
	"os"
	"runtime"
	"slices"
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
		// loadBpf can fail after loading the collection, with the ring buffer
		// reader open and some programs attached. Release them now rather
		// than leave the links live in the kernel until finalizers run.
		_ = l.Close()
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

// A dualFunc is a kernel function the object traces twice: with fentry/fexit
// programs and with kprobe/kretprobe programs. Only one of the two sets is
// loaded and attached.
type dualFunc struct {
	fn      string
	tracing []string // fentry/fexit programs
	kprobes []string // kprobe/kretprobe programs
}

var dualFuncs = []dualFunc{
	{"chmod_common", []string{bpfProgFexitChmodCommon}, []string{bpfProgKprobeChmodCommon, bpfProgKretprobeChmodCommon}},
	{"chown_common", []string{bpfProgFexitChownCommon}, []string{bpfProgKprobeChownCommon, bpfProgKretprobeChownCommon}},
	{"commit_creds", []string{bpfProgFentryCommitCreds}, []string{bpfProgKprobeCommitCreds}},
	{"disassociate_ctty", []string{bpfProgFentryDisassociateCtty}, []string{bpfProgKprobeDisassociateCtty}},
	{"do_filp_open", []string{bpfProgFexitDoFilpOpen}, []string{bpfProgKretprobeDoFilpOpen}},
	{"do_renameat2", []string{bpfProgFentryDoRenameat2}, []string{bpfProgKprobeDoRenameat2}},
	{"do_truncate", []string{bpfProgFexitDoTruncate}, []string{bpfProgKprobeDoTruncate, bpfProgKretprobeDoTruncate}},
	{"do_unlinkat", []string{bpfProgFentryDoUnlinkat}, []string{bpfProgKprobeDoUnlinkat}},
	{"inet_csk_accept", []string{bpfProgFexitInetCskAccept}, []string{bpfProgKretprobeInetCskAccept}},
	{"mnt_want_write", []string{bpfProgFentryMntWantWrite}, []string{bpfProgKprobeMntWantWrite}},
	{"tcp_close", []string{bpfProgFentryTcpClose}, []string{bpfProgKprobeTcpClose}},
	{"tcp_v4_connect", []string{bpfProgFexitTcpV4Connect}, []string{bpfProgKprobeTcpV4Connect, bpfProgKretprobeTcpV4Connect}},
	{"tcp_v6_connect", []string{bpfProgFexitTcpV6Connect}, []string{bpfProgKprobeTcpV6Connect, bpfProgKretprobeTcpV6Connect}},
	{"tty_write", []string{bpfProgFentryTtyWrite}, []string{bpfProgKprobeTtyWrite}},
	{"vfs_rename", []string{bpfProgFentryVfsRename, bpfProgFexitVfsRename}, []string{bpfProgKprobeVfsRename, bpfProgKretprobeVfsRename}},
	{"vfs_unlink", []string{bpfProgFentryVfsUnlink, bpfProgFexitVfsUnlink}, []string{bpfProgKprobeVfsUnlink, bpfProgKretprobeVfsUnlink}},
	{"vfs_write", []string{bpfProgFexitVfsWrite}, []string{bpfProgKprobeVfsWrite, bpfProgKretprobeVfsWrite}},
	{"vfs_writev", []string{bpfProgFexitVfsWritev}, []string{bpfProgKprobeVfsWritev, bpfProgKretprobeVfsWritev}},
}

// fixedProgs are attached on every kernel.
var fixedProgs = []string{
	bpfProgSchedProcessExec,
	bpfProgSchedProcessFork,
	bpfProgTracepointSyscallsSysExitSetsid,
}

// pruneUnusedProgs picks the programs to attach: fixedProgs and, for every
// dual function, the fentry/fexit programs if the kernel has BPF trampolines
// and the function is in kernel BTF, or the kprobe/kretprobe programs
// otherwise. It deletes every other program from spec, so what is left is
// what attachBpfProgs attaches.
//
// An fentry/fexit program whose target is missing from kernel BTF fails to
// load with ErrNotSupported, which fails the whole collection. pahole drops
// functions that are inlined or have inconsistent prototypes, as happened to
// do_renameat2 (beats#46719), so every function is checked.
//
// NewCollectionWithOptions loads every program in the spec, so a program that
// is never attached can only make the load fail. module_load, for one, needs
// btf_trace_module_load, which kernels built without CONFIG_MODULES lack.
func (l *Loader) pruneUnusedProgs(spec *ebpf.CollectionSpec) {
	picked := slices.Clone(fixedProgs)
	for _, df := range dualFuncs {
		if l.hasBpfTramp && kernel.FuncExists(l.kbtf, df.fn) {
			picked = append(picked, df.tracing...)
		} else {
			picked = append(picked, df.kprobes...)
		}
	}
	for name := range spec.Programs {
		if !slices.Contains(picked, name) {
			delete(spec.Programs, name)
		}
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
	spec.Maps[bpfMapEventBufferMap].MaxEntries = uint32(runtime.NumCPU())
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
	// If the default memlock limit is insufficient, loading the collection
	// will fail with a more specific error.
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

	rd, err := ringbuf.NewReader(l.coll.Maps[bpfMapRingbuf])
	if err != nil {
		return fmt.Errorf("error opening ringbuf reader: %v", err)
	}
	l.reader = rd

	if err := l.attachBpfProgs(spec); err != nil {
		return fmt.Errorf("error attaching bpf programs: %v", err)
	}

	// Kernel BTF is only needed up to this point, release it so the
	// decoded spec (~20MiB) can be garbage collected.
	l.kbtf = nil

	return nil
}

func (l *Loader) attachBpfProgs(spec *ebpf.CollectionSpec) error {
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

	// Every program left in the spec is attached, the way its ELF section
	// says. Sorted, so that errors come out in a stable order.
	for _, name := range slices.Sorted(maps.Keys(spec.Programs)) {
		ps, prog := spec.Programs[name], l.coll.Programs[name]
		switch {
		case ps.Type == ebpf.Tracing: // fentry, fexit, tp_btf
			err = errors.Join(err, attachTracing(ps.AttachType, prog))
		case ps.Type == ebpf.TracePoint:
			group, tp, _ := strings.Cut(ps.AttachTo, "/")
			err = errors.Join(err, attachTracepoint(group, tp, prog))
		case ps.Type == ebpf.Kprobe && strings.HasPrefix(ps.SectionName, "kretprobe/"):
			err = errors.Join(err, attachKretprobe(ps.AttachTo, prog))
		case ps.Type == ebpf.Kprobe:
			err = errors.Join(err, attachKprobe(ps.AttachTo, prog))
		default:
			err = errors.Join(err, fmt.Errorf("attach %s: unsupported program type %s", name, ps.Type))
		}
	}

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
	return l.coll.Maps[bpfMapRingbuf].MaxEntries()
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
