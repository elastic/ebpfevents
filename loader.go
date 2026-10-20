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

	// load fallbacks, see loadColl
	dropped  []string // tp_btf programs dropped because they failed to load
	degraded error    // the load failures that led to a fallback
	// newColl is ebpf.NewCollectionWithOptions, replaced in tests.
	newColl func(*ebpf.CollectionSpec, ebpf.CollectionOptions) (*ebpf.Collection, error)

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
		return nil, fmt.Errorf("check kernel version: %w", err)
	}

	cache := btf.NewCache()
	kbtf, err := cache.Kernel()
	if err != nil {
		return nil, fmt.Errorf("load kernel btf: %w", err)
	}
	l.kbtf = kbtf
	l.hasBpfTramp = kernel.HasBpfTramp()

	if err := l.fillIndexes(); err != nil {
		return nil, fmt.Errorf("fill indexes: %w", err)
	}
	if err := l.loadBpf(cache); err != nil {
		// loadBpf can fail after loading the collection, with the ring buffer
		// reader open and some programs attached. Release them now rather
		// than leave the links live in the kernel until finalizers run.
		_ = l.Close()
		return nil, fmt.Errorf("load bpf: %w", err)
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
	tracing []string  // fentry/fexit programs
	kprobes []string  // kprobe/kretprobe programs
	renamed *dualFunc // the function under its 7.0 name, nil if not renamed
}

var dualFuncs = []dualFunc{
	{"chmod_common", []string{bpfProgFexitChmodCommon}, []string{bpfProgKprobeChmodCommon, bpfProgKretprobeChmodCommon}, nil},
	{"chown_common", []string{bpfProgFexitChownCommon}, []string{bpfProgKprobeChownCommon, bpfProgKretprobeChownCommon}, nil},
	{"commit_creds", []string{bpfProgFentryCommitCreds}, []string{bpfProgKprobeCommitCreds}, nil},
	{"disassociate_ctty", []string{bpfProgFentryDisassociateCtty}, []string{bpfProgKprobeDisassociateCtty}, nil},
	{"do_filp_open", []string{bpfProgFexitDoFilpOpen}, []string{bpfProgKretprobeDoFilpOpen},
		&dualFunc{"do_file_open", []string{bpfProgFexitDoFileOpen}, []string{bpfProgKretprobeDoFileOpen}, nil}},
	{"do_renameat2", []string{bpfProgFentryDoRenameat2}, []string{bpfProgKprobeDoRenameat2},
		&dualFunc{"filename_renameat2", []string{bpfProgFentryFilenameRenameat2}, []string{bpfProgKprobeFilenameRenameat2}, nil}},
	{"do_truncate", []string{bpfProgFexitDoTruncate}, []string{bpfProgKprobeDoTruncate, bpfProgKretprobeDoTruncate}, nil},
	{"do_unlinkat", []string{bpfProgFentryDoUnlinkat}, []string{bpfProgKprobeDoUnlinkat},
		&dualFunc{"filename_unlinkat", []string{bpfProgFentryFilenameUnlinkat}, []string{bpfProgKprobeFilenameUnlinkat}, nil}},
	{"inet_csk_accept", []string{bpfProgFexitInetCskAccept}, []string{bpfProgKretprobeInetCskAccept}, nil},
	{"mnt_want_write", []string{bpfProgFentryMntWantWrite}, []string{bpfProgKprobeMntWantWrite}, nil},
	{"tcp_close", []string{bpfProgFentryTcpClose}, []string{bpfProgKprobeTcpClose}, nil},
	{"tcp_v4_connect", []string{bpfProgFexitTcpV4Connect}, []string{bpfProgKprobeTcpV4Connect, bpfProgKretprobeTcpV4Connect}, nil},
	{"tcp_v6_connect", []string{bpfProgFexitTcpV6Connect}, []string{bpfProgKprobeTcpV6Connect, bpfProgKretprobeTcpV6Connect}, nil},
	{"tty_write", []string{bpfProgFentryTtyWrite}, []string{bpfProgKprobeTtyWrite}, nil},
	{"vfs_rename", []string{bpfProgFentryVfsRename, bpfProgFexitVfsRename}, []string{bpfProgKprobeVfsRename, bpfProgKretprobeVfsRename}, nil},
	{"vfs_unlink", []string{bpfProgFentryVfsUnlink, bpfProgFexitVfsUnlink}, []string{bpfProgKprobeVfsUnlink, bpfProgKretprobeVfsUnlink}, nil},
	{"vfs_write", []string{bpfProgFexitVfsWrite}, []string{bpfProgKprobeVfsWrite, bpfProgKretprobeVfsWrite}, nil},
	{"vfs_writev", []string{bpfProgFexitVfsWritev}, []string{bpfProgKprobeVfsWritev, bpfProgKretprobeVfsWritev}, nil},
}

// fixedProgs are attached on every kernel.
var fixedProgs = []string{
	bpfProgSchedProcessExec,
	bpfProgSchedProcessFork,
	bpfProgTracepointSyscallsSysExitSetsid,
}

// pruneUnusedProgs picks the programs to attach: fixedProgs, less any the
// load fallback dropped, and, for every dual function, the fentry/fexit
// programs if the kernel has BPF trampolines and the function is in kernel
// BTF, or the kprobe/kretprobe programs otherwise. It deletes every other
// program from spec, so what is left is what attachBpfProgs attaches.
//
// A renamed function is traced under its 7.0 name only if the old name is
// missing from kernel BTF and the new one is present. pahole can leave out a
// function the kernel still has (it did with do_renameat2), and a kprobe on
// the old name still attaches there.
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
	picked := slices.DeleteFunc(slices.Clone(fixedProgs), func(name string) bool {
		return slices.Contains(l.dropped, name)
	})
	for _, df := range dualFuncs {
		if df.renamed != nil && !kernel.FuncExists(l.kbtf, df.fn) && kernel.FuncExists(l.kbtf, df.renamed.fn) {
			df = *df.renamed
		}
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
		return nil, fmt.Errorf("load collection: %w", err)
	}
	if err := l.rewriteConstants(spec); err != nil {
		return nil, fmt.Errorf("rewrite constants: %w", err)
	}
	spec.Maps[bpfMapEventBufferMap].MaxEntries = uint32(runtime.NumCPU())
	l.pruneUnusedProgs(spec)
	return spec, nil
}

// cilium/ebpf replaces an instruction whose CO-RE relocation it can't resolve
// against kernel BTF with a call to, or a load of, btf.COREBadRelocationSentinel,
// and the verifier rejects the program there. These are the verifier log lines
// for the two, as cilium/ebpf itself matches them (prog.go).
var (
	coreBadCall = fmt.Sprintf("invalid func unknown#%d", btf.COREBadRelocationSentinel)
	coreBadLoad = fmt.Sprintf("r10 = 0x%x", btf.COREBadRelocationSentinel)
)

// isBadRelocation reports whether err is the verifier rejecting a program at
// an instruction poisoned for a CO-RE relocation that couldn't be resolved.
// TestNewLoaderLoadErrors checks it against the running kernel.
func isBadRelocation(err error) bool {
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		return false
	}
	for _, line := range ve.Log {
		if strings.Contains(line, coreBadCall) || strings.Contains(line, coreBadLoad) {
			return true
		}
	}
	return false
}

// rawTpEvents are the events the tp_btf programs emit. They have no kprobe
// variant, so if one fails to load, its events are lost.
var rawTpEvents = map[string]EventType{
	bpfProgSchedProcessExec: EventTypeProcessExec,
	bpfProgSchedProcessFork: EventTypeProcessFork,
}

// failedProg returns the program in spec that err, a NewCollectionWithOptions
// error, is about. cilium/ebpf prefixes it with "program <name>:", which
// TestNewLoaderLoadErrors pins.
func failedProg(spec *ebpf.CollectionSpec, err error) (string, bool) {
	msg := err.Error()
	for name := range spec.Programs {
		if strings.HasPrefix(msg, "program "+name+":") {
			return name, true
		}
	}
	return "", false
}

// fallBack changes what the next load attempt picks so that it avoids err,
// the failure to load spec. It returns what it gave up, or false if no other
// choice of programs avoids err.
//
// Only a bad CO-RE relocation or ErrNotSupported (such as an fentry target
// missing from kernel BTF) depends on the programs chosen, and only in a
// program that has an alternative:
//   - fentry/fexit: every dual function switches to its kprobe variant. The
//     variants share helpers, so one fentry program failing tends to come
//     with others failing; switching them together costs one retry, not one
//     per program.
//   - tp_btf: the program is dropped, and the events only it emits are lost.
//     DisabledEvents reports them.
func (l *Loader) fallBack(spec *ebpf.CollectionSpec, err error) (string, bool) {
	if !isBadRelocation(err) && !errors.Is(err, ebpf.ErrNotSupported) {
		return "", false
	}
	name, ok := failedProg(spec, err)
	if !ok {
		return "", false
	}
	ps := spec.Programs[name]
	if ps.Type != ebpf.Tracing {
		return "", false
	}
	switch ps.AttachType {
	case ebpf.AttachTraceFEntry, ebpf.AttachTraceFExit:
		if !l.hasBpfTramp {
			return "", false
		}
		l.hasBpfTramp = false
		return "fell back to kprobes", true
	case ebpf.AttachTraceRawTp:
		ev, ok := rawTpEvents[name]
		if !ok {
			return "", false
		}
		l.dropped = append(l.dropped, name)
		return fmt.Sprintf("dropped %s, no %s events", name, ev), true
	}
	return "", false
}

// loadColl loads the programs pruneUnusedProgs picks. When a program fails in
// a way another choice avoids (see fallBack), it falls back and tries again.
// Each fallback can happen only once, so there are at most three retries.
func (l *Loader) loadColl(cache *btf.Cache) (*ebpf.Collection, *ebpf.CollectionSpec, error) {
	newColl := l.newColl
	if newColl == nil {
		newColl = ebpf.NewCollectionWithOptions
	}

	var fallbacks []error
	for {
		spec, err := l.prepareSpec()
		if err != nil {
			return nil, nil, err
		}
		coll, err := newColl(spec, ebpf.CollectionOptions{Cache: cache})
		if err == nil {
			l.degraded = errors.Join(fallbacks...)
			return coll, spec, nil
		}
		gaveUp, ok := l.fallBack(spec, err)
		if !ok {
			// The failures that led here too: without them, an error in a
			// kprobe program wouldn't say that kprobes were the fallback.
			return nil, nil, fmt.Errorf("load bpf collection: %w", errors.Join(append(fallbacks, err)...))
		}
		fallbacks = append(fallbacks, fmt.Errorf("%s: %w", gaveUp, err))
	}
}

func (l *Loader) loadBpf(cache *btf.Cache) error {
	// Best-effort: not needed on kernels >= 5.11. On older kernels it
	// requires CAP_SYS_RESOURCE, which may not be available in containers.
	// If the default memlock limit is insufficient, loading the collection
	// will fail with a more specific error.
	_ = rlimit.RemoveMemlock()

	coll, spec, err := l.loadColl(cache)
	if err != nil {
		return err
	}
	l.coll = coll

	rd, err := ringbuf.NewReader(l.coll.Maps[bpfMapRingbuf])
	if err != nil {
		return fmt.Errorf("error opening ringbuf reader: %w", err)
	}
	l.reader = rd

	if err := l.attachBpfProgs(spec); err != nil {
		return fmt.Errorf("error attaching bpf programs: %w", err)
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
			return fmt.Errorf("attach tracing %q: %w", prog.String(), err)
		}
		l.links = append(l.links, lnk)
		return nil
	}
	attachKprobe := func(sym string, prog *ebpf.Program) error {
		lnk, err := link.Kprobe(sym, prog, nil)
		if err != nil {
			return fmt.Errorf("attach kprobe %q: %w", prog.String(), err)
		}
		l.links = append(l.links, lnk)
		return nil
	}
	attachKretprobe := func(sym string, prog *ebpf.Program) error {
		lnk, err := link.Kretprobe(sym, prog, nil)
		if err != nil {
			return fmt.Errorf("attach kretprobe %q: %w", prog.String(), err)
		}
		l.links = append(l.links, lnk)
		return nil
	}
	attachTracepoint := func(group, name string, prog *ebpf.Program) error {
		lnk, err := link.Tracepoint(group, name, prog, nil)
		if err != nil {
			return fmt.Errorf("attach tracepoint '%s/%s': %w", group, name, err)
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

// DisabledEvents returns the event types the loader can't produce on this
// kernel, because the only programs that emit them failed to load. It is
// empty unless NewLoader had to fall back, and Degraded says why.
func (l *Loader) DisabledEvents() []EventType {
	var evs []EventType
	for _, name := range l.dropped {
		evs = append(evs, rawTpEvents[name])
	}
	return evs
}

// Degraded returns the load failures NewLoader worked around, each with what
// it gave up for it, or nil if it loaded what it normally does. Not an error
// for NewLoader's caller to fail on, but one to log: when it reports dropped
// programs, events are missing (see DisabledEvents).
func (l *Loader) Degraded() error {
	return l.degraded
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
		return fmt.Errorf("fill %s: %w", name, err)
	}
	l.constants[name] = idx

	return nil
}

func (l *Loader) fillRetIndex(funcName string) error {
	name := fmt.Sprintf(retIdxFmt, funcName)

	idx, err := kernel.RetIdxByFunc(l.kbtf, funcName)
	if err != nil {
		return fmt.Errorf("fill %s: %w", name, err)
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
		return fmt.Errorf("fill %s: %w", name, err)
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
