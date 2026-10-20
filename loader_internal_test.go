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
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the loader without loading anything into a kernel, so
// they need neither root nor BPF support and run in CI, unlike TestNewLoader
// and TestNewLoaderLoadErrors.
// Kernel BTF is synthesised where a test needs to control which functions and
// fields "exist".

var testInt = &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}

// testKernelBTF builds a BTF spec containing exactly types, standing in for
// the running kernel's BTF.
func testKernelBTF(t *testing.T, types ...btf.Type) *btf.Spec {
	t.Helper()

	b, err := btf.NewBuilder(nil, nil)
	require.NoError(t, err)
	for _, typ := range types {
		_, err := b.Add(typ)
		require.NoError(t, err)
	}
	raw, err := b.Marshal(nil, nil)
	require.NoError(t, err)

	spec, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	require.NoError(t, err)
	return spec
}

// testFunc returns a kernel function with the given parameter names.
func testFunc(name string, params ...string) *btf.Func {
	proto := &btf.FuncProto{Return: testInt}
	for _, p := range params {
		proto.Params = append(proto.Params, btf.FuncParam{Name: p, Type: testInt})
	}
	return &btf.Func{Name: name, Type: proto, Linkage: btf.GlobalFunc}
}

// testStruct returns a struct whose members are 8 bytes apart, in order, so
// member i sits at byte offset 8*i.
func testStruct(name string, members ...string) *btf.Struct {
	s := &btf.Struct{Name: name, Size: uint32(8 * len(members))}
	for i, m := range members {
		s.Members = append(s.Members, btf.Member{Name: m, Type: testInt, Offset: btf.Bits(64 * i)})
	}
	return s
}

// splitProgName splits a program name like
// "fexit__vfs_unlink" into its variant family and the traced function.
func splitProgName(name string) (family, fn string, ok bool) {
	prefix, fn, ok := strings.Cut(name, "__")
	if !ok {
		return "", "", false
	}
	switch prefix {
	case "fentry", "fexit":
		return "tracing", fn, true
	case "kprobe", "kretprobe":
		return "kprobe", fn, true
	}
	return "", "", false
}

// objectDualFuncs returns, for every function the object traces with both a
// tracing and a kprobe variant, its programs by variant family. Derived from
// the object, so a probe added or renamed upstream (as ec1ba650 renamed
// taskstats_exit to disassociate_ctty) is covered without editing the tests.
func objectDualFuncs(t *testing.T) map[string]map[string][]string {
	t.Helper()

	spec, err := loadBpf()
	require.NoError(t, err)

	byFunc := map[string]map[string][]string{}
	for name := range spec.Programs {
		if fam, fn, ok := splitProgName(name); ok {
			if byFunc[fn] == nil {
				byFunc[fn] = map[string][]string{}
			}
			byFunc[fn][fam] = append(byFunc[fn][fam], name)
		}
	}
	for fn, fams := range byFunc {
		if len(fams["tracing"]) == 0 || len(fams["kprobe"]) == 0 {
			delete(byFunc, fn)
		}
	}
	return byFunc
}

// allDualFuncs returns dualFuncs with the 7.0 names of the renamed functions
// as entries of their own.
func allDualFuncs() []dualFunc {
	var all []dualFunc
	for _, df := range dualFuncs {
		all = append(all, df)
		if df.renamed != nil {
			all = append(all, *df.renamed)
		}
	}
	return all
}

// TestDualFuncs checks dualFuncs against the object: every dual function is
// listed, under its old or its 7.0 name, with all of its programs in the right
// set. A function missing from dualFuncs would have both variants loaded and
// neither attached.
func TestDualFuncs(t *testing.T) {
	want := objectDualFuncs(t)
	require.NotEmpty(t, want)

	got := map[string]map[string][]string{}
	for _, df := range allDualFuncs() {
		require.NotContains(t, got, df.fn, "%s is listed twice", df.fn)
		got[df.fn] = map[string][]string{"tracing": df.tracing, "kprobe": df.kprobes}
	}
	for fn := range want {
		require.Contains(t, got, fn, "%s has both variants in the object but no dualFuncs entry", fn)
		for _, fam := range []string{"tracing", "kprobe"} {
			assert.ElementsMatch(t, want[fn][fam], got[fn][fam], "%s %s programs", fn, fam)
		}
	}
	for fn := range got {
		assert.Contains(t, want, fn, "stale dualFuncs entry")
	}
}

func TestPruneUnusedProgs(t *testing.T) {
	byFunc := objectDualFuncs(t)
	var dual []string
	for fn := range byFunc {
		dual = append(dual, fn)
	}

	// A kernel BTF with every dual function except those in missing.
	kernelWithout := func(missing ...string) *btf.Spec {
		skip := map[string]bool{}
		for _, m := range missing {
			skip[m] = true
		}
		var types []btf.Type
		for _, fn := range dual {
			if !skip[fn] {
				types = append(types, testFunc(fn))
			}
		}
		return testKernelBTF(t, types...)
	}

	// Kernels before 7.0 have the old names of the renamed functions, 7.0
	// the new ones.
	var oldNames, newNames []string
	for _, df := range dualFuncs {
		if df.renamed != nil {
			oldNames = append(oldNames, df.fn)
			newNames = append(newNames, df.renamed.fn)
		}
	}
	without := func(names ...string) []string {
		return append(slices.Clone(newNames), names...)
	}

	cases := []struct {
		name        string
		hasBpfTramp bool
		missing     []string
		renamed     bool // the renamed functions are traced under their new names
	}{
		{name: "no trampolines", hasBpfTramp: false, missing: without()},
		{name: "trampolines, all functions in BTF", hasBpfTramp: true, missing: without()},
		// The kernel from beats#46719's dev box: trampolines, but
		// do_renameat2 absent from BTF. Without filename_renameat2 either,
		// the kprobe on the old name is the one that attaches.
		{name: "trampolines, do_renameat2 missing", hasBpfTramp: true, missing: without("do_renameat2")},
		// static in fs/open.c, so pahole may leave them out.
		{name: "trampolines, chmod_common and chown_common missing", hasBpfTramp: true,
			missing: without("chmod_common", "chown_common")},
		{name: "trampolines, every function missing", hasBpfTramp: true, missing: dual},
		{name: "7.0, no trampolines", hasBpfTramp: false, missing: oldNames, renamed: true},
		{name: "7.0, trampolines", hasBpfTramp: true, missing: oldNames, renamed: true},
		// The old name wins when BTF has both.
		{name: "trampolines, old and new names in BTF", hasBpfTramp: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := loadBpf()
			require.NoError(t, err)

			missing := map[string]bool{}
			for _, m := range tc.missing {
				missing[m] = true
			}
			l := &Loader{hasBpfTramp: tc.hasBpfTramp, kbtf: kernelWithout(tc.missing...)}
			l.pruneUnusedProgs(spec)

			unused := newNames
			if tc.renamed {
				unused = oldNames
			}

			wantPicked := slices.Clone(fixedProgs)
			for _, fn := range dual {
				got := map[string]bool{}
				for name := range spec.Programs {
					if fam, f, ok := splitProgName(name); ok && f == fn {
						got[fam] = true
					}
				}
				if slices.Contains(unused, fn) {
					assert.Empty(t, got, "%s: no variant may survive the prune under this name", fn)
					continue
				}

				want := "kprobe"
				if tc.hasBpfTramp && !missing[fn] {
					want = "tracing"
				}
				wantPicked = append(wantPicked, byFunc[fn][want]...)
				assert.Equal(t, map[string]bool{want: true}, got,
					"%s: exactly the %s variants must survive the prune", fn, want)
			}

			// What is left in the spec is what gets loaded and attached.
			assert.ElementsMatch(t, wantPicked, slices.Collect(maps.Keys(spec.Programs)))
		})
	}
}

// Programs the object contains but the loader never attaches, so
// pruneUnusedProgs drops them. If one gets wired up, it must leave this list,
// which TestProgramsAccountedFor enforces.
var unattachedProgs = map[string]bool{
	"kprobe__ptrace_attach": true,
	"module_load":           true,
	"tracepoint_syscalls_sys_enter_memfd_create": true,
	"tracepoint_syscalls_sys_enter_shmget":       true,
}

// TestProgramsAccountedFor checks that every program in the object is either
// attached (dualFuncs, fixedProgs) or deliberately not (unattachedProgs). A
// program added upstream fails it until someone decides which, rather than
// being dropped by pruneUnusedProgs unnoticed.
func TestProgramsAccountedFor(t *testing.T) {
	spec, err := loadBpf()
	require.NoError(t, err)

	known := map[string]string{}
	add := func(name, where string) {
		if prev, ok := known[name]; ok {
			t.Errorf("%s is in both %s and %s", name, prev, where)
		}
		known[name] = where
	}
	for _, df := range allDualFuncs() {
		for _, name := range slices.Concat(df.tracing, df.kprobes) {
			add(name, "dualFuncs")
		}
	}
	for _, name := range fixedProgs {
		add(name, "fixedProgs")
	}
	for name := range unattachedProgs {
		add(name, "unattachedProgs")
	}

	for name := range spec.Programs {
		assert.Contains(t, known, name, "%s is neither attached nor listed in unattachedProgs", name)
	}
	for name, where := range known {
		assert.Contains(t, spec.Programs, name, "stale entry in %s", where)
	}
}

// testLoader returns a Loader set up as NewLoader sets one up on a kernel
// with BPF trampolines and every dual function in BTF, minus the constants,
// which prepareSpec then has none to rewrite.
func testLoader(t *testing.T) *Loader {
	t.Helper()

	var types []btf.Type
	for _, df := range dualFuncs {
		types = append(types, testFunc(df.fn))
	}
	return &Loader{hasBpfTramp: true, kbtf: testKernelBTF(t, types...), constants: map[string]any{}}
}

// loadErr returns the error NewCollectionWithOptions returns when program name
// fails to load with cause.
func loadErr(name string, cause error) error {
	return fmt.Errorf("program %s: load program: %w", name, cause)
}

// Load errors as cilium/ebpf returns them. The bad relocations carry the
// verifier log lines of the two kinds of poisoned instruction.
var (
	errTestBadRelocation = &ebpf.VerifierError{Cause: errors.New("bad CO-RE relocation"), Log: []string{
		"0: R1=ctx() R10=fp0", "; int BPF_PROG(fexit__vfs_write, ...)", "0: (85) call unknown#195896080", "invalid func unknown#195896080",
	}}
	errTestBadReloc2 = &ebpf.VerifierError{Cause: errors.New("bad CO-RE relocation"), Log: []string{
		"0: R1=ctx() R10=fp0", "0: (18) r10 = 0xbad2310", "frame pointer is read only",
	}}
	// Rejected by the verifier, but not at a poisoned instruction.
	errTestVerifier = &ebpf.VerifierError{Cause: errors.New("permission denied"), Log: []string{
		"0: R1=ctx() R10=fp0", "0: (79) r2 = *(u64 *)(r1 +4096)", "invalid bpf_context access off=4096 size=8",
	}}
	errTestNotSupported = fmt.Errorf("fexit do_filp_open: %w", ebpf.ErrNotSupported)
	errTestPermission   = errors.New("operation not permitted")
)

func TestFallBack(t *testing.T) {
	cases := []struct {
		name        string
		noTramp     bool // the loader already uses kprobes
		prog        string
		cause       error
		wantOK      bool
		wantTramp   bool
		wantDropped []string
	}{
		{name: "fexit, bad relocation", prog: bpfProgFexitVfsWrite, cause: errTestBadRelocation, wantOK: true},
		// The beats#46719 7.0 failure, should a target go missing despite
		// the FuncExists check.
		{name: "fexit, target not supported", prog: bpfProgFexitDoFilpOpen, cause: errTestNotSupported, wantOK: true},
		{name: "tp_btf exec, bad relocation", prog: bpfProgSchedProcessExec, cause: errTestBadRelocation,
			wantOK: true, wantTramp: true, wantDropped: []string{bpfProgSchedProcessExec}},
		{name: "tp_btf fork, bad relocation", prog: bpfProgSchedProcessFork, cause: errTestBadRelocation,
			wantOK: true, wantTramp: true, wantDropped: []string{bpfProgSchedProcessFork}},
		{name: "fexit, bad relocation in a load", prog: bpfProgFexitVfsUnlink, cause: errTestBadReloc2, wantOK: true},
		{name: "fentry, other error", prog: bpfProgFentryDoUnlinkat, cause: errTestPermission, wantTramp: true},
		{name: "fentry, verifier rejects elsewhere", prog: bpfProgFentryDoUnlinkat, cause: errTestVerifier, wantTramp: true},
		{name: "tracepoint, bad relocation", prog: bpfProgTracepointSyscallsSysExitSetsid, cause: errTestBadRelocation, wantTramp: true},
		{name: "kprobe, bad relocation", noTramp: true, prog: bpfProgKretprobeVfsWrite, cause: errTestBadRelocation},
		{name: "program not in the spec", prog: "no_such_program", cause: errTestBadRelocation, wantTramp: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := testLoader(t)
			l.hasBpfTramp = !tc.noTramp
			spec, err := l.prepareSpec()
			require.NoError(t, err)
			if tc.prog != "no_such_program" {
				require.Contains(t, spec.Programs, tc.prog)
			}

			gaveUp, ok := l.fallBack(spec, loadErr(tc.prog, tc.cause))
			assert.Equal(t, tc.wantOK, ok, "fallback taken")
			assert.Equal(t, tc.wantOK, gaveUp != "", "fallback described: %q", gaveUp)
			assert.Equal(t, tc.wantTramp, l.hasBpfTramp, "hasBpfTramp")
			assert.Equal(t, tc.wantDropped, l.dropped, "dropped")
		})
	}
}

func TestLoadColl(t *testing.T) {
	type failure struct {
		prog  string
		cause error
	}
	tracing := func(names []string) bool {
		for _, df := range dualFuncs {
			for _, name := range df.tracing {
				if slices.Contains(names, name) {
					return true
				}
			}
		}
		return false
	}

	cases := []struct {
		name     string
		fails    []failure // programs that fail to load on this "kernel"
		attempts int
		wantErr  []string // in the error, if loading fails
		tracing  bool     // the last attempt loads fentry/fexit programs
		disabled []EventType
	}{
		{name: "nothing fails", attempts: 1, tracing: true},
		{
			name:     "fexit fails",
			fails:    []failure{{bpfProgFexitVfsWrite, errTestBadRelocation}},
			attempts: 2,
		},
		{
			name:     "tp_btf fork fails",
			fails:    []failure{{bpfProgSchedProcessFork, errTestBadRelocation}},
			attempts: 2,
			tracing:  true,
			disabled: []EventType{EventTypeProcessFork},
		},
		{
			name: "fexit and both tp_btf fail",
			fails: []failure{
				{bpfProgFexitVfsWrite, errTestBadRelocation},
				{bpfProgSchedProcessExec, errTestBadRelocation},
				{bpfProgSchedProcessFork, errTestBadRelocation},
			},
			attempts: 4,
			disabled: []EventType{EventTypeProcessExec, EventTypeProcessFork},
		},
		{
			// The variants share helpers, so the kprobe one fails too. The
			// error has to show both, and that kprobes were the fallback.
			name: "fexit fails, then its kprobe variant",
			fails: []failure{
				{bpfProgFexitVfsWrite, errTestBadRelocation},
				{bpfProgKretprobeVfsWrite, errTestBadReloc2},
			},
			attempts: 2,
			wantErr:  []string{"program " + bpfProgFexitVfsWrite + ":", "fell back to kprobes", "program " + bpfProgKretprobeVfsWrite + ":"},
		},
		{
			name:     "error no fallback avoids",
			fails:    []failure{{bpfProgFentryDoUnlinkat, errTestPermission}},
			attempts: 1,
			wantErr:  []string{"program " + bpfProgFentryDoUnlinkat + ":", errTestPermission.Error()},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := testLoader(t)
			var attempts [][]string
			l.newColl = func(spec *ebpf.CollectionSpec, _ ebpf.CollectionOptions) (*ebpf.Collection, error) {
				attempts = append(attempts, slices.Sorted(maps.Keys(spec.Programs)))
				for _, f := range tc.fails {
					if _, ok := spec.Programs[f.prog]; ok {
						return nil, loadErr(f.prog, f.cause)
					}
				}
				return &ebpf.Collection{}, nil
			}

			_, spec, err := l.loadColl(nil)
			require.Len(t, attempts, tc.attempts)

			if tc.wantErr != nil {
				require.Error(t, err)
				for _, want := range tc.wantErr {
					assert.ErrorContains(t, err, want)
				}
				assert.ErrorIs(t, err, tc.fails[len(tc.fails)-1].cause)
				assert.ErrorIs(t, err, tc.fails[0].cause, "the first failure must not be lost")
				return
			}
			require.NoError(t, err)

			last := attempts[len(attempts)-1]
			assert.ElementsMatch(t, last, slices.Collect(maps.Keys(spec.Programs)), "the returned spec is the one loaded")
			assert.Equal(t, tc.tracing, tracing(last), "fentry/fexit programs loaded")
			assert.Equal(t, tc.disabled, l.DisabledEvents())
			for _, ev := range tc.disabled {
				for name, rawEv := range rawTpEvents {
					if rawEv == ev {
						assert.NotContains(t, last, name)
					}
				}
			}
			if len(tc.fails) == 0 {
				assert.NoError(t, l.Degraded())
			} else {
				// Every failure that led to a fallback, and what it cost.
				for _, f := range tc.fails {
					assert.ErrorContains(t, l.Degraded(), "program "+f.prog+":")
				}
			}
		})
	}
}

// TestNewLoaderLoadErrors pins the cilium/ebpf error formats the load
// fallback relies on, by loading programs that fail on the running kernel.
// It needs root; its name keeps it under the NewLoader skip pattern in CI.
func TestNewLoaderLoadErrors(t *testing.T) {
	ret0 := asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}
	cases := []struct {
		name  string
		prog  *ebpf.ProgramSpec
		match func(error) bool
	}{
		{
			// The instructions cilium/ebpf puts in place of a CO-RE
			// relocation it can't resolve, which the verifier rejects.
			name: "poisoned_call",
			prog: &ebpf.ProgramSpec{
				Type:         ebpf.SocketFilter,
				License:      "GPL",
				Instructions: append(asm.Instructions{asm.BuiltinFunc(btf.COREBadRelocationSentinel).Call()}, ret0...),
			},
			match: isBadRelocation,
		},
		{
			name: "poisoned_load",
			prog: &ebpf.ProgramSpec{
				Type:         ebpf.SocketFilter,
				License:      "GPL",
				Instructions: append(asm.Instructions{asm.LoadImm(asm.R10, btf.COREBadRelocationSentinel, asm.DWord)}, ret0...),
			},
			match: isBadRelocation,
		},
		{
			// An fentry target missing from kernel BTF.
			name: "no_target",
			prog: &ebpf.ProgramSpec{
				Type:         ebpf.Tracing,
				AttachType:   ebpf.AttachTraceFEntry,
				AttachTo:     "ebpfevents_test_no_such_function",
				License:      "GPL",
				Instructions: ret0,
			},
			match: func(err error) bool { return errors.Is(err, ebpf.ErrNotSupported) },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{tc.name: tc.prog}}
			coll, err := ebpf.NewCollection(spec)
			if err == nil {
				coll.Close()
			}
			require.Error(t, err)
			assert.True(t, tc.match(err), "the fallback doesn't recognise: %v", err)
			name, ok := failedProg(spec, err)
			assert.True(t, ok, "no program named in: %v", err)
			assert.Equal(t, tc.name, name)
		})
	}
}

// TestLoaderConstantsMatchObject checks that every constant fillIndexes can
// set is declared by the object. rewriteConstants fails on any constant the
// object doesn't declare, which makes NewLoader fail on every kernel that
// takes that branch -- the trap that removing the __i_*time offsets set.
func TestLoaderConstantsMatchObject(t *testing.T) {
	// fillIndexes branches on what the kernel has, so cover both sides of
	// every branch: a kernel with the newer layouts and one with the older.
	common := []btf.Type{
		testFunc("inet_csk_accept", "sk", "arg"),
		testFunc("vfs_unlink", "idmap", "dir", "dentry", "delegated_inode"),
		testFunc("do_truncate", "idmap", "dentry", "length", "time_attrs", "filp"),
		testStruct("tty_driver", "major", "minor_start", "type", "subtype"),
	}
	// struct inode is included in each of its three layouts, and kernfs_node
	// and tty_driver in their old and new ones, so that a fill keyed on any
	// spelling would be exercised. The probes read all of them through CO-RE
	// flavors, so the object must declare no offset constant for them. want
	// lists the offsets the probes do depend on.
	kernels := []struct {
		name  string
		types []btf.Type
		want  map[string]uint32
	}{
		{
			name: "6.15+ layouts",
			types: append([]btf.Type{
				testFunc("vfs_rename", "rd"),
				testStruct("iov_iter", "iter_type", "__iov"),
				testStruct("kernfs_node", "count", "__parent"),
				testStruct("inode", "i_mode", "i_atime_sec", "i_mtime_sec", "i_ctime_sec",
					"i_atime_nsec", "i_mtime_nsec", "i_ctime_nsec"),
			}, common...),
			want: map[string]uint32{
				"off__iov_iter____iov__": 8,
			},
		},
		{
			name: "6.7-6.10 layouts",
			types: append([]btf.Type{
				testFunc("vfs_rename", "rd"),
				testStruct("iov_iter", "iter_type", "__iov"),
				testStruct("kernfs_node", "count", "active", "parent"),
				testStruct("inode", "i_mode", "__i_atime", "__i_mtime", "__i_ctime"),
			}, common...),
			want: map[string]uint32{
				"off__iov_iter____iov__": 8,
			},
		},
		{
			name: "pre-6.4 layouts",
			types: append([]btf.Type{
				testFunc("vfs_rename", "old_dir", "old_dentry", "new_dir", "new_dentry"),
				testStruct("iov_iter", "iter_type", "iov"),
				testStruct("kernfs_node", "count", "parent"),
				testStruct("inode", "i_mode", "i_atime", "i_mtime", "i_ctime"),
			}, common...),
		},
	}

	for _, k := range kernels {
		t.Run(k.name, func(t *testing.T) {
			l := &Loader{constants: map[string]any{}, kbtf: testKernelBTF(t, k.types...)}
			require.NoError(t, l.fillIndexes())

			for name, off := range k.want {
				assert.Equal(t, off, l.constants[name], "%s", name)
			}

			spec, err := loadBpf()
			require.NoError(t, err)
			assert.NoError(t, l.rewriteConstants(spec))
		})
	}

	// The running kernel, when its BTF is readable (no root needed).
	t.Run("running kernel", func(t *testing.T) {
		kbtf, err := btf.LoadKernelSpec()
		if err != nil {
			t.Skipf("no kernel BTF: %v", err)
		}
		l := &Loader{constants: map[string]any{}, kbtf: kbtf}
		if err := l.fillIndexes(); err != nil {
			t.Skipf("this kernel lacks a function the loader needs: %v", err)
		}
		spec, err := loadBpf()
		require.NoError(t, err)
		assert.NoError(t, l.rewriteConstants(spec))
	})
}

func TestRewriteConstantsRejectsUndeclared(t *testing.T) {
	spec, err := loadBpf()
	require.NoError(t, err)

	// The object stopped declaring the inode timestamp offsets when the
	// probes moved to CO-RE flavors; filling one must be reported.
	l := &Loader{constants: map[string]any{"off__inode____i_atime__": uint32(8)}}
	assert.ErrorContains(t, l.rewriteConstants(spec), "off__inode____i_atime__")
}
