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
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the loader without loading anything into a kernel, so
// they need neither root nor BPF support and run in CI, unlike TestNewLoader.
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

// Functions whose tracing variant is chosen only if the function exists in
// kernel BTF. The rest switch on trampoline support alone. Keep in sync with
// pruneUnusedProgs and attachBpfProgs.
var btfGuardedFuncs = map[string]bool{
	"do_renameat2":   true,
	"tcp_v6_connect": true,
	"tty_write":      true,
	"vfs_writev":     true,
}

func TestPruneUnusedProgs(t *testing.T) {
	base, err := loadBpf()
	require.NoError(t, err)

	// Every function the object traces with both a tracing and a kprobe
	// variant. Derived from the object, so a probe added or renamed upstream
	// (as ec1ba650 renamed taskstats_exit to disassociate_ctty) is covered
	// without editing this test.
	families := map[string]map[string]bool{}
	for name := range base.Programs {
		if fam, fn, ok := splitProgName(name); ok {
			if families[fn] == nil {
				families[fn] = map[string]bool{}
			}
			families[fn][fam] = true
		}
	}
	var dual []string
	for fn, fams := range families {
		if fams["tracing"] && fams["kprobe"] {
			dual = append(dual, fn)
		}
	}
	require.NotEmpty(t, dual)

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

	cases := []struct {
		name        string
		hasBpfTramp bool
		missing     []string
	}{
		{name: "no trampolines", hasBpfTramp: false},
		{name: "trampolines, all functions in BTF", hasBpfTramp: true},
		// The kernel from beats#46719's dev box: trampolines, but
		// do_renameat2 absent from BTF.
		{name: "trampolines, do_renameat2 missing", hasBpfTramp: true, missing: []string{"do_renameat2"}},
		{name: "trampolines, every guarded function missing", hasBpfTramp: true,
			missing: []string{"do_renameat2", "tcp_v6_connect", "tty_write", "vfs_writev"}},
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

			for _, fn := range dual {
				want := "kprobe"
				if tc.hasBpfTramp && !(btfGuardedFuncs[fn] && missing[fn]) {
					want = "tracing"
				}

				got := map[string]bool{}
				for name := range spec.Programs {
					if fam, f, ok := splitProgName(name); ok && f == fn {
						got[fam] = true
					}
				}
				assert.Equal(t, map[string]bool{want: true}, got,
					"%s: exactly the %s variants must survive the prune", fn, want)
			}

			// Programs that are not part of a tracing/kprobe pair are not
			// pruneUnusedProgs' business.
			for name := range base.Programs {
				if _, fn, ok := splitProgName(name); ok && families[fn]["tracing"] && families[fn]["kprobe"] {
					continue
				}
				assert.Contains(t, spec.Programs, name, "%s must not be pruned", name)
			}
		})
	}
}

// Programs the object contains but attachBpfProgs never attaches, so
// populateObjs deliberately leaves their fields nil. They are still loaded.
// If one gets wired up, it needs a case in populateObjs and must leave this
// list, which the test enforces.
var unattachedProgs = map[string]bool{
	"kprobe__ptrace_attach": true,
	"module_load":           true,
	"tracepoint_syscalls_sys_enter_memfd_create": true,
	"tracepoint_syscalls_sys_enter_shmget":       true,
}

func TestPopulateObjs(t *testing.T) {
	spec, err := loadBpf()
	require.NoError(t, err)

	// Placeholders: populateObjs only copies pointers, nothing is loaded.
	coll := &ebpf.Collection{
		Programs: map[string]*ebpf.Program{},
		Maps:     map[string]*ebpf.Map{},
	}
	for name := range spec.Programs {
		coll.Programs[name] = new(ebpf.Program)
	}
	for name := range unattachedProgs {
		require.Contains(t, spec.Programs, name, "stale entry in unattachedProgs")
	}
	for name := range spec.Maps {
		coll.Maps[name] = new(ebpf.Map)
	}

	l := &Loader{coll: coll}
	l.populateObjs()

	// Every program and map field of bpfObjects must point at the collection
	// entry its ebpf tag names. A missing case leaves the field nil, and the
	// attach code would then dereference it.
	check := func(objs any, lookup func(string) any) {
		v := reflect.ValueOf(objs).Elem()
		for i := 0; i < v.NumField(); i++ {
			tag := v.Type().Field(i).Tag.Get("ebpf")
			field := v.Type().Field(i).Name
			want := lookup(tag)
			require.NotNil(t, want, "%s (%s) has no counterpart in the object", field, tag)
			if unattachedProgs[tag] {
				assert.True(t, v.Field(i).IsNil(), "%s is populated: remove %q from unattachedProgs", field, tag)
				continue
			}
			assert.Same(t, want, v.Field(i).Interface(), "%s is not populated from %q", field, tag)
		}
	}
	check(&l.objs.bpfPrograms, func(name string) any {
		if p, ok := coll.Programs[name]; ok {
			return p
		}
		return nil
	})
	check(&l.objs.bpfMaps, func(name string) any {
		if m, ok := coll.Maps[name]; ok {
			return m
		}
		return nil
	})
}

func TestPruneRawTpProgs(t *testing.T) {
	spec, err := loadBpf()
	require.NoError(t, err)

	var rawTp, rest []string
	for name, p := range spec.Programs {
		if p.Type == ebpf.Tracing && p.AttachType == ebpf.AttachTraceRawTp {
			rawTp = append(rawTp, name)
		} else {
			rest = append(rest, name)
		}
	}
	require.NotEmpty(t, rawTp, "the object should contain tp_btf programs")

	pruneRawTpProgs(spec)

	for _, name := range rawTp {
		assert.NotContains(t, spec.Programs, name)
	}
	for _, name := range rest {
		assert.Contains(t, spec.Programs, name)
	}
}

func TestFillFieldOffsetAs(t *testing.T) {
	const constant = "off__kernfs_node____parent__"

	cases := []struct {
		name    string
		members []string
		want    any // nil: the constant must not be set
	}{
		{name: "6.15+: __parent", members: []string{"count", "__parent"}, want: uint32(8)},
		{name: "before 6.15: parent", members: []string{"count", "active", "parent"}, want: uint32(16)},
		{name: "both: __parent wins", members: []string{"count", "parent", "__parent"}, want: uint32(16)},
		{name: "neither", members: []string{"count"}, want: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := &Loader{
				constants: map[string]any{},
				kbtf:      testKernelBTF(t, testStruct("kernfs_node", tc.members...)),
			}
			require.NoError(t, l.fillFieldOffsetAs("kernfs_node", "__parent", "__parent", "parent"))

			got, ok := l.constants[constant]
			if tc.want == nil {
				assert.False(t, ok, "an absent field must leave the constant unset")
				return
			}
			assert.Equal(t, tc.want, got)
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
	// struct inode is included in each of its three layouts so that a fill
	// keyed on any timestamp spelling would be exercised. want lists the
	// offsets the probes depend on: if one is missing, the probe reads offset
	// 0 and silently reports the wrong cgroup path or tty, with no load error.
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
				"off__iov_iter____iov__":       8,
				"off__kernfs_node____parent__": 8,
				"off__tty_driver__type__":      16,
				"off__tty_driver__subtype__":   24,
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
				"off__iov_iter____iov__":       8,
				"off__kernfs_node____parent__": 16,
				"off__tty_driver__type__":      16,
				"off__tty_driver__subtype__":   24,
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
			want: map[string]uint32{
				"off__kernfs_node____parent__": 8,
				"off__tty_driver__type__":      16,
				"off__tty_driver__subtype__":   24,
			},
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
