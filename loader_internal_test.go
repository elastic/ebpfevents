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
	"maps"
	"slices"
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

// TestDualFuncs checks dualFuncs against the object: every dual function is
// listed, with all of its programs in the right set. A function missing from
// dualFuncs would have both variants loaded and neither attached.
func TestDualFuncs(t *testing.T) {
	want := objectDualFuncs(t)
	require.NotEmpty(t, want)

	got := map[string]map[string][]string{}
	for _, df := range dualFuncs {
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
		// static in fs/open.c, so pahole may leave them out.
		{name: "trampolines, chmod_common and chown_common missing", hasBpfTramp: true,
			missing: []string{"chmod_common", "chown_common"}},
		{name: "trampolines, every function missing", hasBpfTramp: true, missing: dual},
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

			wantPicked := slices.Clone(fixedProgs)
			for _, fn := range dual {
				want := "kprobe"
				if tc.hasBpfTramp && !missing[fn] {
					want = "tracing"
				}
				wantPicked = append(wantPicked, byFunc[fn][want]...)

				got := map[string]bool{}
				for name := range spec.Programs {
					if fam, f, ok := splitProgName(name); ok && f == fn {
						got[fam] = true
					}
				}
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
	for _, df := range dualFuncs {
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
