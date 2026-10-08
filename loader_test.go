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
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/elastic/ebpfevents"
)

// helperEnv makes the test binary run an action for TestNewLoader instead of
// tests, see TestNewLoaderHelper.
const helperEnv = "EBPFEVENTS_TEST_HELPER"

const ptyOutput = "ebpfevents pty test\n"

// TestNewLoader loads the probe on the running kernel and checks the values
// it reads through CO-RE flavors (ebpf's vmlinux_extra.h): inode timestamps,
// kernfs_node parents and tty_driver type/subtype. Only the flavor that
// matches the running kernel is exercised, so run it on kernels on both sides
// of 6.6, 6.7, 6.11 and 6.15. It needs root.
func TestNewLoader(t *testing.T) {
	l, err := ebpfevents.NewLoader()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	records := make(chan ebpfevents.Record, 1024)
	go l.EventLoop(ctx, records)
	defer func() {
		cancel()
		assert.NoError(t, l.Close())
	}()

	exe, err := os.Executable()
	require.NoError(t, err)

	t.Run("Events", func(t *testing.T) {
		// trigger an event
		fname := filepath.Join(t.TempDir(), "testloader")
		_, err := os.Create(fname)
		assert.NoError(t, err)

		timeout := time.After(5 * time.Second)
		for i := range 3 {
			select {
			case r := <-records:
				assert.NoError(t, r.Error)
			case <-timeout:
				t.Errorf("timed out waiting for event %d/3", i+1)
				return
			}
		}
	})

	t.Run("FileTimestamps", func(t *testing.T) {
		// Distinct seconds and nanoseconds in each timestamp, so that a
		// swapped field or a misread nanosecond part can't pass.
		atime := time.Unix(1700000000, 123456789)
		mtime := time.Unix(1700000001, 987654321)

		dir := t.TempDir()
		oldPath := filepath.Join(dir, "timestamps")
		newPath := filepath.Join(dir, "timestamps-renamed")

		f, err := os.Create(oldPath)
		require.NoError(t, err)
		require.NoError(t, f.Close())
		require.NoError(t, os.Chtimes(oldPath, atime, mtime))
		require.NoError(t, os.Rename(oldPath, newPath))

		// The rename event is filled after the rename returns, so a stat
		// taken now sees the same inode times.
		var st unix.Stat_t
		require.NoError(t, unix.Stat(newPath, &st))

		ev := nextEvent(t, records, func(e *ebpfevents.FileRename) bool {
			return int(e.Pids.Tgid) == os.Getpid() && filepath.Base(e.NewPath) == filepath.Base(newPath)
		})
		assert.Equal(t, st.Atim.Nano(), ev.Finfo.Atime.UnixNano(), "atime")
		assert.Equal(t, st.Mtim.Nano(), ev.Finfo.Mtime.UnixNano(), "mtime")
		assert.Equal(t, st.Ctim.Nano(), ev.Finfo.Ctime.UnixNano(), "ctime")
	})

	t.Run("CgroupPath", func(t *testing.T) {
		const root = "/sys/fs/cgroup"

		var sfs unix.Statfs_t
		if err := unix.Statfs(root, &sfs); err != nil || sfs.Type != unix.CGROUP2_SUPER_MAGIC {
			t.Skipf("no cgroup v2 at %s", root)
		}
		// The probe takes the path from the task's pids css. The pids
		// controller has to be enabled at every level, or the path stops
		// at an ancestor.
		if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte("+pids"), 0); err != nil {
			t.Skipf("pids cgroup controller not available: %v", err)
		}

		// Nested, so that building the path walks more than one kernfs_node
		// parent.
		rel := fmt.Sprintf("/ebpfevents_test_%d/nested", os.Getpid())
		leaf := filepath.Join(root, rel)
		parent := filepath.Dir(leaf)
		require.NoError(t, os.MkdirAll(leaf, 0o755))
		t.Cleanup(func() {
			_ = os.Remove(leaf)
			_ = os.Remove(parent)
		})
		require.NoError(t, os.WriteFile(filepath.Join(parent, "cgroup.subtree_control"), []byte("+pids"), 0))

		fd, err := unix.Open(leaf, unix.O_RDONLY|unix.O_DIRECTORY, 0)
		require.NoError(t, err)
		defer func() { _ = unix.Close(fd) }()

		cmd := exec.Command(exe, "-test.run=^$")
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
		require.NoError(t, cmd.Run())

		ev := nextEvent(t, records, func(e *ebpfevents.ProcessExec) bool {
			return int(e.Pids.Tgid) == cmd.Process.Pid
		})
		// A suffix, because under a cgroup namespace the probe still walks
		// up to the host's root.
		assert.True(t, strings.HasSuffix(ev.CgroupPath, rel),
			"cgroup path %q should end with %q", ev.CgroupPath, rel)
	})

	t.Run("TtyWritePty", func(t *testing.T) {
		if _, err := os.Stat("/dev/ptmx"); err != nil {
			t.Skipf("no pty support: %v", err)
		}

		// The probe ignores tty writes from the process that loaded it, so
		// the write has to come from another process.
		cmd := exec.Command(exe, "-test.run=^TestNewLoaderHelper$")
		cmd.Env = append(os.Environ(), helperEnv+"=pty")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "helper: %s", out)

		ev := nextEvent(t, records, func(e *ebpfevents.ProcessTTYWrite) bool {
			return int(e.Pids.Tgid) == cmd.Process.Pid
		})
		assert.Equal(t, ptyOutput, ev.Output)
		assert.Zero(t, ev.Truncated)
		// Written to the pty master (major 128), so the event must describe
		// the slave (UNIX98_PTY_SLAVE_MAJOR, 136-143). A master major means
		// the probe didn't recognise the pty master.
		assert.GreaterOrEqual(t, ev.TTY.Major, uint16(136), "tty major")
		assert.LessOrEqual(t, ev.TTY.Major, uint16(143), "tty major")
	})
}

// TestNewLoaderHelper isn't a test. TestNewLoader runs the test binary with
// helperEnv set to run an action from another process. The name keeps it
// under the NewLoader skip pattern in CI.
func TestNewLoaderHelper(t *testing.T) {
	switch action := os.Getenv(helperEnv); action {
	case "":
		t.Skip("helper process for TestNewLoader")
	case "pty":
		if err := writePtyMaster(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown helper action %q\n", action)
		os.Exit(1)
	}
}

// writePtyMaster writes ptyOutput to the master side of a new pseudo terminal.
func writePtyMaster() error {
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return fmt.Errorf("open ptmx: %w", err)
	}
	defer func() { _ = unix.Close(master) }()

	if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
		return fmt.Errorf("unlockpt: %w", err)
	}

	// Keep the slave open so the write has somewhere to go.
	slave, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(master), unix.TIOCGPTPEER,
		uintptr(unix.O_RDWR|unix.O_NOCTTY))
	if errno != 0 {
		return fmt.Errorf("TIOCGPTPEER: %w", errno)
	}
	defer func() { _ = unix.Close(int(slave)) }()

	if _, err := unix.Write(master, []byte(ptyOutput)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// nextEvent returns the first event body of type T that match accepts. The
// probe reports every process on the host, so it skips all others.
func nextEvent[T any](t *testing.T, records <-chan ebpfevents.Record, match func(*T) bool) *T {
	t.Helper()

	timeout := time.After(5 * time.Second)
	for {
		select {
		case r := <-records:
			if !assert.NoError(t, r.Error) {
				continue
			}
			if body, ok := r.Event.Body.(*T); ok && match(body) {
				return body
			}
		case <-timeout:
			t.Fatalf("timed out waiting for a %T event", *new(T))
			return nil
		}
	}
}
