package kernel

import (
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
)

func TestFieldExists(t *testing.T) {
	spec, err := btf.LoadKernelSpec()
	assert.Nil(t, err)

	assert.True(t, FieldExists(spec, "tty_struct", "link"))
	assert.False(t, FieldExists(spec, "tty_struct", "qwerty"))
}

func TestFuncExists(t *testing.T) {
	spec, err := btf.LoadKernelSpec()
	assert.Nil(t, err)

	assert.True(t, FuncExists(spec, "do_filp_open"))
	assert.False(t, FuncExists(spec, "qwerty"))
}

func TestArgExists(t *testing.T) {
	spec, err := btf.LoadKernelSpec()
	assert.Nil(t, err)

	assert.True(t, ArgExists(spec, "do_filp_open", "pathname"))
	assert.False(t, ArgExists(spec, "do_filp_open", "qwerty"))
}

func TestArgIdxByFunc(t *testing.T) {
	spec, err := btf.LoadKernelSpec()
	assert.Nil(t, err)

	expectedIdx := uint32(1)
	idx, err := ArgIdxByFunc(spec, "do_filp_open", "pathname")
	assert.Nil(t, err)
	assert.Equal(t, expectedIdx, idx)
}

func TestFieldOffset(t *testing.T) {
	spec, err := btf.LoadKernelSpec()
	assert.Nil(t, err)

	expectedOffset := uint32(17) // 4xint + 1xchar
	off, err := FieldOffset(spec, "termios", "c_cc")
	assert.Nil(t, err)
	assert.Equal(t, expectedOffset, off)
}
