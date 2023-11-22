package varlen_test

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/ebpfevents/pkg/endian"
	"github.com/elastic/ebpfevents/pkg/varlen"
)

func writeVarlenFields(t *testing.T, w *bufio.Writer, m varlen.Map) {
	t.Helper()

	var (
		size       uint64
		nfields    uint32
		fieldSizes = make(map[varlen.Field]uint32)
	)

	for k, v := range m {
		size += 4 // `type`
		size += 4 // varlen_field `size`

		fieldSizes[k] = 0
		switch k {
		case varlen.Cwd, varlen.Filename, varlen.CgroupPath,
			varlen.Path, varlen.OldPath, varlen.NewPath, varlen.TTYOutput,
			varlen.SymlinkTargetPath:
			fieldSizes[k] += uint32(len(v.(string))) + 1 // null terminator
		case varlen.Argv:
			for _, str := range v.([]string) {
				fieldSizes[k] += uint32(len(str)) + 1 // null terminator
			}
		case varlen.Env:
			for key, value := range v.(map[string]string) {
				fieldSizes[k] += uint32(len(key))
				fieldSizes[k] += 1 // equal sign
				fieldSizes[k] += uint32(len(value))
				fieldSizes[k] += 1 // null terminator
			}
		default:
			t.Fatalf("unsupported varlen type: %d", k)
		}

		size += uint64(fieldSizes[k])
		nfields++
	}

	assert.Nil(t, binary.Write(w, endian.Native, nfields))
	assert.Nil(t, binary.Write(w, endian.Native, size))

	for k, v := range m {
		assert.Nil(t, binary.Write(w, endian.Native, k))
		assert.Nil(t, binary.Write(w, endian.Native, fieldSizes[k]))

		switch k {
		case varlen.Cwd, varlen.Filename, varlen.CgroupPath,
			varlen.Path, varlen.OldPath, varlen.NewPath, varlen.TTYOutput,
			varlen.SymlinkTargetPath:
			_, err := w.WriteString(v.(string))
			assert.Nil(t, err)
			assert.Nil(t, w.WriteByte(0))
		case varlen.Argv:
			for _, str := range v.([]string) {
				_, err := w.WriteString(str)
				assert.Nil(t, err)
				assert.Nil(t, w.WriteByte(0))
			}
		case varlen.Env:
			for key, value := range v.(map[string]string) {
				_, err := w.WriteString(key)
				assert.Nil(t, err)
				assert.Nil(t, w.WriteByte('='))
				_, err = w.WriteString(value)
				assert.Nil(t, err)
				assert.Nil(t, w.WriteByte(0))
			}
		default:
			t.Fatalf("unsupported varlen type: %d", k)
		}
	}

	assert.Nil(t, w.Flush())
}

func TestDeserializeVarlenFields(t *testing.T) {
	buf := bytes.NewBuffer(nil)

	expectedMap := varlen.Map{
		varlen.Cwd:               "test_cwd",
		varlen.Argv:              []string{"a", "r", "g", "v"},
		varlen.Env:               map[string]string{"a": "b", "c": "d"},
		varlen.Filename:          "test_filename",
		varlen.Path:              "test_path",
		varlen.OldPath:           "test_oldpath",
		varlen.NewPath:           "test_newpath",
		varlen.TTYOutput:         "test_tty",
		varlen.CgroupPath:        "test_cgroup",
		varlen.SymlinkTargetPath: "test_symlink",
	}
	writeVarlenFields(t, bufio.NewWriter(buf), expectedMap)

	m, err := varlen.DeserializeVarlenFields(bytes.NewReader(buf.Bytes()))
	assert.Nil(t, err)

	assert.Equal(t, expectedMap, m)
}
