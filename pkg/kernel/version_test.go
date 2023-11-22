package kernel

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewVersion(t *testing.T) {
	tests := []struct {
		vstring         string
		maj, min, patch int
	}{
		{"1.0.0", 1, 0, 0},
		{"1.2.3", 1, 2, 3},
		{"0.0.0", 0, 0, 0},
		{"1.2", 1, 2, 0},
		{"1", 1, 0, 0},
		{"1.2.3.4.5", 1, 2, 3},
		{"", 0, 0, 0},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("test new version #%d", i), func(t *testing.T) {
			v, err := new(tt.vstring)
			assert.NoError(t, err)
			assert.Equal(t, v.maj, tt.maj)
			assert.Equal(t, v.min, tt.min)
			assert.Equal(t, v.patch, tt.patch)
		})
	}
}

func TestNewVersionError(t *testing.T) {
	tests := []string{
		"1.-1.0",
		".1.0",
		"1.1.",
	}

	for i, s := range tests {
		t.Run(fmt.Sprintf("test new version error #%d", i), func(t *testing.T) {
			_, err := new(s)
			assert.Error(t, err)
		})
	}
}
