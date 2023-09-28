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

package varlen

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/elastic/ebpfevents/internal/endian"
)

// TODO(matt): this is implemented in cloud-defend

type (
	Field uint32
	Map   map[Field]any
)

const (
	Cwd Field = iota
	Argv
	Env
	Filename
	Path
	OldPath
	NewPath
	TTYOutput
	CgroupPath
)

type varlenStart struct {
	nfields uint32
	size    uint64
}

type varlenField struct {
	typ  Field
	size uint32
}

func DeserializeVarlenFields(r *bytes.Reader) (Map, error) {
	start, err := deserializeVarlenStart(r)
	if err != nil {
		return nil, fmt.Errorf("deserialize varlen start: %v", err)
	}

	ret := make(Map)
	for i := uint32(0); i < start.nfields; i++ {
		field, err := deserializeVarlenFieldHeader(r)
		if err != nil {
			return nil, fmt.Errorf("deserialize varlen header: %v", err)
		}

		switch field.typ {
		case Cwd, Filename, Path, OldPath, NewPath, TTYOutput, CgroupPath:
			str, err := deserializeVarlenString(r, field.size)
			if err != nil {
				return nil, fmt.Errorf("deserialize varlen string: %v", err)
			}
			ret[field.typ] = str
		case Argv:
			argv, err := deserializeVarlenArgv(r, field.size)
			if err != nil {
				return nil, fmt.Errorf("deserialize varlen argv: %v", err)
			}
			ret[field.typ] = argv
		case Env:
			env, err := deserializeVarlenEnv(r, field.size)
			if err != nil {
				return nil, fmt.Errorf("deserialize varlen env: %v", err)
			}
			ret[field.typ] = env
		default:
			return nil, fmt.Errorf("unsupported varlen type: %d", field.typ)
		}
	}

	if r.Len() != 0 {
		return nil, fmt.Errorf("data left in reader: %v", r.Len())
	}

	return ret, nil
}

func deserializeVarlenStart(r *bytes.Reader) (*varlenStart, error) {
	var ret varlenStart

	if err := binary.Read(r, endian.Native, &ret.nfields); err != nil {
		return nil, fmt.Errorf("read nfields: %v", err)
	}
	if err := binary.Read(r, endian.Native, &ret.size); err != nil {
		return nil, fmt.Errorf("read size: %v", err)
	}

	return &ret, nil
}

func deserializeVarlenFieldHeader(r *bytes.Reader) (*varlenField, error) {
	var ret varlenField

	if err := binary.Read(r, endian.Native, &ret.typ); err != nil {
		return nil, fmt.Errorf("read typ: %v", err)
	}
	if err := binary.Read(r, endian.Native, &ret.size); err != nil {
		return nil, fmt.Errorf("read size: %v", err)
	}

	return &ret, nil
}

func deserializeVarlenString(r *bytes.Reader, size uint32) (string, error) {
	if size == 0 {
		return "", nil
	}

	var b strings.Builder
	b.Grow(int(size - 1))

	for i := uint32(0); i < size-1; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}

		if err = b.WriteByte(c); err != nil {
			return "", err
		}
	}

	// read null terminator
	_, err := r.ReadByte()
	if err != nil {
		return "", err
	}

	return b.String(), nil
}

func deserializeVarlenArgv(r *bytes.Reader, size uint32) ([]string, error) {
	var (
		b   strings.Builder
		ret = make([]string, 0)
	)
	b.Grow(int(size))

	for i := uint32(0); i < size; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return nil, err
		}

		if c == 0 {
			ret = append(ret, b.String())
			b.Reset()
			continue
		}
		if err = b.WriteByte(c); err != nil {
			return nil, err
		}
	}

	return ret, nil
}

func deserializeVarlenEnv(r *bytes.Reader, size uint32) (map[string]string, error) {
	var (
		key        strings.Builder
		value      strings.Builder
		parsingKey = true
		ret        = make(map[string]string)
	)

	for i := uint32(0); i < size; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return nil, err
		}

		switch c {
		case 0:
			ret[key.String()] = value.String()
			key.Reset()
			value.Reset()
			parsingKey = true
		case '=':
			parsingKey = false
		default:
			if parsingKey {
				if err = key.WriteByte(c); err != nil {
					return nil, err
				}
			} else {
				if err = value.WriteByte(c); err != nil {
					return nil, err
				}
			}
		}
	}

	return ret, nil
}
