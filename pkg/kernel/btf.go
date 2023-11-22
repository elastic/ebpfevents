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

package kernel

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
)

func FieldExists(kbtf *btf.Spec, structName, fieldName string) bool {
	_, err := FieldOffset(kbtf, structName, fieldName)
	return err == nil
}

func FieldOffset(kbtf *btf.Spec, structName, fieldName string) (uint32, error) {
	var s *btf.Struct
	if err := kbtf.TypeByName(structName, &s); err != nil {
		return 0, fmt.Errorf("find btf struct: %v", err)
	}

	return fieldOffsetRecur(kbtf, 0, s, fieldName)
}

func fieldOffsetRecur(kbtf *btf.Spec, base btf.Bits, typ btf.Type, fieldName string) (uint32, error) {
	var members []btf.Member

	switch t := typ.(type) {
	case *btf.Struct:
		members = t.Members
	case *btf.Union:
		members = t.Members
	}

	for _, m := range members {
		if m.Name == fieldName {
			return (base + m.Offset).Bytes(), nil
		}

		switch m.Type.(type) {
		case *btf.Struct, *btf.Union:
			off, err := fieldOffsetRecur(kbtf, base+m.Offset, m.Type, fieldName)
			if err != nil {
				continue
			}
			return off, nil
		default:
			continue
		}
	}

	return 0, fmt.Errorf("field %s not found", fieldName)
}

func ArgIdxByFunc(kbtf *btf.Spec, funcName, argName string) (uint32, error) {
	funcProto, err := funcProtoByName(kbtf, funcName)
	if err != nil {
		return 0, fmt.Errorf("func proto by name: %v", err)
	}

	for i, funcParam := range funcProto.Params {
		if funcParam.Name == argName {
			return uint32(i), nil
		}
	}

	return 0, fmt.Errorf("arg %s not found in %s proto", argName, funcName)
}

func RetIdxByFunc(kbtf *btf.Spec, funcName string) (uint32, error) {
	funcProto, err := funcProtoByName(kbtf, funcName)
	if err != nil {
		return 0, fmt.Errorf("func proto by name: %v", err)
	}

	return uint32(len(funcProto.Params)), nil
}

func ArgExists(kbtf *btf.Spec, funcName, argName string) bool {
	_, err := ArgIdxByFunc(kbtf, funcName, argName)
	return err == nil
}

func FuncExists(kbtf *btf.Spec, funcName string) bool {
	_, err := funcProtoByName(kbtf, funcName)
	return err == nil
}

func funcProtoByName(kbtf *btf.Spec, name string) (*btf.FuncProto, error) {
	var f *btf.Func
	if err := kbtf.TypeByName(name, &f); err != nil {
		return nil, fmt.Errorf("find btf func: %v", err)
	}

	return f.Type.(*btf.FuncProto), nil
}
