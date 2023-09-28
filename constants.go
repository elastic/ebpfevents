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

package ebpfevents

import (
	"fmt"

	"github.com/elastic/ebpfevents/internal/kernel"
)

const (
	argIdxFmt      = "arg__%s__%s__"    // func, arg
	retIdxFmt      = "ret__%s__"        // func
	argExistsFmt   = "exists__%s__%s__" // func, arg
	fieldOffsetFmt = "off__%s__%s__"    // struct, field
)

func (l *Loader) fillArgIndex(funcName, argName string) error {
	name := fmt.Sprintf(argIdxFmt, funcName, argName)

	idx, err := kernel.ArgIdxByFunc(l.kbtf, funcName, argName)
	if err != nil {
		return fmt.Errorf("fill %s: %v", name, err)
	}
	l.constants[name] = idx

	return nil
}

func (l *Loader) fillRetIndex(funcName string) error {
	name := fmt.Sprintf(retIdxFmt, funcName)

	idx, err := kernel.RetIdxByFunc(l.kbtf, funcName)
	if err != nil {
		return fmt.Errorf("fill %s: %v", name, err)
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
		return fmt.Errorf("fill %s: %v", name, err)
	}
	l.constants[name] = off

	return nil
}

func (l *Loader) fillIndexes() error {
	if err := l.fillArgIndex("vfs_unlink", "dentry"); err != nil {
		return fmt.Errorf("fill arg index: %v", err)
	}
	if err := l.fillRetIndex("vfs_unlink"); err != nil {
		return fmt.Errorf("fill ret index: %v", err)
	}

	if kernel.ArgExists(l.kbtf, "vfs_rename", "rd") {
		if err := l.fillArgExists("vfs_rename", "rd"); err != nil {
			return fmt.Errorf("fill arg exists: %v", err)
		}
	} else {
		if err := l.fillArgIndex("vfs_rename", "old_dentry"); err != nil {
			return fmt.Errorf("fill arg index: %v", err)
		}
		if err := l.fillArgIndex("vfs_rename", "new_dentry"); err != nil {
			return fmt.Errorf("fill arg index: %v", err)
		}
	}
	if err := l.fillRetIndex("vfs_rename"); err != nil {
		return fmt.Errorf("fill ret index: %v", err)
	}

	if kernel.FieldExists(l.kbtf, "iov_iter", "__iov") {
		if err := l.fillFieldOffset("iov_iter", "__iov"); err != nil {
			return fmt.Errorf("fill field offset: %v", err)
		}
	}

	return nil
}
