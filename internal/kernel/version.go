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
	"os"
	"strconv"
	"strings"
	"syscall"
)

const (
	// We only support Linux 5.10.16+
	//
	// Linux commit e114dd64c0071500345439fc79dd5e0f9d106ed (went in in
	// 5.11/5.10.16) fixed a verifier bug that (as of 9/28/2022) causes our
	// probes to fail to load.
	minSupportedVersion = "5.10.16"

	procVersionSignature = "/proc/version_signature"
)

type version struct {
	maj, min, patch int
}

func (v version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.maj, v.min, v.patch)
}

func (v version) Less(other version) bool {
	return v.maj < other.maj ||
		(v.maj == other.maj && v.min < other.min) ||
		(v.maj == other.maj && v.min == other.min && v.patch < other.patch)
}

func new(s string) (version, error) {
	var (
		v     version
		parts = strings.Split(s, ".")
	)
	if len(parts) == 1 && parts[0] == "" {
		return v, nil
	}

	major, err := strconv.ParseUint(parts[0], 10, 0)
	if err != nil {
		return v, fmt.Errorf("parse version: bad major: %s", s)
	}
	v.maj = int(major)
	if len(parts) == 1 {
		return v, nil
	}

	minor, err := strconv.ParseUint(parts[1], 10, 0)
	if err != nil {
		return v, fmt.Errorf("parse version: bad minor: %s", s)
	}
	v.min = int(minor)
	if len(parts) == 2 {
		return v, nil
	}

	patch, err := strconv.ParseUint(parts[2], 10, 0)
	if err != nil {
		return v, fmt.Errorf("parse version: bad patch: %s", s)
	}
	v.patch = int(patch)

	return v, nil
}

func CheckSupported() error {
	currentVersion, err := kernelVersion()
	if err != nil {
		return fmt.Errorf("current version: %v", err)
	}

	minVersion, err := new(minSupportedVersion)
	if err != nil {
		return fmt.Errorf("min version: %v", err)
	}

	if !minVersion.Less(currentVersion) {
		return fmt.Errorf("min kernel version (%s) is higher or equal than current kernel version (%s)", minVersion.String(), currentVersion.String())
	}

	return nil
}

func kernelVersion() (version, error) {
	var v version

	if _, err := os.Stat(procVersionSignature); err == nil {
		// Ubuntu kernels do not report the true upstream kernel source version in
		// utsname.release, they report the "ABI version", which is the upstream
		// kernel major.minor with some extra ABI information, e.g.:
		// 5.15.0-48-generic. The upstream patch version is always set to 0.
		//
		// Ubuntu provides a file under procfs that reports the actual upstream
		// source version, so we use that instead if it exists.
		f, err := os.Open(procVersionSignature)
		if err != nil {
			return v, fmt.Errorf("open %s: %v", procVersionSignature, err)
		}
		defer f.Close()

		_, err = fmt.Fscanf(f, "%*s %*s %d.%d.%d\n", &v.maj, &v.min, &v.patch)
		if err != nil {
			return v, fmt.Errorf("read %s: %v", procVersionSignature, err)
		}

		return v, nil
	}

	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return v, fmt.Errorf("uname: %v", err)
	}
	release := make([]byte, 0, len(uname.Release))
	for _, v := range uname.Release {
		if v == 0 {
			break
		}
		release = append(release, byte(v))
	}

	if strings.Contains(string(release), "Debian") {
		// Like Ubuntu, what Debian reports in the un.release buffer is the
		// "ABI version", which is the major.minor of the upstream, with the
		// patch always set to 0 (and some further ABI numbers). e.g.:
		// 5.10.0-18-amd64
		//
		// See the following docs for more info:
		// https://kernel-team.pages.debian.net/kernel-handbook/ch-versions.html
		//
		// Unlike Ubuntu, Debian does not provide a special procfs file
		// indicating the actual upstream source. Instead, it puts the actual
		// upstream source version into the un.version field, after the string
		// "Debian"
		parts := strings.Split(string(release), "Debian ")
		_, err := fmt.Sscanf(parts[1], "%d.%d.%d", &v.maj, &v.min, &v.patch)
		if err != nil {
			return v, fmt.Errorf("read debian release: %v", err)
		}
	}

	_, err := fmt.Sscanf(string(release), "%d.%d.%d", &v.maj, &v.min, &v.patch)
	if err != nil {
		return v, fmt.Errorf("read release: %v", err)
	}

	return v, nil
}
