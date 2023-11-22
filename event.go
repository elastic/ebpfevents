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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/elastic/ebpfevents/pkg/endian"
	"github.com/elastic/ebpfevents/pkg/varlen"
)

//go:generate stringer -linecomment=true -type=EventType,Transport,Family,FileType -output=event_string.go

type EventUnmarshaler interface {
	Unmarshal(*bytes.Reader) error
}

const TaskCommLen = 16

type EventType uint64

const (
	EventTypeProcessFork                EventType = 1 << (iota + 1) // ProcessFork
	EventTypeProcessExec                                            // ProcessExec
	EventTypeProcessExit                                            // ProcessExit
	EventTypeProcessSetsid                                          // ProcessSetsid
	EventTypeProcessSetuid                                          // ProcessSetuid
	EventTypeProcessSetgid                                          // ProcessSetgid
	EventTypeProcessTTYWrite                                        // ProcessTTYWrite
	EventTypeFileDelete                                             // FileDelete
	EventTypeFileCreate                                             // FileCreate
	EventTypeFileRename                                             // FileRename
	EventTypeNetworkConnectionAccepted                              // NetConnectionAccepted
	EventTypeNetworkConnectionAttempted                             // NetConnectionAttempted
	EventTypeNetworkConnectionClosed                                // NetConnectionClosed
)

func (et EventType) MarshalJSON() ([]byte, error) {
	return json.Marshal(et.String())
}

type Header struct {
	NsSinceBoot uint64    `json:"ns_since_boot"`
	Time        time.Time `json:"time"`
	Type        EventType `json:"type"`
}

type Event struct {
	Header `json:",inline"`
	Body   any `json:"body"`
}

type PidInfo struct {
	StartTimeNs uint64 `json:"start_time_ns"`
	Tid         uint32 `json:"tid"`
	Tgid        uint32 `json:"tgid"`
	Ppid        uint32 `json:"ppid"`
	Pgid        uint32 `json:"pgid"`
	Sid         uint32 `json:"sid"`
}

type CredInfo struct {
	Ruid         uint32 `json:"ruid"`
	Rgid         uint32 `json:"rgid"`
	Euid         uint32 `json:"euid"`
	Egid         uint32 `json:"egid"`
	Suid         uint32 `json:"suid"`
	Sgid         uint32 `json:"sgid"`
	CapPermitted uint64 `json:"cap_permitted"`
	CapEffective uint64 `json:"cap_effective"`
}

type TTYWinsize struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

type TTYTermios struct {
	Iflag uint32 `json:"iflag"`
	Oflag uint32 `json:"oflag"`
	Lflag uint32 `json:"lflag"`
	Cflag uint32 `json:"cflag"`
}

type TTYDev struct {
	Minor   uint16     `json:"minor"`
	Major   uint16     `json:"major"`
	Winsize TTYWinsize `json:"winsize"`
	Termios TTYTermios `json:"-"`
}

type ProcessFork struct {
	ParentPids PidInfo  `json:"parent_pids"`
	ChildPids  PidInfo  `json:"child_pids"`
	Creds      CredInfo `json:"creds"`
	CgroupPath string   `json:"cgroup_path"`
}

func (e *ProcessFork) Unmarshal(r *bytes.Reader) error {
	if err := binary.Read(r, endian.Native, &e.ParentPids); err != nil {
		return fmt.Errorf("read parent pids: %v", err)
	}
	if err := binary.Read(r, endian.Native, &e.ChildPids); err != nil {
		return fmt.Errorf("read child pids: %v", err)
	}
	if err := binary.Read(r, endian.Native, &e.Creds); err != nil {
		return fmt.Errorf("read creds: %v", err)
	}

	vlMap, err := varlen.DeserializeVarlenFields(r)
	if err != nil {
		return fmt.Errorf("deserialize varlen fields: %v", err)
	}
	if val, ok := vlMap[varlen.CgroupPath]; ok {
		e.CgroupPath = val.(string)
	}

	return nil
}

type ProcessExec struct {
	Pids       PidInfo           `json:"pids"`
	Creds      CredInfo          `json:"creds"`
	CTTY       TTYDev            `json:"ctty"`
	Cwd        string            `json:"cwd"`
	Argv       []string          `json:"argv"`
	Env        map[string]string `json:"env"`
	Filename   string            `json:"filename"`
	CgroupPath string            `json:"cgroup_path"`
}

func (e *ProcessExec) Unmarshal(r *bytes.Reader) error {
	if err := binary.Read(r, endian.Native, &e.Pids); err != nil {
		return fmt.Errorf("read pids: %v", err)
	}
	if err := binary.Read(r, endian.Native, &e.Creds); err != nil {
		return fmt.Errorf("read creds: %v", err)
	}
	if err := binary.Read(r, endian.Native, &e.CTTY); err != nil {
		return fmt.Errorf("read ctty: %v", err)
	}

	vlMap, err := varlen.DeserializeVarlenFields(r)
	if err != nil {
		return fmt.Errorf("deserialize varlen fields: %v", err)
	}
	if val, ok := vlMap[varlen.Cwd]; ok {
		e.Cwd = val.(string)
	}
	if val, ok := vlMap[varlen.Argv]; ok {
		e.Argv = val.([]string)
	}
	if val, ok := vlMap[varlen.Env]; ok {
		e.Env = val.(map[string]string)
	}
	if val, ok := vlMap[varlen.Filename]; ok {
		e.Filename = val.(string)
	}
	if val, ok := vlMap[varlen.CgroupPath]; ok {
		e.CgroupPath = val.(string)
	}

	return nil
}

type ProcessExit struct {
	Pids       PidInfo `json:"pids"`
	ExitCode   int32   `json:"exit_code"`
	CgroupPath string  `json:"cgroup_path"`
}

func (e *ProcessExit) Unmarshal(r *bytes.Reader) error {
	if err := binary.Read(r, endian.Native, &e.Pids); err != nil {
		return fmt.Errorf("read pids: %v", err)
	}
	if err := binary.Read(r, endian.Native, &e.ExitCode); err != nil {
		return fmt.Errorf("read exit code: %v", err)
	}

	vlMap, err := varlen.DeserializeVarlenFields(r)
	if err != nil {
		return fmt.Errorf("deserialize varlen fields: %v", err)
	}
	if val, ok := vlMap[varlen.CgroupPath]; ok {
		e.CgroupPath = val.(string)
	}

	return nil
}

type ProcessSetsid struct {
	Pids PidInfo `json:"pids"`
}

func (e *ProcessSetsid) Unmarshal(r *bytes.Reader) error {
	if err := binary.Read(r, endian.Native, &e.Pids); err != nil {
		return fmt.Errorf("read pids: %v", err)
	}
	return nil
}

type ProcessSetuid struct {
	Pids    PidInfo `json:"pids"`
	NewRuid uint32  `json:"new_ruid"`
	NewEuid uint32  `json:"new_euid"`
	NewRgid uint32  `json:"new_rgid"`
	NewEgid uint32  `json:"new_egid"`
}

func (e *ProcessSetuid) Unmarshal(r *bytes.Reader) error {
	if err := binary.Read(r, endian.Native, &e.Pids); err != nil {
		return fmt.Errorf("read pids: %v", err)
	}
	if err := binary.Read(r, endian.Native, &e.NewRuid); err != nil {
		return fmt.Errorf("read new ruid: %v", err)
	}
	if err := binary.Read(r, endian.Native, &e.NewEuid); err != nil {
		return fmt.Errorf("read new euid: %v", err)
	}
	if err := binary.Read(r, endian.Native, &e.NewRgid); err != nil {
		return fmt.Errorf("read new rgid: %v", err)
	}
	if err := binary.Read(r, endian.Native, &e.NewEgid); err != nil {
		return fmt.Errorf("read new egid: %v", err)
	}

	return nil
}

type ProcessSetgid struct {
	Pids    PidInfo `json:"pids"`
	NewRgid uint32  `json:"new_rgid"`
	NewEgid uint32  `json:"new_egid"`
	NewRuid uint32  `json:"new_ruid"`
	NewEuid uint32  `json:"new_euid"`
}

func (e *ProcessSetgid) Unmarshal(r *bytes.Reader) error {
	if err := binary.Read(r, endian.Native, &e.Pids); err != nil {
		return fmt.Errorf("read pids: %v", err)
	}
	if err := binary.Read(r, endian.Native, &e.NewRgid); err != nil {
		return fmt.Errorf("read new rgid: %v", err)
	}
	if err := binary.Read(r, endian.Native, &e.NewEgid); err != nil {
		return fmt.Errorf("read new egid: %v", err)
	}
	if err := binary.Read(r, endian.Native, &e.NewRuid); err != nil {
		return fmt.Errorf("read new ruid: %v", err)
	}
	if err := binary.Read(r, endian.Native, &e.NewEuid); err != nil {
		return fmt.Errorf("read new euid: %v", err)
	}

	return nil
}

type ProcessTTYWrite struct {
	Pids      PidInfo `json:"pids"`
	Truncated uint64  `json:"truncated"`
	CTTY      TTYDev  `json:"ctty"`
	TTY       TTYDev  `json:"tty"`
	Comm      string  `json:"comm"`
	Output    string  `json:"output"`
}

func (e *ProcessTTYWrite) Unmarshal(r *bytes.Reader) error {
	if err := binary.Read(r, endian.Native, &e.Pids); err != nil {
		return fmt.Errorf("read pids: %v", err)
	}
	if err := binary.Read(r, endian.Native, &e.Truncated); err != nil {
		return fmt.Errorf("read truncated: %v", err)
	}
	if err := binary.Read(r, endian.Native, &e.CTTY); err != nil {
		return fmt.Errorf("read ctty: %v", err)
	}
	if err := binary.Read(r, endian.Native, &e.TTY); err != nil {
		return fmt.Errorf("read tty: %v", err)
	}

	comm, err := readTaskComm(r)
	if err != nil {
		return err
	}
	e.Comm = comm

	vlMap, err := varlen.DeserializeVarlenFields(r)
	if err != nil {
		return fmt.Errorf("deserialize varlen fields: %v", err)
	}
	if val, ok := vlMap[varlen.TTYOutput]; ok {
		e.Output = val.(string)
	}

	return nil
}

type FileType uint32

const (
	FileTypeUnknown     FileType = iota // Unknown
	FileTypeFile                        // File
	FileTypeDir                         // Dir
	FileTypeSymlink                     // Symlink
	FileTypeCharDevice                  // CharDevice
	FileTypeBlockDevice                 // BlockDevice
	FileTypeNamedPipe                   // NamedPipe
	FileTypeSocket                      // Socket
)

func (ft FileType) MarshalJSON() ([]byte, error) {
	return json.Marshal(ft.String())
}

type FileInfo struct {
	Type  FileType    `json:"type"`
	Inode uint64      `json:"inode"`
	Mode  os.FileMode `json:"mode"`
	Size  uint64      `json:"size"`
	Uid   uint32      `json:"uid"`
	Gid   uint32      `json:"gid"`
	Atime time.Time   `json:"atime"`
	Mtime time.Time   `json:"mtime"`
	Ctime time.Time   `json:"ctime"`
}

type FileCreate struct {
	Pids              PidInfo  `json:"pids"`
	Finfo             FileInfo `json:"file_info"`
	MountNs           uint32   `json:"mount_ns"`
	Comm              string   `json:"comm"`
	Path              string   `json:"path"`
	SymlinkTargetPath string   `json:"symlink_target_path"`
}

func (e *FileCreate) Unmarshal(r *bytes.Reader) error {
	if err := binary.Read(r, endian.Native, &e.Pids); err != nil {
		return fmt.Errorf("read pids: %v", err)
	}

	fi, err := readFileInfo(r)
	if err != nil {
		return fmt.Errorf("read file info: %v", err)
	}
	e.Finfo = fi

	if err := binary.Read(r, endian.Native, &e.MountNs); err != nil {
		return fmt.Errorf("read mount namespace: %v", err)
	}

	comm, err := readTaskComm(r)
	if err != nil {
		return err
	}
	e.Comm = comm

	vlMap, err := varlen.DeserializeVarlenFields(r)
	if err != nil {
		return fmt.Errorf("deserialize varlen fields: %v", err)
	}
	if val, ok := vlMap[varlen.Path]; ok {
		e.Path = val.(string)
	}
	if val, ok := vlMap[varlen.SymlinkTargetPath]; ok {
		e.SymlinkTargetPath = val.(string)
	}

	return nil
}

type FileDelete struct {
	Pids              PidInfo  `json:"pids"`
	Finfo             FileInfo `json:"file_info"`
	MountNs           uint32   `json:"mount_ns"`
	Comm              string   `json:"comm"`
	Path              string   `json:"path"`
	SymlinkTargetPath string   `json:"symlink_target_path"`
}

func (e *FileDelete) Unmarshal(r *bytes.Reader) error {
	if err := binary.Read(r, endian.Native, &e.Pids); err != nil {
		return fmt.Errorf("read pids: %v", err)
	}

	fi, err := readFileInfo(r)
	if err != nil {
		return fmt.Errorf("read file info: %v", err)
	}
	e.Finfo = fi

	if err := binary.Read(r, endian.Native, &e.MountNs); err != nil {
		return fmt.Errorf("read mount namespace: %v", err)
	}

	comm, err := readTaskComm(r)
	if err != nil {
		return err
	}
	e.Comm = comm

	vlMap, err := varlen.DeserializeVarlenFields(r)
	if err != nil {
		return fmt.Errorf("deserialize varlen fields: %v", err)
	}
	if val, ok := vlMap[varlen.Path]; ok {
		e.Path = val.(string)
	}
	if val, ok := vlMap[varlen.SymlinkTargetPath]; ok {
		e.SymlinkTargetPath = val.(string)
	}

	return nil
}

type FileRename struct {
	Pids              PidInfo  `json:"pids"`
	Finfo             FileInfo `json:"file_info"`
	MountNs           uint32   `json:"mount_ns"`
	Comm              string   `json:"comm"`
	OldPath           string   `json:"old_path"`
	NewPath           string   `json:"new_path"`
	SymlinkTargetPath string   `json:"symlink_target_path"`
}

func (e *FileRename) Unmarshal(r *bytes.Reader) error {
	if err := binary.Read(r, endian.Native, &e.Pids); err != nil {
		return fmt.Errorf("read pids: %v", err)
	}

	fi, err := readFileInfo(r)
	if err != nil {
		return fmt.Errorf("read file info: %v", err)
	}
	e.Finfo = fi

	if err := binary.Read(r, endian.Native, &e.MountNs); err != nil {
		return fmt.Errorf("read mount namespace: %v", err)
	}

	comm, err := readTaskComm(r)
	if err != nil {
		return err
	}
	e.Comm = comm

	vlMap, err := varlen.DeserializeVarlenFields(r)
	if err != nil {
		return fmt.Errorf("deserialize varlen fields: %v", err)
	}
	if val, ok := vlMap[varlen.OldPath]; ok {
		e.OldPath = val.(string)
	}
	if val, ok := vlMap[varlen.NewPath]; ok {
		e.NewPath = val.(string)
	}
	if val, ok := vlMap[varlen.SymlinkTargetPath]; ok {
		e.SymlinkTargetPath = val.(string)
	}

	return nil
}

type Transport uint32

const (
	TransportTCP Transport = iota + 1 // TCP
)

func (t Transport) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

type Family uint32

const (
	AFInet  Family = iota + 1 // Inet
	AFInet6                   // Inet6
)

func (f Family) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.String())
}

type NetInfo struct {
	Transport          Transport  `json:"transport"`
	Family             Family     `json:"family"`
	SourceAddress      netip.Addr `json:"source_address"`
	DestinationAddress netip.Addr `json:"destination_address"`
	SourcePort         uint16     `json:"source_port"`
	DestinationPort    uint16     `json:"destination_port"`
	NetNs              uint32     `json:"net_ns"`
	BytesSent          uint64     `json:"bytes_sent"`
	BytesReceived      uint64     `json:"bytes_received"`
}

type NetEvent struct {
	Pids PidInfo `json:"pids"`
	Net  NetInfo `json:"net"`
	Comm string  `json:"comm"`
}

func (e *NetEvent) Unmarshal(r *bytes.Reader) error {
	if err := binary.Read(r, endian.Native, &e.Pids); err != nil {
		return fmt.Errorf("read pids: %v", err)
	}

	ni, err := readNetInfo(r)
	if err != nil {
		return fmt.Errorf("read net info: %v", err)
	}
	e.Net = ni

	comm, err := readTaskComm(r)
	if err != nil {
		return err
	}
	e.Comm = comm

	return nil
}

func NewEvent(raw []byte) (*Event, error) {
	var (
		err error
		ev  Event
		r   = bytes.NewReader(raw)
	)

	if err := readHeader(r, &ev); err != nil {
		return nil, fmt.Errorf("read event header: %v", err)
	}

	switch ev.Header.Type {
	case EventTypeProcessFork:
		err = readBody(r, &ProcessFork{}, &ev)
	case EventTypeProcessExec:
		err = readBody(r, &ProcessExec{}, &ev)
	case EventTypeProcessExit:
		err = readBody(r, &ProcessExit{}, &ev)
	case EventTypeProcessSetsid:
		err = readBody(r, &ProcessSetsid{}, &ev)
	case EventTypeProcessSetuid:
		err = readBody(r, &ProcessSetuid{}, &ev)
	case EventTypeProcessSetgid:
		err = readBody(r, &ProcessSetgid{}, &ev)
	case EventTypeProcessTTYWrite:
		err = readBody(r, &ProcessTTYWrite{}, &ev)
	case EventTypeFileDelete:
		err = readBody(r, &FileDelete{}, &ev)
	case EventTypeFileCreate:
		err = readBody(r, &FileCreate{}, &ev)
	case EventTypeFileRename:
		err = readBody(r, &FileRename{}, &ev)
	case EventTypeNetworkConnectionAccepted, EventTypeNetworkConnectionAttempted, EventTypeNetworkConnectionClosed:
		err = readBody(r, &NetEvent{}, &ev)
	default:
		return nil, fmt.Errorf("unknown event type %d", ev.Header.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("read event body: %v", err)
	}

	return &ev, nil
}

func readHeader(r *bytes.Reader, ev *Event) error {
	var h Header

	if err := binary.Read(r, endian.Native, &h.NsSinceBoot); err != nil {
		return fmt.Errorf("read ns since boot: %v", err)
	}
	if err := binary.Read(r, endian.Native, &h.Type); err != nil {
		return fmt.Errorf("read type: %v", err)
	}
	h.Time = time.Now()
	ev.Header = h

	return nil
}

func readBody(r *bytes.Reader, e EventUnmarshaler, ev *Event) error {
	if err := e.Unmarshal(r); err != nil {
		return fmt.Errorf("unmarshal: %v", err)
	}
	ev.Body = e
	return nil
}

func readTaskComm(r *bytes.Reader) (string, error) {
	var buf [TaskCommLen]byte
	if err := binary.Read(r, endian.Native, &buf); err != nil {
		return "", fmt.Errorf("read comm: %v", err)
	}
	return unix.ByteSliceToString(buf[:]), nil
}

func readNetInfo(r *bytes.Reader) (NetInfo, error) {
	var ni NetInfo

	if err := binary.Read(r, endian.Native, &ni.Transport); err != nil {
		return ni, fmt.Errorf("read transport: %v", err)
	}
	if err := binary.Read(r, endian.Native, &ni.Family); err != nil {
		return ni, fmt.Errorf("read family: %v", err)
	}

	var saddr [16]byte
	if err := binary.Read(r, endian.Native, &saddr); err != nil {
		return ni, fmt.Errorf("read saddr/6: %v", err)
	}
	ni.SourceAddress = netip.AddrFrom16(saddr)

	var daddr [16]byte
	if err := binary.Read(r, endian.Native, &daddr); err != nil {
		return ni, fmt.Errorf("read daddr/6: %v", err)
	}
	ni.DestinationAddress = netip.AddrFrom16(daddr)

	if err := binary.Read(r, endian.Native, &ni.SourcePort); err != nil {
		return ni, fmt.Errorf("read sport: %v", err)
	}
	if err := binary.Read(r, endian.Native, &ni.DestinationPort); err != nil {
		return ni, fmt.Errorf("read dport: %v", err)
	}
	if err := binary.Read(r, endian.Native, &ni.NetNs); err != nil {
		return ni, fmt.Errorf("read net ns: %v", err)
	}
	if err := binary.Read(r, endian.Native, &ni.BytesSent); err != nil {
		return ni, fmt.Errorf("read bytes sent: %v", err)
	}
	if err := binary.Read(r, endian.Native, &ni.BytesReceived); err != nil {
		return ni, fmt.Errorf("read bytes received: %v", err)
	}

	return ni, nil
}

func readFileInfo(r *bytes.Reader) (FileInfo, error) {
	var fi FileInfo

	if err := binary.Read(r, endian.Native, &fi.Type); err != nil {
		return fi, fmt.Errorf("read type: %v", err)
	}
	if err := binary.Read(r, endian.Native, &fi.Inode); err != nil {
		return fi, fmt.Errorf("read inode: %v", err)
	}

	var m uint16
	if err := binary.Read(r, endian.Native, &m); err != nil {
		return fi, fmt.Errorf("read mode: %v", err)
	}
	fi.Mode = os.FileMode(m)

	if err := binary.Read(r, endian.Native, &fi.Size); err != nil {
		return fi, fmt.Errorf("read size: %v", err)
	}
	if err := binary.Read(r, endian.Native, &fi.Uid); err != nil {
		return fi, fmt.Errorf("read uid: %v", err)
	}
	if err := binary.Read(r, endian.Native, &fi.Gid); err != nil {
		return fi, fmt.Errorf("read gid: %v", err)
	}

	var ts uint64

	if err := binary.Read(r, endian.Native, &ts); err != nil {
		return fi, fmt.Errorf("read atime: %v", err)
	}
	fi.Atime = time.Unix(0, int64(ts))

	if err := binary.Read(r, endian.Native, &ts); err != nil {
		return fi, fmt.Errorf("read mtime: %v", err)
	}
	fi.Mtime = time.Unix(0, int64(ts))

	if err := binary.Read(r, endian.Native, &ts); err != nil {
		return fi, fmt.Errorf("read ctime: %v", err)
	}
	fi.Ctime = time.Unix(0, int64(ts))

	return fi, nil
}
