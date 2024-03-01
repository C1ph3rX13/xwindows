package xwindows

import (
	"golang.org/x/sys/windows"
)

const (
	PROCESS_ALL_ACCESS = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFF
	STATUS_SUCCESS     = 0x00000000
)

type ThreadEntry32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

/* EtwEventWrite Funcs */

type EVENT_DESCRIPTOR struct {
	Id      uint16
	Version byte
	Channel byte
	Level   byte
	Opcode  byte
	Task    uint16
	Keyword uint64
}

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

type EVENT_DATA_DESCRIPTOR struct {
	ptr      uintptr
	size     uint32
	reserved uint32
}

/* EtwEventWrite Funcs */

type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            windows.Handle
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type NTSTATUS uintptr
