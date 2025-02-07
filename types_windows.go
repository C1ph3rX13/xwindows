package xwindows

import (
	"golang.org/x/sys/windows"
)

const (
	STATUS_SUCCESS     = 0x00000000
	CONTEXT_ALL        = 0x001F
	PROCESS_ALL_ACCESS = windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0xFFF
)

type (
	BOOLEAN          byte
	BOOL             int32
	DWORD            uint32
	DWORD32          uint32
	DWORD64          uint32
	WORD             uint16
	HANDLE           uintptr
	PVOID            uintptr
	PBOOL            uintptr
	LPVOID           uintptr
	SIZE_T           uintptr
	LPCVOID          uintptr
	LPCSTR           uintptr
	LPDWORD          uintptr
	ProcessInfoClass uint32
	ULONG            uintptr
	PULONG           uintptr
	NTSTATUS         int32
	HMODULE          uintptr
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

// XMM_SAVE_AREA32
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
type XMM_SAVE_AREA32 struct {
	ControlWord    uint16
	StatusWord     uint16
	TagWord        byte
	Reserved1      byte
	ErrorOpcode    uint16
	ErrorOffset    uint32
	ErrorSelector  uint16
	Reserved2      uint16
	DataOffset     uint32
	DataSelector   uint16
	Reserved3      uint16
	MxCsr          uint32
	MxCsr_Mask     uint32
	FloatRegisters [8]M128A
	XmmRegisters   [256]byte
	Reserved4      [96]byte
}

// M128A
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
type M128A struct {
	Low  uint64
	High int64
}

// CONTEXT
// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
type CONTEXT struct {
	P1Home uint64
	P2Home uint64
	P3Home uint64
	P4Home uint64
	P5Home uint64
	P6Home uint64

	ContextFlags uint32
	MxCsr        uint32

	SegCs  uint16
	SegDs  uint16
	SegEs  uint16
	SegFs  uint16
	SegGs  uint16
	SegSs  uint16
	EFlags uint32

	Dr0 uint64
	Dr1 uint64
	Dr2 uint64
	Dr3 uint64
	Dr6 uint64
	Dr7 uint64

	Rax uint64
	Rcx uint64
	Rdx uint64
	Rbx uint64
	Rsp uint64
	Rbp uint64
	Rsi uint64
	Rdi uint64
	R8  uint64
	R9  uint64
	R10 uint64
	R11 uint64
	R12 uint64
	R13 uint64
	R14 uint64
	R15 uint64

	Rip uint64

	FltSave XMM_SAVE_AREA32

	VectorRegister [26]M128A
	VectorControl  uint64

	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

/*
type IMAGE_DOS_HEADER struct { // DOS .EXE header

		E_magic    uint16     // Magic number
		E_cblp     uint16     // Bytes on last page of file
		E_cp       uint16     // Pages in file
		E_crlc     uint16     // Relocations
		E_cparhdr  uint16     // Size of header in paragraphs
		E_minalloc uint16     // Minimum extra paragraphs needed
		E_maxalloc uint16     // Maximum extra paragraphs needed
		E_ss       uint16     // Initial (relative) SS value
		E_sp       uint16     // Initial SP value
		E_csum     uint16     // Checksum
		E_ip       uint16     // Initial IP value
		E_cs       uint16     // Initial (relative) CS value
		E_lfarlc   uint16     // File address of relocation table
		E_ovno     uint16     // Overlay number
		E_res      [4]uint16  // Reserved words
		E_oemid    uint16     // OEM identifier (for E_oeminfo)
		E_oeminfo  uint16     // OEM information; E_oemid specific
		E_res2     [10]uint16 // Reserved words
		E_lfanew   uint32     // File address of new exe header
	}
*/
type IMAGE_NT_HEADER struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER
}

/*
	type IMAGE_FILE_HEADER struct {
		Machine              uint16
		NumberOfSections     uint16
		TimeDateStamp        uint32
		PointerToSymbolTable uint32
		NumberOfSymbols      uint32
		SizeOfOptionalHeader uint16
		Characteristics      uint16
	}
*/

type IMAGE_OPTIONAL_HEADER struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

/*
type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}
*/
