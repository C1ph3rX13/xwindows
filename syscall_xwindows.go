package xwindows

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var _ unsafe.Pointer

// Do the interface allocations only once for common
// Errno values.
const (
	errnoERROR_IO_PENDING = 997
)

var (
	errERROR_IO_PENDING error = syscall.Errno(errnoERROR_IO_PENDING)
	errERROR_EINVAL     error = syscall.EINVAL
)

// errnoErr returns common boxed Errno values, to prevent
// allocations at runtime.
func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return errERROR_EINVAL
	case errnoERROR_IO_PENDING:
		return errERROR_IO_PENDING
	}
	// TODO: add more here, after collecting data on the common
	// error values see on Windows. (perhaps when running
	// all.bat?)
	return e
}

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modntdll    = windows.NewLazySystemDLL("ntdll.dll")
	modrpcrt4   = windows.NewLazySystemDLL("Rpcrt4.dll")
	modactiveds = windows.NewLazySystemDLL("Activeds.dll")
	modpsapi    = windows.NewLazySystemDLL("psapi.dll")
	moddbghelp  = windows.NewLazySystemDLL("dbghelp.dll")
	modadvapi32 = windows.NewLazySystemDLL("Advapi32.dll")
	moduser32   = windows.NewLazySystemDLL("user32.dll")
	modwinmm    = windows.NewLazySystemDLL("Winmm.dll")
)

// kernel32.dll
var (
	procVirtualAlloc               = modkernel32.NewProc("VirtualAlloc")
	procVirtualProtect             = modkernel32.NewProc("VirtualProtect")
	procVirtualProtectEx           = modkernel32.NewProc("VirtualProtectEx")
	procVirtualAllocEx             = modkernel32.NewProc("VirtualAllocEx")
	procCreateRemoteThreadEx       = modkernel32.NewProc("CreateRemoteThreadEx")
	procConvertThreadToFiber       = modkernel32.NewProc("ConvertThreadToFiber")
	procCreateFiber                = modkernel32.NewProc("CreateFiber")
	procSwitchToFiber              = modkernel32.NewProc("SwitchToFiber")
	procGetCurrentThread           = modkernel32.NewProc("GetCurrentThread")
	procWaitForSingleObject        = modkernel32.NewProc("WaitForSingleObject")
	procCreateThread               = modkernel32.NewProc("CreateThread")
	procOpenProcess                = modkernel32.NewProc("OpenProcess")
	procWriteProcessMemory         = modkernel32.NewProc("WriteProcessMemory")
	procCloseHandle                = modkernel32.NewProc("CloseHandle")
	procHeapCreate                 = modkernel32.NewProc("HeapCreate")
	procGetCurrentProcess          = modkernel32.NewProc("GetCurrentProcess")
	procRtlMoveMemory              = modkernel32.NewProc("RtlMoveMemory")
	procEnumSystemLocalesW         = modkernel32.NewProc("EnumSystemLocalesW")
	procEnumSystemLocalesEx        = modkernel32.NewProc("EnumSystemLocalesEx")
	procTerminateThread            = modkernel32.NewProc("TerminateThread")
	procReadProcessMemory          = modkernel32.NewProc("ReadProcessMemory")
	procCreateToolhelp32Snapshot   = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First              = modkernel32.NewProc("Thread32First")
	procOpenThread                 = modkernel32.NewProc("OpenThread")
	procQueueUserAPC               = modkernel32.NewProc("QueueUserAPC")
	procCreateRemoteThread         = modkernel32.NewProc("CreateRemoteThread")
	procLoadLibraryA               = modkernel32.NewProc("LoadLibraryA")
	procResumeThread               = modkernel32.NewProc("ResumeThread")
	procGetThreadContext           = modkernel32.NewProc("GetThreadContext")
	procSetThreadContext           = modkernel32.NewProc("SetThreadContext")
	procCreateProcessA             = modkernel32.NewProc("CreateProcessA")
	procSuspendThread              = modkernel32.NewProc("SuspendThread")
	procLoadLibraryW               = modkernel32.NewProc("LoadLibraryW")
	procBeep                       = modkernel32.NewProc("Beep")
	procSetFileInformationByHandle = modkernel32.NewProc("SetFileInformationByHandle")
	procGetProcAddress             = modkernel32.NewProc("GetProcAddress")
	procGetConsoleWindow           = modkernel32.NewProc("GetConsoleWindow")
	procCreateProcessW             = modkernel32.NewProc("CreateProcessW")
	procEnumTimeFormatsA           = modkernel32.NewProc("EnumTimeFormatsA")
	procEnumSystemLocalesA         = modkernel32.NewProc("EnumSystemLocalesA")
	// SandBox
	procGetTickCount                       = modkernel32.NewProc("GetTickCount")
	procGetPhysicallyInstalledSystemMemory = modkernel32.NewProc("GetPhysicallyInstalledSystemMemory")
	procSleepEx                            = modkernel32.NewProc("SleepEx")
)

// ntdll.dll
var (
	procRtlCopyMemory               = modntdll.NewProc("RtlCopyMemory")
	procRtlCopyBytes                = modntdll.NewProc("RtlCopyBytes")
	procNtQueueApcThreadEx          = modntdll.NewProc("NtQueueApcThreadEx")
	procEtwpCreateEtwThread         = modntdll.NewProc("EtwpCreateEtwThread")
	procRtlEthernetStringToAddressA = modntdll.NewProc("RtlEthernetStringToAddressA")
	procRtlEthernetAddressToStringA = modntdll.NewProc("RtlEthernetAddressToStringA")
	procRtlIpv4StringToAddressA     = modntdll.NewProc("RtlIpv4StringToAddressA")
	procRtlIpv4AddressToStringA     = modntdll.NewProc("RtlIpv4AddressToStringA")
	procNtAllocateVirtualMemory     = modntdll.NewProc("NtAllocateVirtualMemory")
	procNtWriteVirtualMemory        = modntdll.NewProc("NtWriteVirtualMemory")
	procEtwEventWrite               = modntdll.NewProc("EtwEventWrite")
	procEtwEventWriteEx             = modntdll.NewProc("EtwEventWriteEx")
	procEtwEventWriteFull           = modntdll.NewProc("EtwEventWriteFull")
	procEtwEventWriteString         = modntdll.NewProc("EtwEventWriteString")
	procEtwEventWriteTransfer       = modntdll.NewProc("EtwEventWriteTransfer")
	procNtQueryInformationThread    = modntdll.NewProc("NtQueryInformationThread")
	procNtCreateSection             = modntdll.NewProc("NtCreateSection")
	procNtUnmapViewOfSection        = modntdll.NewProc("NtUnmapViewOfSection")
	procNtQueryInformationProcess   = modntdll.NewProc("NtQueryInformationProcess")
	procNtDelayExecution            = modntdll.NewProc("NtDelayExecution")
)

// Rpcrt4
var (
	procUuidFromStringA = modrpcrt4.NewProc("UuidFromStringA")
)

// Activeds.dll
var (
	procAllocADsMem   = modactiveds.NewProc("AllocADsMem")
	procFreeADsMem    = modactiveds.NewProc("FreeADsMem")
	procReallocADsMem = modactiveds.NewProc("ReallocADsMem")
)

// psapi.dll
var (
	procEnumPageFilesW = modpsapi.NewProc("EnumPageFilesW")
)

// dbghelp.dll
var (
	procEnumerateLoadedModules = moddbghelp.NewProc("EnumerateLoadedModules")
)

// Advapi32.dll
var (
	procIQueryTagInformation = modadvapi32.NewProc("I_QueryTagInformation")
	procRegDeleteTreeA       = modadvapi32.NewProc("RegDeleteTreeA")
)

// user32.dll
var (
	procShowWindow         = moduser32.NewProc("ShowWindow")
	procEnumChildWindows   = moduser32.NewProc("EnumChildWindows")
	procEnumWindows        = moduser32.NewProc("EnumWindows")
	procEnumThreadWindows  = moduser32.NewProc("EnumThreadWindows")
	procEnumDesktopWindows = moduser32.NewProc("EnumDesktopWindows")
)

// Winmm.dll
var (
	procTimeGetTime = modwinmm.NewProc("timeGetTime")
)
