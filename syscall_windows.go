package xwindows

import (
	"syscall"

	"golang.org/x/sys/windows"
)

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
	return e
}

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	modntdll    = windows.NewLazySystemDLL("ntdll.dll")
	modrpcrt4   = windows.NewLazySystemDLL("Rpcrt4.dll")
	modactiveds = windows.NewLazySystemDLL("Activeds.dll")
	modpsapi    = windows.NewLazySystemDLL("psapi.dll")
	moddbghelp  = windows.NewLazySystemDLL("dbghelp.dll")
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")

	// kernel32
	procVirtualAlloc             = modkernel32.NewProc("VirtualAlloc")
	procVirtualProtect           = modkernel32.NewProc("VirtualProtect")
	procVirtualProtectEx         = modkernel32.NewProc("VirtualProtectEx")
	procVirtualAllocEx           = modkernel32.NewProc("VirtualAllocEx")
	procCreateRemoteThreadEx     = modkernel32.NewProc("CreateRemoteThreadEx")
	procConvertThreadToFiber     = modkernel32.NewProc("ConvertThreadToFiber")
	procCreateFiber              = modkernel32.NewProc("CreateFiber")
	procSwitchToFiber            = modkernel32.NewProc("SwitchToFiber")
	procGetCurrentThread         = modkernel32.NewProc("GetCurrentThread")
	procWaitForSingleObject      = modkernel32.NewProc("WaitForSingleObject")
	procCreateThread             = modkernel32.NewProc("CreateThread")
	procOpenProcess              = modkernel32.NewProc("OpenProcess")
	procWriteProcessMemory       = modkernel32.NewProc("WriteProcessMemory")
	procCloseHandle              = modkernel32.NewProc("CloseHandle")
	procHeapCreate               = modkernel32.NewProc("HeapCreate")
	procGetCurrentProcess        = modkernel32.NewProc("GetCurrentProcess")
	procRtlMoveMemory            = modkernel32.NewProc("RtlMoveMemory")
	procEnumSystemLocalesW       = modkernel32.NewProc("EnumSystemLocalesW")
	procEnumSystemLocalesEx      = modkernel32.NewProc("EnumSystemLocalesEx")
	procTerminateThread          = modkernel32.NewProc("TerminateThread")
	procReadProcessMemory        = modkernel32.NewProc("ReadProcessMemory")
	procCreateToolhelp32Snapshot = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First            = modkernel32.NewProc("Thread32First")
	procOpenThread               = modkernel32.NewProc("OpenThread")
	procQueueUserAPC             = modkernel32.NewProc("QueueUserAPC")
	// SandBox
	procGetTickCount                       = modkernel32.NewProc("GetTickCount")
	procGetPhysicallyInstalledSystemMemory = modkernel32.NewProc("GetPhysicallyInstalledSystemMemory")

	// ntdll
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

	// Rpcrt4
	procUuidFromStringA = modrpcrt4.NewProc("UuidFromStringA")

	// Activeds
	procAllocADsMem          = modactiveds.NewProc("AllocADsMem")
	procFreeADsMem           = modadvapi32.NewProc("FreeADsMem")
	procIQueryTagInformation = modadvapi32.NewProc("I_QueryTagInformation")

	// psapi
	procEnumPageFilesW = modpsapi.NewProc("EnumPageFilesW")

	// dbghelp
	procEnumerateLoadedModules = moddbghelp.NewProc("EnumerateLoadedModules")
)
