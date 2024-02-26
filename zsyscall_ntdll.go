package xwindows

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

/*
void RtlCopyMemory(
	void*       Destination,
	const void* Source,
	size_t      Length
	);
*/

func RtlCopyMemory(address uintptr, source uintptr, length uintptr) (err error) {
	r1, _, e1 := syscall.SyscallN(procRtlCopyMemory.Addr(), address, source, length)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
The RtlCopyBytes routine copies the specified number of bytes from a source memory block to a destination memory block.

VOID RtlCopyBytes(
	_Out_       PVOID  Destination,
	_In_  const VOID   *Source,
	_In_        SIZE_T Length
	);
*/

func RtlCopyBytes(address uintptr, source uintptr, length uintptr) (err error) {
	r1, _, e1 := syscall.SyscallN(procRtlCopyBytes.Addr(), address, source, length)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
NTSTATUS
NtQueueApcThreadEx(
	IN HANDLE ThreadHandle,
	IN USER_APC_OPTION UserApcOption,
	IN PPS_APC_ROUTINE ApcRoutine,
	IN PVOID SystemArgument1 OPTIONAL,
	IN PVOID SystemArgument2 OPTIONAL,
	IN PVOID SystemArgument3 OPTIONAL
	);
*/

func NtQueueApcThreadEx(threadHandle uintptr, userApcOption uintptr, apcRoutine uintptr, args ...uintptr) (err error) {
	r1, _, e1 := syscall.SyscallN(procNtQueueApcThreadEx.Addr(), threadHandle, userApcOption, apcRoutine, uintptr(len(args)), uintptr(unsafe.Pointer(&args[0])))
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
https://gist.github.com/TheWover/b2b2e427d3a81659942f4e8b9a978dc3

static extern IntPtr EtwpCreateEtwThread(
	IntPtr lpStartAddress,
	IntPtr lpParameter
	);
*/

func EtwpCreateEtwThread(lpStartAddress uintptr, lpParameter uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procEtwpCreateEtwThread.Addr(), lpStartAddress, lpParameter)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
The RtlEthernetStringToAddress function converts a string representation of an Ethernet MAC address to a binary format of the Ethernet address.

NTSYSAPI NTSTATUS RtlEthernetStringToAddressA(
	[in]  PCSTR    S,
	[out] PCSTR    *Terminator,
	[out] DL_EUI48 *Addr
	);

If the function succeeds, the return value is STATUS_SUCCESS
*/

func RtlEthernetStringToAddressA(s uintptr, terminator uintptr, addr uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procRtlEthernetStringToAddressA.Addr(), s, terminator, addr)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
The RtlEthernetAddressToString function converts a binary Ethernet address to a string representation of the Ethernet MAC address.

NTSYSAPI PSTR RtlEthernetAddressToStringA(
	[in]  const DL_EUI48 *Addr,
	[out] PSTR           S
	);

A pointer to the NULL character inserted at the end of the string representation of the Ethernet MAC address. This can be used by the caller to easily append more information to the string.
*/

func RtlEthernetAddressToStringA(addr uintptr, s uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procRtlEthernetAddressToStringA.Addr(), addr, s)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
The RtlIpv4StringToAddress function converts a string representation of an IPv4 address to a binary IPv4 address.

NTSYSAPI NTSTATUS RtlIpv4StringToAddressA(
	[in]  PCSTR   S,
	[in]  BOOLEAN Strict,
	[out] PCSTR   *Terminator,
	[out] in_addr *Addr
	);

If the function succeeds, the return value is STATUS_SUCCESS.
*/

func RtlIpv4StringToAddressA(s uintptr, strict uintptr, terminator uintptr, addr uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procRtlIpv4StringToAddressA.Addr(), s, strict, terminator, addr)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
The RtlIpv4AddressToString function converts an IPv4 address to a string in Internet standard dotted-decimal format.

NTSYSAPI PSTR RtlIpv4AddressToStringA(
	[in]  const in_addr *Addr,
	[out] PSTR          S
	);

A pointer to the NULL character inserted at the end of the string representation of the IPv4 address. This can be used by the caller to easily append more information to the string.
*/

func RtlIpv4AddressToStringA(addr uintptr, s uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procRtlIpv4AddressToStringA.Addr(), addr, s)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
The NtAllocateVirtualMemory routine reserves, commits, or both, a region of pages within the user-mode virtual address space of a specified process.

__kernel_entry NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
	[in]      HANDLE    ProcessHandle,
	[in, out] PVOID     *BaseAddress,
	[in]      ULONG_PTR ZeroBits,
	[in, out] PSIZE_T   RegionSize,
	[in]      ULONG     AllocationType,
	[in]      ULONG     Protect
	);

NtAllocateVirtualMemory returns either STATUS_SUCCESS or an error status code
*/

func NtAllocateVirtualMemory(processHandle windows.Handle, baseAddress uintptr, zeroBits uintptr, regionSize uintptr, allocationType uintptr, protect uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procNtAllocateVirtualMemory.Addr(), uintptr(processHandle), baseAddress, zeroBits, regionSize, allocationType, protect)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
NtWriteVirtualMemory is similar to WINAPI WriteProcessMemory.

NTSYSAPI
NTSTATUS
NTAPI
NtWriteVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL
	);
*/

func NtWriteVirtualMemory(processHandle windows.Handle, baseAddress uintptr, buffer uintptr, numberOfBytesToWrite uintptr, numberOfBytesWritten uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procNtWriteVirtualMemory.Addr(), uintptr(processHandle), baseAddress, buffer, numberOfBytesToWrite, numberOfBytesWritten)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Writes a basic event to a session.

ULONG
EVNTAPI
EtwEventWrite(

	__in REGHANDLE RegHandle,
	__in PCEVENT_DESCRIPTOR EventDescriptor,
	__in ULONG UserDataCount,
	__in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
	);

Return value
A Win32 error code.
*/

func EtwEventWrite(regHandle windows.Handle, eventDescriptor uintptr, userDataCount uintptr, userData uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procEtwEventWrite.Addr(), uintptr(regHandle), eventDescriptor, userDataCount, userData)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Writes a full event to a session.

ULONG
EVNTAPI
EtwEventWriteFull(
	__in REGHANDLE RegHandle,
	__in PCEVENT_DESCRIPTOR EventDescriptor,
	__in USHORT EventProperty,
	__in_opt LPCGUID ActivityId,
	__in_opt LPCGUID RelatedActivityId,
	__in ULONG UserDataCount,
	__in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
	);

A Win32 error code.
*/

func EtwEventWriteFull(regHandle windows.Handle, eventDescriptor uintptr, eventProperty uintptr, activityId uintptr, relatedActivityId uintptr, userDataCount uintptr, userData uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procEtwEventWriteFull.Addr(), uintptr(regHandle), eventDescriptor, eventProperty, activityId, relatedActivityId, userDataCount, userData)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
ULONG
EtwEventWriteEx (
	REGHANDLE RegHandle,
	EVENT_DESCRIPTOR const *EventDescriptor,
	ULONG64 Filter,
	ULONG Flags,
	GUID const *ActivityId,
	GUID const *RelatedActivityId,
	ULONG UserDataCount,
	EVENT_DATA_DESCRIPTOR *UserData);

The function returns zero for success, else a Win32 error code.

Link: https://www.geoffchappell.com/studies/windows/win32/ntdll/api/etw/evntapi/writeex.htm
*/

func EtwEventWriteEx(regHandle windows.Handle, eventDescriptor uintptr, filter uintptr, flags uintptr, activityId uintptr, relatedActivityId uintptr, userDataCount uintptr, userData uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procEtwEventWriteEx.Addr(), uintptr(regHandle), eventDescriptor, filter, flags, activityId, relatedActivityId, userDataCount, userData)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
NTSYSAPI
ULONG
NTAPI
EtwEventWriteString(
	_In_ REGHANDLE RegHandle,
	_In_ UCHAR Level,
	_In_ ULONGLONG Keyword,
	_In_ PCWSTR String
	);
*/

func EtwEventWriteString(regHandle windows.Handle, level uintptr, keyword uintptr, string uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procEtwEventWriteString.Addr(), uintptr(regHandle), level, keyword, string)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
ULONG
	EtwEventWriteTransfer (
	REGHANDLE RegHandle,
	EVENT_DESCRIPTOR const *EventDescriptor,
	GUID const *ActivityId,
	GUID const *RelatedActivityId,
	ULONG UserDataCount,
	EVENT_DATA_DESCRIPTOR *UserData);

The function returns zero for success, else a Win32 error code.
*/

func EtwEventWriteTransfer(regHandle windows.Handle, eventDescriptor uintptr, activityId uintptr, relatedActivityId uintptr, userDataCount uintptr, userData uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procEtwEventWriteTransfer.Addr(), uintptr(regHandle), eventDescriptor, activityId, relatedActivityId, userDataCount, userData)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Retrieves information about the specified thread.

__kernel_entry NTSTATUS NtQueryInformationThread(
	[in]            HANDLE          ThreadHandle,
	[in]            THREADINFOCLASS ThreadInformationClass,
	[in, out]       PVOID           ThreadInformation,
	[in]            ULONG           ThreadInformationLength,
	[out, optional] PULONG          ReturnLength
	);

Returns an NTSTATUS success or error code.

Link: https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationthread
*/

func NtQueryInformationThread(threadHandle windows.Handle, threadInformationClass uintptr, threadInformation uintptr, threadInformationLength uintptr, returnLength uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procNtQueryInformationThread.Addr(), uintptr(threadHandle), threadInformationClass, threadInformation, threadInformationLength, returnLength)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}
