package xsyscall

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_xwindows.go syscall_xwindows.go

// Windows api calls kernel32

// Windows api calls ntdll

//sys NtQueryInformationProcess(processHandle windows.Handle, processInformationClass int32, processInformation *byte, processInformationLength uint32, returnLength *uint32) (value uintptr, err error) = ntdll.NtQueryInformationProcess
//sys RtlCopyMemory(address *byte, source *byte, length uintptr) (err error) = ntdll.RtlCopyMemory
//sys RtlCopyBytes(address uintptr, source *byte, length uintptr) (err error) = ntdll.RtlCopyBytes
//sys NtQueueApcThreadEx(threadHandle windows.Handle, userApcOption uintptr, apcRoutine uintptr) (err error) = ntdll.NtQueueApcThreadEx
//sys EtwpCreateEtwThread(lpStartAddress uintptr, lpParameter uintptr) (value uintptr, err error) = ntdll.EtwpCreateEtwThread
//sys RtlEthernetStringToAddressA(s uintptr, terminator *byte, addr *byte) (value uintptr, err error) = ntdll.RtlEthernetStringToAddressA
//sys RtlEthernetAddressToStringA(addr *byte, s uintptr) (value uintptr, err error) = ntdll.RtlEthernetAddressToStringA
//sys RtlIpv4StringToAddressA(s uintptr, strict uintptr, terminator *byte, addr *byte) (value uintptr, err error) = ntdll.RtlIpv4StringToAddressA
//sys RtlIpv4AddressToStringA(addr uintptr, s uintptr) (value uintptr, err error) = ntdll.RtlIpv4AddressToStringA
//sys NtAllocateVirtualMemory(processHandle windows.Handle, baseAddress *byte, zeroBits uintptr, regionSize uintptr, allocationType uintptr, protect uintptr) (value uintptr, err error) = ntdll.NtAllocateVirtualMemory
//sys NtWriteVirtualMemory(processHandle windows.Handle, baseAddress *byte, buffer *byte, BufferSize uintptr, numberOfBytesWritten *uintptr) (value uintptr, err error) = ntdll.NtWriteVirtualMemory
//sys EtwEventWrite(regHandle windows.Handle, eventDescriptor uintptr, userDataCount uint32, userData uintptr) (value uintptr, err error) = ntdll.EtwEventWrite
//sys EtwEventWriteFull(regHandle windows.Handle, eventDescriptor uintptr, eventProperty uintptr, activityId uintptr, relatedActivityId uintptr, userDataCount uint32, userData uintptr) (value uintptr, err error) = ntdll.EtwEventWriteFull
//sys EtwEventWriteEx(regHandle windows.Handle, eventDescriptor uintptr, filter uint64, flags uint32, activityId uintptr, relatedActivityId uintptr, userDataCount uintptr, userData uintptr) (value uintptr, err error) = ntdll.EtwEventWriteEx
