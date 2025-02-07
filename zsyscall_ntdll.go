package xwindows

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

/*
RtlCopyMemory 例程将源内存块的内容复制到目标内存块

void RtlCopyMemory(

	void*       Destination,
	const void* Source,
	size_t      Length
	);

无返回值

Link: https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopymemory
*/
func RtlCopyMemory(address unsafe.Pointer, source unsafe.Pointer, length uintptr) (err error) {
	_, _, e1 := syscall.SyscallN(
		procRtlCopyMemory.Addr(),
		uintptr(address), // 指向要将字节复制到的目标内存块的指针
		uintptr(source),  // 指向要从中复制字节的源内存块的指针
		length,           // 要从源复制到目标的字节数
	)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

/*
RtlCopyBytes
The RtlCopyBytes routine copies the specified number of bytes from a source memory block to a destination memory block.

VOID RtlCopyBytes(

	  _Out_       PVOID  Destination,
	  _In_  const VOID   *Source,
	  _In_        SIZE_T Length
	);

# Return value None

Link: https://learn.microsoft.com/en-us/previous-versions/windows/hardware/kernel/ff561806(v=vs.85)
*/
func RtlCopyBytes(address uintptr, source *byte, length uintptr) (err error) {
	r1, _, e1 := syscall.SyscallN(
		procRtlCopyBytes.Addr(),
		address,                         // A pointer to the destination memory to copy the bytes to.
		uintptr(unsafe.Pointer(source)), // A pointer to the source memory to copy the bytes from.
		length,                          // The number of bytes to copy from the source to the destination.
	)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
NtQueueApcThreadEx
Each time NtQueueApcThread is called, a new KAPC object is allocated in kernel mode (from the kernel pool) to store the data about the APC object. Let’s say there’s a component that queues a lot of APCs, one after another. This can have performance implications because a lot of non-paged memory is used and also allocating memory takes some time.

NTSTATUS
NtQueueApcThreadEx(

	IN HANDLE ThreadHandle,
	IN USER_APC_OPTION UserApcOption,
	IN PPS_APC_ROUTINE ApcRoutine,
	IN PVOID SystemArgument1 OPTIONAL,
	IN PVOID SystemArgument2 OPTIONAL,
	IN PVOID SystemArgument3 OPTIONAL
	);

Link: https://repnz.github.io/posts/apc/user-apc/#ntqueueapcthreadex-reusing-kernel-memory
Gitlab: https://gitlab.com/mjwhitta/runsc/-/blob/v1.3.4/api_windows.go#L157
Github: https://github.com/mjwhitta/win/blob/v0.15.2/api/ntdll_windows.go#L171
*/
func NtQueueApcThreadEx(threadHandle windows.Handle, userApcOption uintptr, apcRoutine uintptr, args ...uintptr) (err error) {
	_, _, e1 := syscall.SyscallN(
		procNtQueueApcThreadEx.Addr(),
		uintptr(threadHandle),
		userApcOption, // 0x1
		apcRoutine,
		uintptr(len(args)),
		uintptr(unsafe.Pointer(&args[0])),
	)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

/*
EtwpCreateEtwThread

static extern IntPtr EtwpCreateEtwThread(

	IntPtr lpStartAddress,
	IntPtr lpParameter
	);

Link: https://gist.github.com/TheWover/b2b2e427d3a81659942f4e8b9a978dc3
*/
func EtwpCreateEtwThread(lpStartAddress uintptr, lpParameter uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procEtwpCreateEtwThread.Addr(),
		lpStartAddress,
		lpParameter,
		0,
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
RtlEthernetStringToAddressA
将以太网 MAC 地址的字符串表示形式转换为以太网地址的二进制格式

NTSYSAPI NTSTATUS RtlEthernetStringToAddressA(

	[in]  PCSTR    S,
	[out] PCSTR    *Terminator,
	[out] DL_EUI48 *Addr
	);

如果函数成功，则返回值 STATUS_SUCCESS。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/ip2string/nf-ip2string-rtlethernetstringtoaddressa
*/
func RtlEthernetStringToAddressA(s uintptr, terminator *byte, addr *byte) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procRtlEthernetStringToAddressA.Addr(),
		s,                                   // 指向缓冲区的指针，该缓冲区包含以 NULL 结尾的以太网 MAC 地址字符串表示形式
		uintptr(unsafe.Pointer(terminator)), // 一个参数，用于接收指向终止转换字符串的字符的指针
		uintptr(unsafe.Pointer(addr)),       // 一个指针，用于存储以太网 MAC 地址的二进制表示形式
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
RtlEthernetAddressToStringA
将二进制以太网地址转换为以太网 MAC 地址的字符串表示形式

NTSYSAPI PSTR RtlEthernetAddressToStringA(

	  [in]  const DL_EUI48 *Addr,
	  [out] PSTR           S
	);

指向插入到以太网 MAC 地址字符串表示形式的末尾的 NULL 字符的指针。 调用方可以使用它轻松地将更多信息追加到字符串。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/ip2string/nf-ip2string-rtlethernetaddresstostringa
*/
func RtlEthernetAddressToStringA(addr *byte, s uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procRtlEthernetAddressToStringA.Addr(),
		uintptr(unsafe.Pointer(addr)),
		s,
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

// RtlIpv4StringToAddressA
/*
RtlIpv4StringToAddressA
将 IPv4 地址的字符串表示形式转换为二进制 IPv4 地址

NTSYSAPI NTSTATUS RtlIpv4StringToAddressA(

	[in]  PCSTR   S,           // 指向包含 IPv4 地址的 NULL终止字符串表示形式的缓冲区的指针
	[in]  BOOLEAN Strict,      // 一个值，该值指示字符串是否必须是以严格四部分点十进制表示法表示的 IPv4 地址
	[out] PCSTR   *Terminator, // 一个参数，该参数接收指向终止转换字符串的字符的指针
	[out] in_addr *Addr        // 一个指针，其中存储 IPv4 地址的二进制表示形式
	);

如果函数成功，则返回值 STATUS_SUCCESS。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/ip2string/nf-ip2string-rtlipv4stringtoaddressa
*/
func RtlIpv4StringToAddressA(s uintptr, strict uintptr, terminator uintptr, addr uintptr) (NTStatus windows.NTStatus, err error) {
	r1, _, e1 := syscall.SyscallN(
		procRtlIpv4StringToAddressA.Addr(),
		s,
		strict,
		terminator,
		addr,
	)
	NTStatus = windows.NTStatus(r1)
	if !errors.Is(NTStatus, windows.STATUS_SUCCESS) {
		err = errnoErr(e1)
	}
	return
}

/*
RtlIpv4StringToAddressExA
将 IPv4 地址和端口号的字符串表示形式转换为二进制 IPv4 地址和端口

NTSYSAPI NTSTATUS RtlIpv4StringToAddressExA(
[in]  PCSTR   AddressString,
[in]  BOOLEAN Strict,
[out] in_addr *Address,
[out] PUSHORT Port
);

如果函数成功，则返回值 STATUS_SUCCESS
如果函数失败，则返回值为 STATUS_INVALID_PARAMETER

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/ip2string/nf-ip2string-rtlipv4stringtoaddressexa
*/
func RtlIpv4StringToAddressExA(s uintptr, strict uintptr, addr uintptr, port uintptr) (NTStatus windows.NTStatus, err error) {
	r1, _, e1 := syscall.SyscallN(
		procRtlIpv4StringToAddressExA.Addr(),
		s,
		strict,
		addr,
		port,
	)
	NTStatus = windows.NTStatus(r1)
	if !errors.Is(NTStatus, windows.STATUS_SUCCESS) {
		err = errnoErr(e1)
	}
	return
}

/*
RtlIpv4AddressToStringA
将 IPv4 地址转换为 Internet 标准点十进制格式的字符串

NTSYSAPI PSTR RtlIpv4AddressToStringA(

	[in]  const in_addr *Addr,
	[out] PSTR          S
	);

指向在 IPv4 地址的字符串表示形式末尾插入的 NULL 字符的指针。 调用方可以使用它轻松将更多信息追加到字符串。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/ip2string/nf-ip2string-rtlipv4addresstostringa
*/
func RtlIpv4AddressToStringA(addr uintptr, s uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procRtlIpv4AddressToStringA.Addr(),
		addr, // 按网络字节顺序排列的 IPv4 地址
		s,    // 指向缓冲区的指针，用于存储 IPv4 地址的 以 NULL 结尾的字符串表示形式
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
NtAllocateVirtualMemory
在指定进程的用户模式虚拟地址空间中保留和/或提交页面区域。

__kernel_entry NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(

	[in]      HANDLE    ProcessHandle,
	[in, out] PVOID     *BaseAddress,
	[in]      ULONG_PTR ZeroBits,
	[in, out] PSIZE_T   RegionSize,
	[in]      ULONG     AllocationType,
	[in]      ULONG     Protect
	);

NtAllocateVirtualMemory returns either STATUS_SUCCESS or an error status code

Link: https://learn.microsoft.com/zh-cn/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory
*/
func NtAllocateVirtualMemory(processHandle windows.Handle, baseAddress *byte, zeroBits uintptr, regionSize uintptr, allocationType uintptr, protect uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procNtAllocateVirtualMemory.Addr(),
		uintptr(processHandle),               // 应为其执行映射的过程的句柄
		uintptr(unsafe.Pointer(baseAddress)), // 指向将接收已分配页区域的基址的变量的指针
		zeroBits,                             // 节视图基址中必须为零的高序地址位数
		regionSize,                           // 指向变量的指针，该变量将接收已分配页区域的实际大小（以字节为单位）
		allocationType,                       // 一个位掩码，其中包含指定要为指定页面区域执行的分配类型的标志
		protect,                              // 包含页面保护标志的位掩码，这些标志指定对已提交页面区域所需的保护
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
NtWriteVirtualMemory is similar to WINAPI WriteProcessMemory.

NTSYSCALLAPI
NTSTATUS
NTAPI
NtWriteVirtualMemory(

	_In_ HANDLE ProcessHandle,
	_In_opt_ PVOID BaseAddress,
	_In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
	_In_ SIZE_T NumberOfBytesToWrite,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
	);

Link: https://ntdoc.m417z.com/ntwritevirtualmemory
Link: https://undocumented-ntinternals.github.io/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html
*/
func NtWriteVirtualMemory(processHandle windows.Handle, baseAddress *byte, buffer *byte, BufferSize uintptr, numberOfBytesWritten *uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procNtWriteVirtualMemory.Addr(),
		uintptr(processHandle),
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(buffer)),
		BufferSize,
		uintptr(unsafe.Pointer(numberOfBytesWritten)),
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
EtwEventWrite 函数及其返回的结构在操作系统内部，并且可能会从一个版本的 Windows 更改为另一个版本。
将基本事件写入会话

ULONG
EVNTAPI
EtwEventWrite(

	__in REGHANDLE RegHandle,
	__in PCEVENT_DESCRIPTOR EventDescriptor,
	__in ULONG UserDataCount,
	__in_ecount_opt(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData
	);

返回值
Win32 错误代码。

Link: https://learn.microsoft.com/zh-cn/windows/win32/devnotes/etweventwrite
*/
func EtwEventWrite(regHandle windows.Handle, eventDescriptor uintptr, userDataCount uint32, userData uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procEtwEventWrite.Addr(),
		uintptr(regHandle),     // 提供程序的 RegHandle
		eventDescriptor,        // 要记录的事件的事件描述符
		uintptr(userDataCount), // 用户数据项数
		userData,               // 指向用户数据项数组的指针
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
EtwEventWriteFull 函数及其返回的结构在操作系统内部，可能会从一个版本的 Windows 更改为另一个版本。
将完整事件写入会话

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

返回值
Win32 错误代码。

Link: https://learn.microsoft.com/zh-cn/windows/win32/devnotes/etweventwritefull
*/
func EtwEventWriteFull(regHandle windows.Handle, eventDescriptor uintptr, eventProperty uintptr, activityId uintptr, relatedActivityId uintptr, userDataCount uint32, userData uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procEtwEventWriteFull.Addr(),
		uintptr(regHandle),     // 提供程序的 RegHandle
		eventDescriptor,        // 要记录的事件的事件描述符
		eventProperty,          // 用户提供的标志
		activityId,             // 活动 ID
		relatedActivityId,      // 相关活动 ID
		uintptr(userDataCount), // 用户数据项的数目
		userData,               // 指向用户数据项数组的指针
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
EtwEventWriteEx

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
func EtwEventWriteEx(regHandle windows.Handle, eventDescriptor uintptr, filter uint64, flags uint32, activityId uintptr, relatedActivityId uintptr, userDataCount uintptr, userData uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procEtwEventWriteEx.Addr(),
		uintptr(regHandle), // 提供程序的 RegHandle
		eventDescriptor,    // 要记录的事件的事件描述符
		uintptr(filter),    // 指定启用事件提供程序但不接收此事件的跟踪会话
		uintptr(flags),     // 允许事件处理的变化
		activityId,         // 活动 ID
		relatedActivityId,  // 将事件标记为与某个其他事件的活动相关
		userDataCount,      // 用户数据项的数目
		userData,           // 指向用户数据项数组的指针
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
EtwEventWriteString forwarded from EventWriteString
TODO: Need documentation, not sure function is correct

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
func EtwEventWriteString(regHandle windows.Handle, level byte, keyword uint64, str *uint16) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procEtwEventWriteString.Addr(),
		uintptr(regHandle),
		uintptr(level),
		uintptr(keyword),
		uintptr(unsafe.Pointer(str)),
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
EtwEventWriteTransfer
TODO: Need documentation, not sure function is correct

ULONG

	EtwEventWriteTransfer (
	REGHANDLE RegHandle,
	EVENT_DESCRIPTOR const *EventDescriptor,
	GUID const *ActivityId,
	GUID const *RelatedActivityId,
	ULONG UserDataCount,
	EVENT_DATA_DESCRIPTOR *UserData
	);

The function returns zero for success, else a Win32 error code.
*/
func EtwEventWriteTransfer(regHandle windows.Handle, eventDescriptor *EVENT_DESCRIPTOR, activityId, relatedActivityId *GUID, userDataCount uint32, userData []*EVENT_DATA_DESCRIPTOR) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procEtwEventWriteTransfer.Addr(),
		uintptr(regHandle),
		uintptr(unsafe.Pointer(eventDescriptor)),
		uintptr(unsafe.Pointer(activityId)),
		uintptr(unsafe.Pointer(relatedActivityId)),
		uintptr(userDataCount),
		uintptr(unsafe.Pointer(&userData[0])),
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
NtQueryInformationThread 在 Windows 的未来版本中可能已更改或不可用。 应用程序应使用本主题中列出的备用函数。
检索有关指定线程的信息。

__kernel_entry NTSTATUS NtQueryInformationThread(

	[in]            HANDLE          ThreadHandle,
	[in]            THREADINFOCLASS ThreadInformationClass,
	[in, out]       PVOID           ThreadInformation,
	[in]            ULONG           ThreadInformationLength,
	[out, optional] PULONG          ReturnLength
	);

返回 NTSTATUS 成功或错误代码。
NTSTATUS 错误代码的形式和意义列在 DDK 中提供的 Ntstatus.h 头文件中，并在 DDK 文档中 Kernel-Mode 驱动程序体系结构/设计指南/驱动程序编程技术/日志记录错误下进行了介绍。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/winternl/nf-winternl-ntqueryinformationthread?redirectedfrom=MSDN
*/
func NtQueryInformationThread(threadHandle windows.Handle, threadInformationClass uintptr, threadInformation uintptr, threadInformationLength uintptr, returnLength uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procNtQueryInformationThread.Addr(),
		uintptr(threadHandle),   // 正在请求哪些信息的线程的句柄
		threadInformationClass,  // 如果此参数是 THREADINFOCLASS 枚举的 ThreadIsIoPending 值，则函数将确定线程是否有任何 I/O 操作挂起
		threadInformation,       // 指向缓冲区的指针，函数在其中写入请求的信息
		threadInformationLength, // ThreadInformation 参数指向的缓冲区大小（以字节为单位）
		returnLength,            // 指向变量的指针，函数在其中返回所请求信息的大小
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
NtCreateSection 例程创建一个节对象**

__kernel_entry NTSYSCALLAPI NTSTATUS NtCreateSection(

	  [out]          PHANDLE            SectionHandle,
	  [in]           ACCESS_MASK        DesiredAccess,
	  [in, optional] POBJECT_ATTRIBUTES ObjectAttributes,
	  [in, optional] PLARGE_INTEGER     MaximumSize,
	  [in]           ULONG              SectionPageProtection,
	  [in]           ULONG              AllocationAttributes,
	  [in, optional] HANDLE             FileHandle
	);

NtCreateSection 在成功时返回STATUS_SUCCESS，或在失败时返回相应的 NTSTATUS 错误代码

link: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatesection
Github: https://github.com/hillu/go-ntdll/blob/f8894bfa00af/section_generated.go#L24
*/
func NtCreateSection(sectionHandle *windows.Handle, desiredAccess uint32, objectAttributes *OBJECT_ATTRIBUTES, maximumSize *int64, sectionPageProtection uint32, allocationAttributes uint32, fileHandle windows.Handle) (err error) {
	_, _, e1 := syscall.SyscallN(procNtCreateSection.Addr(),
		uintptr(unsafe.Pointer(sectionHandle)),    // 指向 HANDLE 变量的指针，该变量接收节对象的句柄
		uintptr(desiredAccess),                    // 指定一个 ACCESS_MASK 值，该值确定对 对象的请求访问权限
		uintptr(unsafe.Pointer(objectAttributes)), // 指向 OBJECT_ATTRIBUTES 结构的指针，该结构指定对象名称和其他属性
		uintptr(unsafe.Pointer(maximumSize)),      // 指定节的最大大小（以字节为单位）
		uintptr(sectionPageProtection),            // 指定要在节中的每个页面上放置的保护
		uintptr(allocationAttributes),             // 指定SEC_XXX 标志的位掩码，用于确定节的分配属性
		uintptr(fileHandle),                       // （可选）指定打开的文件对象的句柄。 如果 FileHandle 的值为 NULL，则分区由分页文件提供支持。 否则，节由指定文件提供支持。
	)
	if e1 != 0 {
		err = errnoErr(e1)
		return
	}
	return
}

/*
NtQueryInformationProcess
检索有关指定进程的信息

__kernel_entry NTSTATUS NtQueryInformationProcess(

	[in]            HANDLE           ProcessHandle,
	[in]            PROCESSINFOCLASS ProcessInformationClass,
	[out]           PVOID            ProcessInformation,
	[in]            ULONG            ProcessInformationLength,
	[out, optional] PULONG           ReturnLength

);

返回值
函数返回 NTSTATUS 成功或错误代码。
NTSTATUS 错误代码的形式和意义列在 DDK 中提供的 Ntstatus.h 头文件中

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
*/
func NtQueryInformationProcess(
	processHandle windows.Handle,
	processInformationClass uint32,
	processInformation unsafe.Pointer,
	processInformationLength uintptr,
	returnLength *uintptr,
) (NTSTATUS uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procNtQueryInformationProcess.Addr(),
		uintptr(processHandle),
		uintptr(processInformationClass),
		uintptr(processInformation),
		processInformationLength,              // 缓冲区大小 (字节)
		uintptr(unsafe.Pointer(returnLength)), // 可选的返回长度
	)
	NTSTATUS = r1
	if NTSTATUS != 0 {
		err = errnoErr(e1)
	}
	return
}

/*
func NtQueryInformationProcess(
	processHandle windows.Handle,
	processInformationClass uint32,
	processInformation unsafe.Pointer,
	processInformationLength uint32,
	returnLength *uint32,
) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procNtQueryInformationProcess.Addr(),
		uintptr(processHandle),
		uintptr(processInformationClass),
		uintptr(processInformation),
		uintptr(processInformationLength),
		uintptr(unsafe.Pointer(returnLength)),
	)
	value = r1
	if value != 0 {
		err = errnoErr(e1)
	}
	return
}
*/

// NtQueryInformationProcessZ 暂代 NtQueryInformationProcess(调用参数错误) 的使用
func NtQueryInformationProcessZ(
	processHandle windows.Handle,
	processInformationClass uintptr,
	processInformation uintptr,
	processInformationLength uintptr,
	returnLength uintptr,
) (value uintptr, err error) {
	r1, _, e1 := procNtQueryInformationProcess.Call(
		uintptr(processHandle),
		processInformationClass,
		processInformation,
		processInformationLength,
		returnLength,
	)
	value = r1
	if value != 0 {
		err = e1
	}
	return
}

/*
NtDelayExecution

NTSYSAPI
NTSTATUS
NTAPI
NtDelayExecution(

	IN BOOLEAN              Alertable,
	IN PLARGE_INTEGER       DelayInterval
	);
*/
func NtDelayExecution(DelayInterval int64) (err error) {
	delay := -(DelayInterval * 1000 * 10000)

	r1, _, e1 := syscall.SyscallN(
		procNtDelayExecution.Addr(),
		uintptr(0),
		uintptr(unsafe.Pointer(&delay)),
	)
	if r1 != 0 {
		err = errnoErr(e1)
	}
	return
}
