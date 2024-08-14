package xwindows

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

/*
VirtualAlloc
保留、提交或更改调用进程的虚拟地址空间中页面区域的状态, 此函数分配的内存会自动初始化为零
若要在另一个进程的地址空间中分配内存，请使用 VirtualAllocEx 函数

LPVOID VirtualAlloc(

	  [in, optional] LPVOID lpAddress,
	  [in]           SIZE_T dwSize,
	  [in]           DWORD  flAllocationType, (MEM_COMMIT | MEM_RESERVE)
	  [in]           DWORD  flProtect         (PAGE_READWRITE or PAGE_EXECUTE_READWRITE)
	);

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
*/
func VirtualAlloc(address uintptr, size uintptr, allocType uint32, protect uint32) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procVirtualAlloc.Addr(), address, size, uintptr(allocType), uintptr(protect), 0, 0)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
VirtualProtect
更改调用进程的虚拟地址空间中已提交页面区域的保护
若要更改任何进程的访问保护，请使用 VirtualProtectEx 函数

BOOL VirtualProtect(

	  [in]  LPVOID lpAddress,
	  [in]  SIZE_T dwSize,
	  [in]  DWORD  flNewProtect,
	  [out] DWORD  lpflOldProtect
	);

如果该函数成功，则返回值为非零值

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
*/
func VirtualProtect(address uintptr, size uintptr, newProtect uint32, oldProtect *uint32) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procVirtualProtect.Addr(),
		address,
		size,
		uintptr(newProtect),
		uintptr(unsafe.Pointer(oldProtect)),
		0,
		0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
VirtualProtectEx
更改指定进程的虚拟地址空间中已提交页面区域的保护

BOOL VirtualProtectEx(

	[in]  HANDLE hProcess,
	[in]  LPVOID lpAddress,
	[in]  SIZE_T dwSize,
	[in]  DWORD  flNewProtect,
	[out] PDWORD lpflOldProtect
	);

如果该函数成功，则返回值为非零值

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex
*/
func VirtualProtectEx(process windows.Handle, address uintptr, size uintptr, newProtect uint32, oldProtect *uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(
		procVirtualProtectEx.Addr(),
		uintptr(process),
		address,
		size,
		uintptr(newProtect),
		uintptr(unsafe.Pointer(oldProtect)),
		0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
VirtualAllocEx
在指定进程的虚拟地址空间中保留、提交或更改内存区域的状态。 函数将它分配的内存初始化为零
若要为物理内存指定 NUMA 节点，请参阅 VirtualAllocExNuma

LPVOID VirtualAllocEx(

	  [in]           HANDLE hProcess,
	  [in, optional] LPVOID lpAddress,
	  [in]           SIZE_T dwSize,
	  [in]           DWORD  flAllocationType,
	  [in]           DWORD  flProtect
	);

如果函数成功，则返回值是已分配页区域的基址
如果函数失败，则返回值为 NULL

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
*/
func VirtualAllocEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, allocType uint32, protect uint32) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procVirtualAllocEx.Addr(),
		uintptr(hProcess),
		lpAddress,
		dwSize,
		uintptr(allocType),
		uintptr(protect),
		0,
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
ConvertThreadToFiber
Converts the current thread into a fiber. You must convert a thread into a fiber before you can schedule other fibers.

LPVOID ConvertThreadToFiber(

	  [in, optional] LPVOID lpParameter
	);

If the function succeeds, the return value is the address of the fiber.

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/winbase/nf-winbase-convertthreadtofiber
*/
func ConvertThreadToFiber(lpParameter uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procConvertThreadToFiber.Addr(),
		lpParameter,
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
CreateFiber
Allocates a fiber object, assigns it a stack, and sets up execution to begin at the specified start address, typically the fiber function. This function does not schedule the fiber.

LPVOID CreateFiber(

	  [in]           SIZE_T                dwStackSize,
	  [in]           LPFIBER_START_ROUTINE lpStartAddress,
	  [in, optional] LPVOID                lpParameter
	);

If the function succeeds, the return value is the address of the fiber.

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/winbase/nf-winbase-createfiber
*/
func CreateFiber(dwStackSize uintptr, lpStartAddress uintptr, lpParameter uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procCreateFiber.Addr(),
		dwStackSize,
		lpStartAddress,
		lpParameter,
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
SwitchToFiber
Schedules a fiber. The function must be called on a fiber.

Void SwitchToFiber(

	[in] LPVOID lpFiber
	);

None return value.

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/winbase/nf-winbase-switchtofiber
*/
func SwitchToFiber(lpFiber uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procSwitchToFiber.Addr(),
		lpFiber,
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
GetCurrentThread
Retrieves a pseudo handle for the calling thread.

HANDLE GetCurrentThread();

The return value is a pseudo handle for the current thread.

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthread
*/
func GetCurrentThread() (handle windows.Handle, err error) {
	r1, _, e1 := syscall.SyscallN(procGetCurrentThread.Addr())
	handle = windows.Handle(r1)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
WaitForSingleObject
Waits until the specified object is in the signaled state or the time-out interval elapses.
To enter an alertable wait state, use the WaitForSingleObjectEx function. To wait for multiple objects, use WaitForMultipleObjects.

DWORD WaitForSingleObject(

	[in] HANDLE hHandle,
	[in] DWORD  dwMilliseconds
	);

If the function succeeds, the return value indicates the event that caused the function to return. It can be one of the following values.

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
*/
func WaitForSingleObject(handle windows.Handle, waitMilliseconds uint32) (event uint32, err error) {
	r1, _, e1 := syscall.SyscallN(
		procWaitForSingleObject.Addr(),
		uintptr(handle),
		uintptr(waitMilliseconds),
		0,
	)
	event = uint32(r1)
	if event == 0xffffffff {
		err = errnoErr(e1)
	}
	return
}

/*
CreateThread
创建在调用进程的虚拟地址空间内执行的线程。
若要创建在另一个进程的虚拟地址空间中运行的线程，请使用 CreateRemoteThread 函数

HANDLE CreateThread(

	[in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	[in]            SIZE_T                  dwStackSize,
	[in]            LPTHREAD_START_ROUTINE  lpStartAddress,
	[in, optional]  __drv_aliasesMem LPVOID lpParameter,
	[in]            DWORD                   dwCreationFlags,
	[out, optional] LPDWORD                 lpThreadId
	);

如果函数成功，则返回值是新线程的句柄
如果函数失败，则返回值为 NULL

type pCreateThread func(lpThreadAttributes *windows.SecurityAttributes, dwStackSize uintptr, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpThreadId *uint32) uintptr

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
*/
func CreateThread(lpThreadAttributes uintptr, dwStackSize uintptr, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpThreadId uintptr) (handle windows.Handle, err error) {
	r1, _, e1 := syscall.SyscallN(
		procCreateThread.Addr(),
		lpThreadAttributes, // 指向 SECURITY_ATTRIBUTES 结构的指针，该结构确定是否可由子进程继承返回的句柄
		dwStackSize,
		lpStartAddress,
		lpParameter,
		uintptr(dwCreationFlags),
		lpThreadId,
	)
	handle = windows.Handle(r1)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
OpenProcess
打开现有的本地进程对象

HANDLE OpenProcess(

	[in] DWORD dwDesiredAccess,
	[in] BOOL  bInheritHandle,
	[in] DWORD dwProcessId
	);

如果函数成功，则返回值是指定进程的打开句柄; 如果函数失败，则返回值为 NULL

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
*/
func OpenProcess(desiredAccess uint32, inheritHandle bool, processId uint32) (handle windows.Handle, err error) {
	var _p0 uint32
	if inheritHandle {
		_p0 = 1
	}
	r1, _, e1 := syscall.SyscallN(
		procOpenProcess.Addr(),
		uintptr(desiredAccess), // 对进程对象的访问, 根据进程的安全描述符检查此访问权限
		uintptr(_p0),           // 如果此值为 TRUE, 则此进程创建的进程将继承句柄; 否则, 进程不会继承此句柄
		uintptr(processId),     // 要打开的本地进程的标识符
	)
	handle = windows.Handle(r1)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
WriteProcessMemory
将数据写入到指定进程中的内存区域。 要写入的整个区域必须可访问，否则操作将失败

BOOL WriteProcessMemory(

	[in]  HANDLE  hProcess,
	[in]  LPVOID  lpBaseAddress,
	[in]  LPCVOID lpBuffer,
	[in]  SIZE_T  nSize,
	[out] SIZE_T  *lpNumberOfBytesWritten
	);

如果该函数成功，则返回值为非零值。
如果函数失败，则返回值为 0（零）。 要获得更多的错误信息，请调用 GetLastError。 如果请求的写入操作交叉到无法访问的进程区域，函数将失败。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
*/
func WriteProcessMemory(process windows.Handle, baseAddress uintptr, buffer *byte, size uintptr, numberOfBytesWritten *uintptr) (err error) {
	r1, _, e1 := syscall.SyscallN(
		procWriteProcessMemory.Addr(),
		uintptr(process),
		baseAddress,
		uintptr(unsafe.Pointer(buffer)),
		size,
		uintptr(unsafe.Pointer(numberOfBytesWritten)),
		0,
	)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
CreateRemoteThreadEx
创建一个线程，该线程在另一个进程的虚拟地址空间中运行，并选择性地指定扩展属性，例如处理器组相关性

HANDLE CreateRemoteThreadEx(

	[in]            HANDLE                       hProcess,
	[in, optional]  LPSECURITY_ATTRIBUTES        lpThreadAttributes,
	[in]            SIZE_T                       dwStackSize,
	[in]            LPTHREAD_START_ROUTINE       lpStartAddress,
	[in, optional]  LPVOID                       lpParameter,
	[in]            DWORD                        dwCreationFlags,
	[in, optional]  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	[out, optional] LPDWORD                      lpThreadId
	);

如果函数成功，则返回值是新线程的句柄
如果函数失败，则返回值为 NULL

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethreadex
*/
func CreateRemoteThreadEx(hProcess windows.Handle, lpThreadAttributes uintptr, dwStackSize uintptr, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpAttributeList uintptr, lpThreadId uintptr) (handle windows.Handle, err error) {
	r1, _, e1 := syscall.SyscallN(
		procCreateRemoteThreadEx.Addr(),
		uintptr(hProcess), // 要在其中创建线程的进程句柄
		lpThreadAttributes,
		dwStackSize,
		lpStartAddress, // 指向应用程序定义的函数的指针 ，类型LPTHREAD_START_ROUTINE 由线程执行，表示远程进程中线程的起始地址
		lpParameter,
		uintptr(dwCreationFlags),
		lpAttributeList,
		lpThreadId,
	)
	handle = windows.Handle(r1)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
CloseHandle
关闭打开的对象句柄

BOOL CloseHandle(

	[in] HANDLE hObject
	);

如果该函数成功，则返回值为非零值
如果函数失败，则返回值为零

Link: https://learn.microsoft.com/zh-CN/windows/win32/api/handleapi/nf-handleapi-closehandle
*/
func CloseHandle(handle windows.Handle) (err error) {
	r1, _, e1 := syscall.SyscallN(procCloseHandle.Addr(), uintptr(handle), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
HeapCreate
创建可由调用进程使用的专用堆对象。 函数在进程的虚拟地址空间中保留空间，并为此块的指定初始部分分配物理存储

HANDLE HeapCreate(

	[in] DWORD  flOptions,
	[in] SIZE_T dwInitialSize,
	[in] SIZE_T dwMaximumSize
	);

如果函数成功，则返回值是新创建的堆的句柄
如果函数失败，则返回值为 NULL

Link: https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate
*/
func HeapCreate(flOptions uint32, dwInitialSize uintptr, dwMaximumSize uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procHeapCreate.Addr(),
		uintptr(flOptions),
		dwInitialSize,
		dwMaximumSize,
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
HeapAlloc
从堆中分配内存块。 分配的内存不可移动

DECLSPEC_ALLOCATOR LPVOID HeapAlloc(

	[in] HANDLE hHeap,
	[in] DWORD  dwFlags,
	[in] SIZE_T dwBytes
	);

如果函数成功，则返回值是指向已分配内存块的指针
如果函数失败并且您尚未指定 HEAP_GENERATE_EXCEPTIONS，则返回值为 NULL
如果函数失败并且已指定 HEAP_GENERATE_EXCEPTIONS，则函数可能会生成列出的任一异常: STATUS_NO_MEMORY, STATUS_ACCESS_VIOLATION

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/heapapi/nf-heapapi-heapalloc
*/
func HeapAlloc(hHeap windows.Handle, dwFlags uint32, dwBytes uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procHeapCreate.Addr(),
		uintptr(hHeap),
		uintptr(dwFlags),
		dwBytes,
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
EnumSystemLocalesA
枚举安装在操作系统上或受操作系统支持的区域设置

BOOL EnumSystemLocalesA(

	[in] LOCALE_ENUMPROCA lpLocaleEnumProc,
	[in] DWORD            dwFlags
	);

如果成功，则返回非零值，否则返回 0。 若要获取扩展错误信息，应用程序可以调用 GetLastError，这会返回以下错误代码之一:
ERROR_BADDB: 函数无法访问数据，这种情况通常不应发生，通常表示安装错误、磁盘问题或类似问题。
ERROR_INVALID_FLAGS: 为标志提供的值无效。
ERROR_INVALID_PARAMETER: 任何参数值都无效。

Link: https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumsystemlocalesa
*/
func EnumSystemLocalesA(lpLocaleEnumProc uintptr, dwFlags uint32) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procHeapCreate.Addr(), lpLocaleEnumProc, uintptr(dwFlags))
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
GetCurrentProcess
检索当前进程的伪句柄

HANDLE GetCurrentProcess();

返回值是当前进程的伪句柄

Link: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
*/
func GetCurrentProcess() (handle windows.Handle, err error) {
	r1, _, e1 := syscall.SyscallN(procGetCurrentProcess.Addr())
	handle = windows.Handle(r1)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
RtlMoveMemory
将源内存块的内容复制到目标内存块，并支持重叠的源内存块和目标内存块

VOID RtlMoveMemory(

	_Out_       VOID UNALIGNED *Destination,
	_In_  const VOID UNALIGNED *Source,
	_In_        SIZE_T         Length
	);

无返回值

Link: https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory
*/
func RtlMoveMemory(destination *byte, source *byte, length uintptr) (err error) {
	_, _, e1 := syscall.SyscallN(
		procRtlMoveMemory.Addr(),
		uintptr(unsafe.Pointer(destination)), // 指向要将字节复制到的目标内存块的指针
		uintptr(unsafe.Pointer(source)),      // 指向要从中复制字节的源内存块的指针
		length,                               // 要从源复制到目标的字节数
	)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

/*
EnumSystemLocalesW
枚举安装在操作系统上或受操作系统支持的区域设置

BOOL EnumSystemLocalesW(

	[in] LOCALE_ENUMPROCW lpLocaleEnumProc,
	[in] DWORD            dwFlags
	);

如果成功，则返回非零值，否则返回 0。 若要获取扩展错误信息，应用程序可以调用 GetLastError，这会返回以下错误代码之一:
ERROR_BADDB: 函数无法访问数据，这种情况通常不应发生，通常表示安装错误、磁盘问题或类似问题。
ERROR_INVALID_FLAGS: 为标志提供的值无效。
ERROR_INVALID_PARAMETER: 任何参数值都无效。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/winnls/nf-winnls-enumsystemlocalesw
*/
func EnumSystemLocalesW(lpLocaleEnumProc uintptr, dwFlags uint32) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procEnumSystemLocalesW.Addr(),
		lpLocaleEnumProc, // 指向应用程序定义的回调函数的指针
		uintptr(dwFlags), // 指定要枚举的区域设置标识符的标志
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
EnumSystemLocalesEx
枚举安装在操作系统上或受操作系统支持的区域设置
注意：如果设计为仅在 Windows Vista 及更高版本上运行，则应用程序应优先调用此函数，而不是 EnumSystemLocales

BOOL EnumSystemLocalesEx(

	[in]           LOCALE_ENUMPROCEX lpLocaleEnumProcEx,
	[in]           DWORD             dwFlags,
	[in]           LPARAM            lParam,
	[in, optional] LPVOID            lpReserved
	);

如果成功，则返回非零值，否则返回 0。 若要获取扩展错误信息，应用程序可以调用 GetLastError，这会返回以下错误代码之一:

ERROR_BADDB: 函数无法访问数据。 这种情况通常不应发生，通常表示安装错误、磁盘问题或类似问题。
ERROR_INVALID_FLAGS: 为标志提供的值无效。
ERROR_INVALID_PARAMETER: 任何参数值都无效。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/winnls/nf-winnls-enumsystemlocalesex
*/
func EnumSystemLocalesEx(lpLocaleEnumProcEx uintptr, dwFlags uint32, lParam uintptr, lpReserved uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procEnumSystemLocalesEx.Addr(),
		lpLocaleEnumProcEx, // 指向应用程序定义的回调函数的指针
		uintptr(dwFlags),   // 标识要枚举的区域设置的标志
		lParam,             // 要传递给回调函数的应用程序提供的参数
		lpReserved,         // 保留; 必须为 NULL
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
TerminateThread
终止线程

BOOL TerminateThread(

	[in, out] HANDLE hThread,
	[in]      DWORD  dwExitCode
	);

如果该函数成功，则返回值为非零值。
如果函数失败，则返回值为零。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminatethread
*/
func TerminateThread(hThread uintptr, dwExitCode uint32) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procTerminateThread.Addr(),
		hThread,             // 要终止的线程的句柄
		uintptr(dwExitCode), // 线程的退出代码, 使用 GetExitCodeThread 函数检索线程的退出值
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
ReadProcessMemory
BOOL ReadProcessMemory(

	[in]  HANDLE  hProcess,
	[in]  LPCVOID lpBaseAddress,
	[out] LPVOID  lpBuffer,
	[in]  SIZE_T  nSize,
	[out] SIZE_T  *lpNumberOfBytesRead
	);

如果该函数成功，则返回值为非零值。
如果函数失败，则返回值为 0。
如果请求的读取操作交叉到无法访问的进程区域，函数将失败。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory
*/
func ReadProcessMemory(process windows.Handle, baseAddress uintptr, buffer *byte, size uintptr, numberOfBytesRead *uintptr) (err error) {
	r1, _, e1 := syscall.SyscallN(
		procReadProcessMemory.Addr(),
		uintptr(process), // 包含正在读取的内存的进程句柄
		baseAddress,      // 指向从中读取的指定进程中基址的指针
		uintptr(unsafe.Pointer(buffer)),
		size,
		uintptr(unsafe.Pointer(numberOfBytesRead)),
		0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
CreateToolhelp32Snapshot
获取指定进程以及这些进程使用的堆、模块和线程的快照

HANDLE CreateToolhelp32Snapshot(

	[in] DWORD dwFlags,
	[in] DWORD th32ProcessID
	);

如果函数成功，它将返回指定快照的打开句柄。
如果函数失败，它将返回 INVALID_HANDLE_VALUE。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
*/
func CreateToolhelp32Snapshot(flags uint32, processId uint32) (handle windows.Handle, err error) {
	r0, _, e1 := syscall.SyscallN(
		procCreateToolhelp32Snapshot.Addr(),
		uintptr(flags),
		uintptr(processId),
		0,
	)
	handle = windows.Handle(r0)
	if handle == windows.InvalidHandle {
		err = errnoErr(e1)
	}
	return
}

/*
Thread32First
检索系统快照中遇到的任何进程的第一个线程的相关信息

BOOL Thread32First(

	[in]      HANDLE          hSnapshot,
	[in, out] LPTHREADENTRY32 lpte
	);

如果线程列表的第一个条目已复制到缓冲区，则返回 TRUE ，否则返回 FALSE 。
如果不存在线程或快照不包含线程信息，则 GetLastError 函数返回ERROR_NO_MORE_FILES错误值。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/tlhelp32/nf-tlhelp32-thread32first
*/
func Thread32First(snapshot windows.Handle, threadEntry *ThreadEntry32) (err error) {
	r1, _, e1 := syscall.SyscallN(
		procThread32First.Addr(),
		uintptr(snapshot),                    // 快照的句柄，该句柄是从上次调用 CreateToolhelp32Snapshot 函数返回的。
		uintptr(unsafe.Pointer(threadEntry)), // 指向 THREADENTRY32 结构的指针
		0,
	)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
GetTickCount
检索自系统启动以来经过的毫秒数，最长为 49.7 天

DWORD GetTickCount();

返回值是自系统启动以来经过的毫秒数

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount
*/
func GetTickCount() (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procGetTickCount.Addr())
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
GetPhysicallyInstalledSystemMemory
检索实际安装在计算机上的 RAM 量

BOOL GetPhysicallyInstalledSystemMemory(

	[out] PULONGLONG TotalMemoryInKilobytes
	);

如果函数成功，则返回 TRUE 并将 TotalMemoryInKilobytes 参数设置为非零值。
如果函数失败，它将返回 FALSE ，并且不会修改 TotalMemoryInKilobytes 参数。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/sysinfoapi/nf-sysinfoapi-getphysicallyinstalledsystemmemory
*/
func GetPhysicallyInstalledSystemMemory(totalMemoryInKilobytes uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procGetPhysicallyInstalledSystemMemory.Addr(),
		totalMemoryInKilobytes, // 指向变量的指针，该变量接收物理安装的 RAM 量（以 KB 为单位）
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
OpenThread
打开现有线程对象

HANDLE OpenThread(

	[in] DWORD dwDesiredAccess,
	[in] BOOL  bInheritHandle,
	[in] DWORD dwThreadId
	);

如果函数成功，则返回值是指定线程的打开句柄。
如果函数失败，则返回值为 NULL。

Link: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread
*/
func OpenThread(desiredAccess uint32, inheritHandle bool, threadId uint32) (handle windows.Handle, err error) {
	var _p0 uint32
	if inheritHandle {
		_p0 = 1
	}
	r1, _, e1 := syscall.SyscallN(
		procOpenThread.Addr(),
		uintptr(desiredAccess), // 对线程对象的访问
		uintptr(_p0),           // 如果此值为 TRUE，则此进程创建的进程将继承句柄; 否则，进程不会继承此句柄
		uintptr(threadId))      // 要打开的线程的标识符
	handle = windows.Handle(r1)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
QueueUserAPC
将用户模式 异步过程调用 (APC) 对象添加到指定线程的 APC 队列

DWORD QueueUserAPC(

	[in] PAPCFUNC  pfnAPC,
	[in] HANDLE    hThread,
	[in] ULONG_PTR dwData
	);

如果该函数成功，则返回值为非零值。
如果函数失败，则返回值为零。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc
*/
func QueueUserAPC(pfnAPC uintptr, hThread uintptr, dwData uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procQueueUserAPC.Addr(),
		pfnAPC,  // 指向应用程序提供的 APC 函数的指针，该函数在指定线程执行可警报等待操作时调用
		hThread, // 线程的句柄
		dwData,  // 传递给 pfnAPC 参数指向的 APC 函数的单个值
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
CreateRemoteThread
创建在另一个进程的虚拟地址空间中运行的线程。
使用 CreateRemoteThreadEx 函数创建在另一个进程的虚拟地址空间中运行的线程，并选择性地指定扩展属性。

HANDLE CreateRemoteThread(

	  [in]  HANDLE                 hProcess,
	  [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	  [in]  SIZE_T                 dwStackSize,
	  [in]  LPTHREAD_START_ROUTINE lpStartAddress,
	  [in]  LPVOID                 lpParameter,
	  [in]  DWORD                  dwCreationFlags,
	  [out] LPDWORD                lpThreadId
	);

如果函数成功，则返回值是新线程的句柄。
如果函数失败，则返回值为 NULL。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
*/
func CreateRemoteThread(hProcess windows.Handle, lpThreadAttributes uintptr, dwStackSize uintptr, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uintptr, lpThreadId uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procCreateRemoteThread.Addr(),
		uintptr(hProcess), // 要在其中创建线程的进程句柄
		lpThreadAttributes,
		dwStackSize,
		lpStartAddress, // 起始地址
		lpParameter,
		dwCreationFlags,
		lpThreadId,
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
LoadLibraryA
将指定的模块加载到调用进程的地址空间中。 指定的模块可能会导致加载其他模块。
有关其他加载选项，请使用 LoadLibraryEx 函数。

HMODULE LoadLibraryA(

	  [in] LPCSTR lpLibFileName // 模块的名称。 可以是库模块 (.dll 文件) ，也可以是可执行模块 (.exe 文件)
	);

返回值
如果函数成功，则返回值是模块的句柄。
如果函数失败，则返回值为 NULL。 要获得更多的错误信息，请调用 GetLastError。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
*/
func LoadLibraryA(lpLibFileName string) (handle windows.Handle, err error) {
	r1, _, e1 := syscall.SyscallN(
		procLoadLibraryA.Addr(),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(lpLibFileName))), // type: *uint16
	)
	handle = windows.Handle(r1)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
GetThreadContext
检索指定线程的上下文。
64 位应用程序可以使用 Wow64GetThreadContext 检索 WOW64 线程的上下文。

BOOL GetThreadContext(

	[in]      HANDLE    hThread,  // 要检索其上下文的线程的句柄
	[in, out] LPCONTEXT lpContext // 指向 CONTEXT 结构的指针 (，例如接收指定线程的适当上下文 的 ARM64_NT_CONTEXT)
	);

如果该函数成功，则返回值为非零值。
如果函数失败，则返回值为零。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext
*/
func GetThreadContext(hThread windows.Handle, lpContext *CONTEXT) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procGetThreadContext.Addr(),
		uintptr(hThread),
		uintptr(unsafe.Pointer(lpContext)),
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
ResumeThread
递减线程的挂起计数。 当暂停计数减为零时，将恢复线程的执行。

DWORD ResumeThread(

	[in] HANDLE hThread // 要重启的线程的句柄
	);

如果函数成功，则返回值是线程的上一个挂起计数。
如果函数失败，则返回值 (DWORD) -1。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread
*/
func ResumeThread(hThread windows.Handle) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procResumeThread.Addr(),
		uintptr(hThread),
	)
	value = r1
	if value == 0xFFFFFFFF {
		err = errnoErr(e1)
	}
	return
}

/*
SetThreadContext
设置指定的线程的上下文。
64 位应用程序可以使用 Wow64SetThreadContext 函数设置 WOW64 线程的上下文。

BOOL SetThreadContext(

	[in] HANDLE        hThread, 	// 要设置其上下文的线程的句柄
	[in] const CONTEXT *lpContext   // 指向 CONTEXT 结构的指针，该结构包含要设置在指定线程中的上下文
	);

如果设置了上下文，则返回值为非零值。
如果函数失败，则返回值为零。

CONTEXT 结构: https://learn.microsoft.com/zh-cn/windows/win32/api/winnt/ns-winnt-arm64_nt_context
Link: https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext
*/
func SetThreadContext(hThread windows.Handle, lpContext *CONTEXT) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procSetThreadContext.Addr(),
		uintptr(hThread),
		uintptr(unsafe.Pointer(lpContext)),
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
CreateProcessA
创建新进程及其主线程。 新进程在调用进程的安全上下文中运行。
如果调用进程正在模拟其他用户，则新进程将令牌用于调用进程，而不是模拟令牌。 若要在模拟令牌表示的用户的安全上下文中运行新进程，请使用 CreateProcessAsUser 或 CreateProcessWithLogonW 函数。

BOOL CreateProcessA(

	[in, optional]      LPCSTR                lpApplicationName,    // 要执行的模块的名称
	[in, out, optional] LPSTR                 lpCommandLine,        // 要执行的命令行
	[in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,  // 指向 SECURITY_ATTRIBUTES 结构的指针
	[in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,   // 指向 SECURITY_ATTRIBUTES 结构的指针
	[in]                BOOL                  bInheritHandles,      // 参数为 TRUE，则调用进程中的每个可继承句柄都由新进程继承
	[in]                DWORD                 dwCreationFlags,      // 控制优先级类和进程的创建的标志
	[in, optional]      LPVOID                lpEnvironment,        // 指向新进程的环境块的指针
	[in, optional]      LPCSTR                lpCurrentDirectory,   // 进程当前目录的完整路径
	[in]                LPSTARTUPINFOA        lpStartupInfo,		// 指向 STARTUPINFO 或 STARTUPINFOEX 结构的指针
	[out]               LPPROCESS_INFORMATION lpProcessInformation  // 指向接收有关新进程的标识信息的 PROCESS_INFORMATION 结构的指针
	);

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
*/
func CreateProcessA(appName *uint16, commandLine *uint16, procSecurity *windows.SecurityAttributes, threadSecurity *windows.SecurityAttributes, inheritHandles bool, creationFlags uint32, env *uint16, currentDir *uint16, startupInfo *windows.StartupInfo, outProcInfo *windows.ProcessInformation) (err error) {
	var _p0 uint32
	if inheritHandles {
		_p0 = 1
	}
	r1, _, e1 := syscall.SyscallN(
		procCreateProcessA.Addr(),
		uintptr(unsafe.Pointer(appName)),
		uintptr(unsafe.Pointer(commandLine)),
		uintptr(unsafe.Pointer(procSecurity)),
		uintptr(unsafe.Pointer(threadSecurity)),
		uintptr(_p0),
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(env)),
		uintptr(unsafe.Pointer(currentDir)),
		uintptr(unsafe.Pointer(startupInfo)),
		uintptr(unsafe.Pointer(outProcInfo)),
	)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
SuspendThread
挂起指定的线程。
64 位应用程序可以使用 Wow64SuspendThread 函数挂起 WOW64 线程。

DWORD SuspendThread(

	[in] HANDLE hThread // 要挂起的线程的句柄
	);

如果函数成功，则返回值为线程的上一个挂起计数;否则为 (DWORD) -1。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread
*/
func SuspendThread(hThread windows.Handle) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procSuspendThread.Addr(),
		uintptr(hThread),
	)
	value = r1
	if value == 0xFFFFFFFF {
		err = errnoErr(e1)
	}
	return
}

/*
LoadLibraryW
将指定的模块加载到调用进程的地址空间中。 指定的模块可能会导致加载其他模块。

HMODULE LoadLibraryW(

	[in] LPCWSTR lpLibFileName
	);

如果函数成功，则返回值是模块的句柄。
如果函数失败，则返回值为 NULL。

Links: https://learn.microsoft.com/zh-cn/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw
*/
func LoadLibraryW(libName string) (handle windows.Handle, err error) {
	var _p0 *uint16
	_p0, err = windows.UTF16PtrFromString(libName)
	if err != nil {
		return
	}
	return _LoadLibrary(_p0)
}

func _LoadLibrary(libName *uint16) (handle windows.Handle, err error) {
	r0, _, e1 := syscall.SyscallN(
		procLoadLibraryW.Addr(),
		uintptr(unsafe.Pointer(libName)),
	)
	handle = windows.Handle(r0)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Beep
在扬声器上生成简单的音调。 函数是同步的;它执行可警报等待，在声音完成之前不会将控制权返回到其调用方。

BOOL Beep(

	[in] DWORD dwFreq,		// 声音的频率，以Hz为单位。 此参数的范围必须介于 37 到 32,767 (0x25 到 0x7FFF) 。
	[in] DWORD dwDuration   // 声音的持续时间（以毫秒为单位）。
	);

如果该函数成功，则返回值为非零值。
如果函数失败，则返回值为零。

Links: https://learn.microsoft.com/zh-cn/windows/win32/api/utilapiset/nf-utilapiset-beep
*/
func Beep(dwFreq uint32, dwDuration uint32) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procBeep.Addr(),
		uintptr(dwFreq),
		uintptr(dwDuration),
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
SetFileInformationByHandle
设置指定文件的文件信息。
若要使用文件句柄检索文件信息，请参阅 GetFileInformationByHandle 或 GetFileInformationByHandleEx。

BOOL SetFileInformationByHandle(

	[in] HANDLE                    hFile, // 要更改其信息的文件的句柄
	[in] FILE_INFO_BY_HANDLE_CLASS FileInformationClass, // 一个FILE_INFO_BY_HANDLE_CLASS枚举值，该值指定要更改的信息的类型
	[in] LPVOID                    lpFileInformation, // 指向缓冲区的指针，该缓冲区包含指定文件信息类要更改的信息
	[in] DWORD                     dwBufferSize // lpFileInformation 的大小（以字节为单位）
	);

如果成功，则返回非零值，否则返回零。
要获得更多的错误信息，请调用 GetLastError。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle
*/
func SetFileInformationByHandle(handle windows.Handle, class uint32, inBuffer *byte, inBufferLen uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(
		procSetFileInformationByHandle.Addr(),
		uintptr(handle),
		uintptr(class),
		uintptr(unsafe.Pointer(inBuffer)),
		uintptr(inBufferLen),
	)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
GetProcAddress

FARPROC GetProcAddress(

	[in] HMODULE hModule,
	[in] LPCSTR  lpProcName
	);

[in] hModule
包含函数或变量的 DLL 模块的句柄。 LoadLibrary、LoadLibraryEx、LoadPackagedLibrary 或 GetModuleHandle 函数返回此句柄。
GetProcAddress 函数不会从使用 LOAD_LIBRARY_AS_DATAFILE 标志加载的模块中检索地址。 有关详细信息，请参阅 LoadLibraryEx。

[in] lpProcName
函数或变量名称，或函数的序号值。 如果此参数是序号值，则它必须在低序位字中；高序位字必须为零。

Return
如果函数成功，则返回值是导出的函数或变量的地址。
如果函数失败，则返回值为 NULL。 要获得更多的错误信息，请调用 GetLastError。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
*/
func GetProcAddress(module windows.Handle, procName string) (proc uintptr, err error) {
	var _p0 *byte
	_p0, err = windows.BytePtrFromString(procName)
	if err != nil {
		return
	}
	return _GetProcAddress(module, _p0)
}

func _GetProcAddress(module windows.Handle, procName *byte) (proc uintptr, err error) {
	r0, _, e1 := syscall.SyscallN(
		procGetProcAddress.Addr(),
		uintptr(module),
		uintptr(unsafe.Pointer(procName)),
		0,
	)
	proc = r0
	if proc == 0 {
		err = errnoErr(e1)
	}
	return
}

func GetLoadLibraryAAddr() (uintptr, error) {
	ptr, err := windows.GetProcAddress(
		windows.Handle(procLoadLibraryA.Addr()),
		"LoadLibraryA",
	)
	err = syscall.GetLastError()
	return ptr, err
}

/*
GetConsoleWindow
检索与调用进程相关联的控制台使用的窗口句柄

HWND WINAPI GetConsoleWindow(void);

返回值
返回值是与调用进程相关联的控制台所使用的窗口句柄，如果没有此类关联控制台，则返回值为 NULL。

Link: https://learn.microsoft.com/zh-cn/windows/console/getconsolewindow
*/
func GetConsoleWindow() (proc uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procGetConsoleWindow.Addr())
	proc = r1
	if proc == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
SleepEx
挂起当前线程，直到满足指定的条件。 发生以下情况之一时，将继续执行：

	调用 I/O 完成回调函数。
	异步过程调用 (APC) 排队到线程。
	超时间隔已过。

DWORD SleepEx(

	[in] DWORD dwMilliseconds,   // 暂停执行的时间间隔（以毫秒为单位）
	[in] BOOL  bAlertable        // 如果此参数为 FALSE，则函数在超时期限过后才会返回

);

返回值
如果指定的时间间隔过期，则返回值为零。

如果函数由于一个或多个 I/O 完成回调函数而返回，则返回值WAIT_IO_COMPLETION。 仅当 bAlertable 为 TRUE，并且调用 SleepEx 函数的线程与调用扩展 I/O 函数的线程相同时，才会发生这种情况。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/synchapi/nf-synchapi-sleepex
*/
func SleepEx(dwMilliseconds uint32, bAlertable bool) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procSleepEx.Addr(),
		uintptr(dwMilliseconds),
		uintptr(unsafe.Pointer(&bAlertable)),
	)
	if r1 != 0 {
		err = errnoErr(e1)
	}
	return
}
