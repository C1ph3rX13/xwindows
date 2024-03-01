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

void SwitchToFiber(

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

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
*/
func CreateThread(lpThreadAttributes uintptr, dwStackSize uintptr, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uintptr, lpThreadId uintptr) (handle windows.Handle, err error) {
	r1, _, e1 := syscall.SyscallN(
		procCreateThread.Addr(),
		lpThreadAttributes,
		dwStackSize,
		lpStartAddress,
		lpParameter,
		dwCreationFlags,
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
