package xwindows

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func VirtualAlloc(address uintptr, size uintptr, allocType uint32, protect uint32) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procVirtualAlloc.Addr(), address, size, uintptr(allocType), uintptr(protect), 0, 0)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualProtect(address uintptr, size uintptr, allocType uint32, protect uint32) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procVirtualProtect.Addr(), address, size, uintptr(allocType), uintptr(protect), 0, 0)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

func VirtualProtectEx(process windows.Handle, address uintptr, size uintptr, newProtect uint32, oldProtect *uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procVirtualProtectEx.Addr(), uintptr(process), address, size, uintptr(newProtect), uintptr(unsafe.Pointer(oldProtect)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process. The function initializes the memory it allocates to zero.

If the function succeeds, the return value is the base address of the allocated region of pages.

If the function fails, the return value is NULL. To get extended error information, call GetLastError.

LPVOID VirtualAllocEx(
	[in]           HANDLE hProcess,
	[in, optional] LPVOID lpAddress,
	[in]           SIZE_T dwSize,
	[in]           DWORD  flAllocationType,
	[in]           DWORD  flProtect
	);
*/

func VirtualAllocEx(hProcess windows.Handle, lpAddress uintptr, dwSize uintptr, newProtect uint32, oldProtect *uint32) (err error) {
	r1, _, e1 := syscall.SyscallN(procVirtualAllocEx.Addr(), uintptr(hProcess), lpAddress, dwSize, uintptr(newProtect), uintptr(unsafe.Pointer(oldProtect)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Converts the current thread into a fiber. You must convert a thread into a fiber before you can schedule other fibers.

If the function succeeds, the return value is the address of the fiber.

LPVOID ConvertThreadToFiber(
	[in, optional] LPVOID lpParameter
	);
*/

func ConvertThreadToFiber(lpParameter uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procConvertThreadToFiber.Addr(), lpParameter)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Allocates a fiber object, assigns it a stack, and sets up execution to begin at the specified start address, typically the fiber function. This function does not schedule the fiber.

If the function succeeds, the return value is the address of the fiber.

LPVOID CreateFiber(
	[in]           SIZE_T                dwStackSize,
	[in]           LPFIBER_START_ROUTINE lpStartAddress,
	[in, optional] LPVOID                lpParameter
	);
*/

func CreateFiber(dwStackSize uintptr, lpStartAddress uintptr, lpParameter uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procCreateFiber.Addr(), dwStackSize, lpStartAddress, lpParameter)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Schedules a fiber. The function must be called on a fiber.

None return value.

void SwitchToFiber(
	[in] LPVOID lpFiber
	);
*/

func SwitchToFiber(lpFiber uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procSwitchToFiber.Addr(), lpFiber)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Retrieves a pseudo handle for the calling thread.

The return value is a pseudo handle for the current thread.

HANDLE GetCurrentThread();
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
Waits until the specified object is in the signaled state or the time-out interval elapses.
To enter an alertable wait state, use the WaitForSingleObjectEx function. To wait for multiple objects, use WaitForMultipleObjects.

If the function succeeds, the return value indicates the event that caused the function to return. It can be one of the following values.

DWORD WaitForSingleObject(
	[in] HANDLE hHandle,
	[in] DWORD  dwMilliseconds
	);
*/

func WaitForSingleObject(handle windows.Handle, waitMilliseconds uint32) (event uint32, err error) {
	r1, _, e1 := syscall.SyscallN(procWaitForSingleObject.Addr(), uintptr(handle), uintptr(waitMilliseconds), 0)
	event = uint32(r1)
	if event == 0xffffffff {
		err = errnoErr(e1)
	}
	return
}

/*
Creates a thread to execute within the virtual address space of the calling process.

If the function succeeds, the return value is a handle to the new thread.

If the function fails, the return value is NULL. To get extended error information, call GetLastError.

HANDLE CreateThread(
	[in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	[in]            SIZE_T                  dwStackSize,
	[in]            LPTHREAD_START_ROUTINE  lpStartAddress,
	[in, optional]  __drv_aliasesMem LPVOID lpParameter,
	[in]            DWORD                   dwCreationFlags,
	[out, optional] LPDWORD                 lpThreadId
	);
*/

func CreateThread(lpThreadAttributes uintptr, dwStackSize uintptr, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uintptr, lpThreadId uintptr) (handle windows.Handle, err error) {
	r1, _, e1 := syscall.SyscallN(procCreateThread.Addr(), lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId)
	handle = windows.Handle(r1)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Opens an existing local process object.

If the function succeeds, the return value is an open handle to the specified process.

If the function fails, the return value is NULL. To get extended error information, call GetLastError.

HANDLE OpenProcess(
	[in] DWORD dwDesiredAccess,
	[in] BOOL  bInheritHandle,
	[in] DWORD dwProcessId
	);
*/

func OpenProcess(desiredAccess uint32, inheritHandle bool, processId uint32) (handle windows.Handle, err error) {
	var _p0 uint32
	if inheritHandle {
		_p0 = 1
	}
	r1, _, e1 := syscall.SyscallN(procOpenProcess.Addr(), uintptr(desiredAccess), uintptr(_p0), uintptr(processId))
	handle = windows.Handle(r1)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails.

If the function succeeds, the return value is nonzero.

If the function fails, the return value is 0 (zero). To get extended error information, call GetLastError. The function fails if the requested write operation crosses into an area of the process that is inaccessible.

BOOL WriteProcessMemory(
	[in]  HANDLE  hProcess,
	[in]  LPVOID  lpBaseAddress,
	[in]  LPCVOID lpBuffer,
	[in]  SIZE_T  nSize,
	[out] SIZE_T  *lpNumberOfBytesWritten
	);
*/

func WriteProcessMemory(hProcess windows.Handle, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr, lpNumberOfBytesWritten *uintptr) (err error) {
	r1, _, e1 := syscall.SyscallN(procWriteProcessMemory.Addr(), uintptr(hProcess), lpBaseAddress, uintptr(unsafe.Pointer(lpBuffer)), nSize, uintptr(unsafe.Pointer(lpNumberOfBytesWritten)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Creates a thread that runs in the virtual address space of another process and optionally specifies extended attributes such as processor group affinity.

If the function succeeds, the return value is a handle to the new thread.

If the function fails, the return value is NULL. To get extended error information, call GetLastError.

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
*/

func CreateRemoteThreadEx(hProcess windows.Handle, lpThreadAttributes uintptr, dwStackSize uintptr, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uint32, lpAttributeList uintptr, lpThreadId uintptr) (handle windows.Handle, err error) {
	r1, _, e1 := syscall.SyscallN(procCreateRemoteThreadEx.Addr(), uintptr(hProcess), lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, uintptr(dwCreationFlags), lpAttributeList, lpThreadId)
	handle = windows.Handle(r1)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Closes an open object handle.

If the function succeeds, the return value is nonzero.

If the function fails, the return value is zero. To get extended error information, call GetLastError.

BOOL CloseHandle(
	[in] HANDLE hObject
	);
*/

func CloseHandle(handle windows.Handle) (err error) {
	r1, _, e1 := syscall.SyscallN(procCloseHandle.Addr(), uintptr(handle), 0, 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Creates a private heap object that can be used by the calling process. The function reserves space in the virtual address space of the process and allocates physical storage for a specified initial portion of this block.

If the function succeeds, the return value is a handle to the newly created heap.

If the function fails, the return value is NULL. To get extended error information, call GetLastError.

HANDLE HeapCreate(
	[in] DWORD  flOptions,
	[in] SIZE_T dwInitialSize,
	[in] SIZE_T dwMaximumSize
	);

Link: https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate
*/

func HeapCreate(flOptions uint32, dwInitialSize uintptr, dwMaximumSize uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procHeapCreate.Addr(), uintptr(flOptions), dwInitialSize, dwMaximumSize)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Allocates a block of memory from a heap. The allocated memory is not movable.

If the function succeeds, the return value is a pointer to the allocated memory block.

If the function fails, and you have not specified HEAP_GENERATE_EXCEPTIONS, the return value is NULL.

If the function fails, and you have specified HEAP_GENERATE_EXCEPTIONS, the function may generate either of the exceptions listed in the following table. The particular exception depends upon the nature of the heap corruption. For more information, see GetExceptionCode.

DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
	[in] HANDLE hHeap,
	[in] DWORD  dwFlags,
	[in] SIZE_T dwBytes
	);

Link: https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc
*/

func HeapAlloc(hHeap windows.Handle, dwFlags uint32, dwBytes uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procHeapCreate.Addr(), uintptr(hHeap), uintptr(dwFlags), dwBytes)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Enumerates the locales that are either installed on or supported by an operating system.

Returns a nonzero value if successful, or 0 otherwise. To get extended error information, the application can call GetLastError, which can return one of the following error codes:

1.ERROR_BADDB. The function could not access the data. This situation should not normally occur, and typically indicates a bad installation, a disk problem, or the like.
2.ERROR_INVALID_FLAGS. The values supplied for flags were not valid.
3.ERROR_INVALID_PARAMETER. Any of the parameter values was invalid.

BOOL EnumSystemLocalesA(
	[in] LOCALE_ENUMPROCA lpLocaleEnumProc,
	[in] DWORD            dwFlags
	);

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
The return value is a pseudo handle to the current process.

HANDLE GetCurrentProcess();

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
Copies the contents of a source memory block to a destination memory block, and supports overlapping source and destination memory blocks.

Return value: None

VOID RtlMoveMemory(
	_Out_       VOID UNALIGNED *Destination,
	_In_  const VOID UNALIGNED *Source,
	_In_        SIZE_T         Length
	);

Link: https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory
*/

func RtlMoveMemory(destination uintptr, source uintptr, length uintptr) (err error) {
	_, _, e1 := syscall.SyscallN(procRtlMoveMemory.Addr(), destination, source, length)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Enumerates the locales that are either installed on or supported by an operating system.

BOOL EnumSystemLocalesW(

	[in] LOCALE_ENUMPROCW lpLocaleEnumProc,
	[in] DWORD            dwFlags
	);

Returns a nonzero value if successful, or 0 otherwise. To get extended error information, the application can call GetLastError, which can return one of the following error codes:

ERROR_BADDB. The function could not access the data. This situation should not normally occur, and typically indicates a bad installation, a disk problem, or the like.
ERROR_INVALID_FLAGS. The values supplied for flags were not valid.
ERROR_INVALID_PARAMETER. Any of the parameter values was invalid.
*/

func EnumSystemLocalesW(lpLocaleEnumProc uintptr, dwFlags uint32) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procEnumSystemLocalesW.Addr(), lpLocaleEnumProc, uintptr(dwFlags))
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Enumerates the locales that are either installed on or supported by an operating system.

BOOL EnumSystemLocalesEx(
	[in]           LOCALE_ENUMPROCEX lpLocaleEnumProcEx,
	[in]           DWORD             dwFlags,
	[in]           LPARAM            lParam,
	[in, optional] LPVOID            lpReserved
	);

Returns a nonzero value if successful, or 0 otherwise. To get extended error information, the application can call GetLastError, which can return one of the following error codes:

ERROR_BADDB. The function could not access the data. This situation should not normally occur, and typically indicates a bad installation, a disk problem, or the like.
ERROR_INVALID_FLAGS. The values supplied for flags were not valid.
ERROR_INVALID_PARAMETER. Any of the parameter values was invalid.

Link:https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumsystemlocalesex
*/

func EnumSystemLocalesEx(lpLocaleEnumProcEx uintptr, dwFlags uint32, lParam uintptr, lpReserved uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procEnumSystemLocalesEx.Addr(), lpLocaleEnumProcEx, uintptr(dwFlags), lParam, lpReserved)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Terminates a thread.

BOOL TerminateThread(
	[in, out] HANDLE hThread,
	[in]      DWORD  dwExitCode
	);

If the function succeeds, the return value is nonzero.

If the function fails, the return value is zero. To get extended error information, call GetLastError.

Link: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminatethread
*/

func TerminateThread(hThread uintptr, dwExitCode uint32) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procTerminateThread.Addr(), hThread, uintptr(dwExitCode))
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
BOOL ReadProcessMemory(
	[in]  HANDLE  hProcess,
	[in]  LPCVOID lpBaseAddress,
	[out] LPVOID  lpBuffer,
	[in]  SIZE_T  nSize,
	[out] SIZE_T  *lpNumberOfBytesRead
	);

If the function succeeds, the return value is nonzero.

If the function fails, the return value is 0 (zero). To get extended error information, call GetLastError.

The function fails if the requested read operation crosses into an area of the process that is inaccessible.

Link: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory
*/

func ReadProcessMemory(process windows.Handle, baseAddress uintptr, buffer *byte, size uintptr, numberOfBytesRead *uintptr) (err error) {
	r1, _, e1 := syscall.SyscallN(procReadProcessMemory.Addr(), uintptr(process), baseAddress, uintptr(unsafe.Pointer(buffer)), size, uintptr(unsafe.Pointer(numberOfBytesRead)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.

HANDLE CreateToolhelp32Snapshot(
	[in] DWORD dwFlags,
	[in] DWORD th32ProcessID
	);

If the function succeeds, it returns an open handle to the specified snapshot.
*/

func CreateToolhelp32Snapshot(flags uint32, processId uint32) (handle windows.Handle, err error) {
	r0, _, e1 := syscall.SyscallN(procCreateToolhelp32Snapshot.Addr(), uintptr(flags), uintptr(processId), 0)
	handle = windows.Handle(r0)
	if handle == windows.InvalidHandle {
		err = errnoErr(e1)
	}
	return
}

/*
Retrieves information about the first thread of any process encountered in a system snapshot.

BOOL Thread32First(
	[in]      HANDLE          hSnapshot,
	[in, out] LPTHREADENTRY32 lpte
	);

Returns TRUE if the first entry of the thread list has been copied to the buffer or FALSE otherwise. The ERROR_NO_MORE_FILES error value is returned by the GetLastError function if no threads exist or the snapshot does not contain thread information.

Link: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32first
*/

func Thread32First(snapshot windows.Handle, threadEntry *ThreadEntry32) (err error) {
	r1, _, e1 := syscall.SyscallN(procThread32First.Addr(), 2, uintptr(snapshot), uintptr(unsafe.Pointer(threadEntry)), 0)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Retrieves the number of milliseconds that have elapsed since the system was started, up to 49.7 days.

DWORD GetTickCount();

The return value is the number of milliseconds that have elapsed since the system was started.
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
Retrieves the amount of RAM that is physically installed on the computer.

BOOL GetPhysicallyInstalledSystemMemory(
	[out] PULONGLONG TotalMemoryInKilobytes
	);

If the function succeeds, it returns TRUE and sets the TotalMemoryInKilobytes parameter to a nonzero value.
*/

func GetPhysicallyInstalledSystemMemory(totalMemoryInKilobytes uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procGetPhysicallyInstalledSystemMemory.Addr(), totalMemoryInKilobytes)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Opens an existing thread object.

HANDLE OpenThread(
	[in] DWORD dwDesiredAccess,
	[in] BOOL  bInheritHandle,
	[in] DWORD dwThreadId
	);

If the function succeeds, the return value is an open handle to the specified thread.

If the function fails, the return value is NULL. To get extended error information, call GetLastError

Link: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread
*/

func OpenThread(desiredAccess uint32, inheritHandle bool, threadId uint32) (handle windows.Handle, err error) {
	var _p0 uint32
	if inheritHandle {
		_p0 = 1
	}
	r1, _, e1 := syscall.SyscallN(procOpenThread.Addr(), uintptr(desiredAccess), uintptr(_p0), uintptr(threadId))
	handle = windows.Handle(r1)
	if handle == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
Adds a user-mode asynchronous procedure call (APC) object to the APC queue of the specified thread.

DWORD QueueUserAPC(
	[in] PAPCFUNC  pfnAPC,
	[in] HANDLE    hThread,
	[in] ULONG_PTR dwData
	);

If the function succeeds, the return value is nonzero.
*/

func QueueUserAPC(pfnAPC uintptr, hThread uintptr, dwData uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procQueueUserAPC.Addr(), pfnAPC, hThread, dwData)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}
