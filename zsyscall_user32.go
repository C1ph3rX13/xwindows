package xwindows

import (
	"syscall"

	"golang.org/x/sys/windows"
)

/*
ShowWindow
设置指定窗口的显示状态

BOOL ShowWindow(

	[in] HWND hWnd,
	[in] int  nCmdShow
	);

返回值
类型： BOOL
如果窗口以前可见，则返回值为非零值。
如果以前隐藏窗口，则返回值为零。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/winuser/nf-winuser-showwindow
*/
func ShowWindow(handle windows.Handle, cmdShow int32) (err error) {
	r1, _, e1 := syscall.SyscallN(
		procShowWindow.Addr(),
		uintptr(handle),
		uintptr(cmdShow),
	)
	if r1 == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
EnumWindows
通过将句柄传递到每个窗口，进而将传递给应用程序定义的回调函数，枚举屏幕上的所有顶级窗口
枚举窗口 将一直持续到最后一个顶级窗口被枚举或回调函数返回 FALSE

BOOL EnumWindows(

	[in] WNDENUMPROC lpEnumFunc, // 指向应用程序定义的回调函数的指针
	[in] LPARAM      lParam      // 要传递给回调函数的应用程序定义值

);

返回值
类型： BOOL
如果该函数成功，则返回值为非零值。
如果函数失败，则返回值为零。 要获得更多的错误信息，请调用 GetLastError。
如果 EnumWindowsProc 返回零，则返回值也为零。 在这种情况下，回调函数应调用 SetLastError 以获取要返回到 EnumWindows 调用方有意义的错误代码。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/winuser/nf-winuser-enumwindows
*/
func EnumWindows(lpEnumFunc windows.Handle, lParam uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procEnumWindows.Addr(),
		uintptr(lpEnumFunc),
		lParam,
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
EnumDesktopWindows
枚举与指定桌面关联的所有顶级窗口

BOOL EnumDesktopWindows(

	[in, optional] HDESK       hDesktop, // 要枚举其顶级窗口的桌面的句柄
	[in]           WNDENUMPROC lpfn, // 指向应用程序定义的 EnumWindowsProc 回调函数的指针
	[in]           LPARAM      lParam // 要传递给回调函数的应用程序定义值

);
返回值
如果函数失败或无法执行枚举，则返回值为零。
要获得更多的错误信息，请调用 GetLastError。
必须确保回调函数设置 SetLastError （如果失败）。
Windows Server 2003 和 Windows XP/2000： 如果桌面上没有窗口， GetLastError 将返回 ERROR_INVALID_HANDLE。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/winuser/nf-winuser-enumdesktopwindowss
*/
func EnumDesktopWindows(hDESK windows.Handle, lpfn uintptr, lParam uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procEnumDesktopWindows.Addr(),
		uintptr(hDESK),
		lpfn,
		lParam,
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
EnumThreadWindows
通过将句柄传递到每个窗口，再将传递给应用程序定义的回调函数，枚举与线程关联的所有非子窗口
EnumThreadWindows 一直持续到枚举最后一个窗口或回调函数返回 FALSE

BOOL EnumThreadWindows(

	[in] DWORD       dwThreadId, // 要枚举其窗口的线程的标识符
	[in] WNDENUMPROC lpfn, // 指向应用程序定义的回调函数的指针
	[in] LPARAM      lParam // 要传递给回调函数的应用程序定义值

);

返回值
类型： BOOL
如果回调函数为 dwThreadId 指定的线程中的所有窗口返回 TRUE，则返回值为 TRUE。
如果回调函数在任何枚举窗口上返回 FALSE ，或者如果在 dwThreadId 指定的线程中找不到任何窗口，则返回值为 FALSE

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/winuser/nf-winuser-enumthreadwindows
*/
func EnumThreadWindows(dwThreadId uint32, lpfn uintptr, lParam uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procEnumThreadWindows.Addr(),
		uintptr(dwThreadId),
		lpfn,
		lParam,
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}
