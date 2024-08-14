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
