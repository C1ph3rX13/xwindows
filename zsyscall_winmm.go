package xwindows

import "syscall"

/*
TimeGetTime
timeGetTime 函数检索系统时间（以毫秒为单位）。 系统时间是 Windows 启动以来经过的时间。

DWORD timeGetTime();

返回值
返回系统时间（以毫秒为单位）。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/timeapi/nf-timeapi-timegettime
*/
func TimeGetTime() (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procTimeGetTime.Addr())
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}
