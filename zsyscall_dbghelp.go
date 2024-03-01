package xwindows

import (
	"syscall"

	"golang.org/x/sys/windows"
)

/*
EnumerateLoadedModules
枚举指定进程的已加载模块。

BOOL IMAGEAPI EnumerateLoadedModules(

	[in]           HANDLE                       hProcess,
	[in]           PENUMLOADED_MODULES_CALLBACK EnumLoadedModulesCallback,
	[in, optional] PVOID                        UserContext
	);

返回值
如果函数成功，则返回值为 TRUE。
如果函数失败，则返回值为 FALSE。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/dbghelp/nf-dbghelp-enumerateloadedmodules
*/
func EnumerateLoadedModules(hProcess windows.Handle, enumLoadedModulesCallback uintptr, userContext uintptr) (value uintptr, err error) {
	r0, _, e1 := syscall.SyscallN(
		procEnumerateLoadedModules.Addr(),
		uintptr(hProcess),         // 将枚举其模块的进程句柄
		enumLoadedModulesCallback, // 应用程序定义的回调函数
		userContext)               // 可选的用户定义数据。 此值将传递给回调函数
	value = r0
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}
