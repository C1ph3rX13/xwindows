package xwindows

import (
	"syscall"

	"golang.org/x/sys/windows"
)

/*
Enumerates the loaded modules for the specified process.

BOOL IMAGEAPI EnumerateLoadedModules(
[in]           HANDLE                       hProcess,
[in]           PENUMLOADED_MODULES_CALLBACK EnumLoadedModulesCallback,
[in, optional] PVOID                        UserContext
);

If the function succeeds, the return value is TRUE.

If the function fails, the return value is FALSE. To retrieve extended error information, call GetLastError.
*/

func EnumerateLoadedModules(hProcess windows.Handle, enumLoadedModulesCallback uintptr, userContext uintptr) (value uintptr, err error) {
	r0, _, e1 := syscall.SyscallN(procEnumerateLoadedModules.Addr(), uintptr(hProcess), enumLoadedModulesCallback, userContext)
	value = r0
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}
