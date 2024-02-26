package xwindows

import "syscall"

/*
Calls the callback routine for each installed pagefile in the system.

BOOL EnumPageFilesW(
	[out] PENUM_PAGE_FILE_CALLBACKW pCallBackRoutine,
	[in]  LPVOID                    pContext
	);

If the function succeeds, the return value is TRUE. If the function fails, the return value is FALSE. To get extended error information, call GetLastError.
*/

func EnumPageFilesW(pCallBackRoutine uintptr, pContext uintptr) (value uintptr, err error) {
	r0, _, e1 := syscall.SyscallN(procEnumPageFilesW.Addr(), pCallBackRoutine, pContext)
	value = r0
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}
