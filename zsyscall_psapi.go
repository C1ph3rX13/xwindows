package xwindows

import "syscall"

/*
EnumPageFilesW
为系统中每个已安装的页面文件调用回调例程

BOOL EnumPageFilesW(

	[out] PENUM_PAGE_FILE_CALLBACKW pCallBackRoutine,
	[in]  LPVOID                    pContext
	);

返回值
如果函数成功，则返回值为 TRUE。
如果函数失败，则返回值为 FALSE。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/psapi/nf-psapi-enumpagefilesw
*/
func EnumPageFilesW(pCallBackRoutine uintptr, pContext uintptr) (value uintptr, err error) {
	r0, _, e1 := syscall.SyscallN(
		procEnumPageFilesW.Addr(),
		pCallBackRoutine, // 指向为每个页面文件调用的例程的指针
		pContext,         // 传递给回调例程的用户定义数据
	)
	value = r0
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}
