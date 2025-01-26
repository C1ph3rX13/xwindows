package xwindows

import "syscall"

/*
AllocADsMem 函数分配指定大小的内存块。

LPVOID AllocADsMem(

	[in] DWORD cb
	);

返回值
类型： LPVOID
如果成功，该函数将返回指向已分配内存的非 NULL 指针。 当不再需要此内存时，调用方必须通过将返回的指针传递给 FreeADsMem 来释放此内存。
如果未成功，则返回 NULL 。 调用 ADsGetLastError 以获取扩展错误状态。 有关错误代码值的详细信息，请参阅 ADSI 错误代码。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/adshlp/nf-adshlp-allocadsmem
*/
func AllocADsMem(cb uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procAllocADsMem.Addr(),
		cb, // 类型：DWORD 包含要分配的大小（以字节为单位）
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
FreeADsMem 函数释放由 AllocADsMem 或 ReallocADsMem 分配的内存。

BOOL FreeADsMem(

	[in] LPVOID pMem
	);

返回值
类型： BOOL
如果成功，函数将返回 TRUE ，否则返回 FALSE。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/adshlp/nf-adshlp-freeadsmem
*/
func FreeADsMem(pMem uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procFreeADsMem.Addr(),
		pMem, // 类型： LPVOID 指向要释放的内存的指针。 此内存必须已使用 AllocADsMem 或 ReallocADsMem 函数进行分配。
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
ReallocADsMem 函数重新分配并复制现有内存块

LPVOID ReallocADsMem(

	[in] LPVOID pOldMem, // 指向要复制的内存的指针
	[in] DWORD  cbOld, // 要复制的内存的大小（以字节为单位）
	[in] DWORD  cbNew  // 要分配的内存的大小（以字节为单位）

);

返回值
类型： LPVOID
成功后，函数返回指向新分配内存的指针。 否则返回 NULL。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/adshlp/nf-adshlp-reallocadsmem
*/
func ReallocADsMem(pOldMem uintptr, cbOld uint32, cbNew uint32) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procReallocADsMem.Addr(),
		pOldMem,
		uintptr(cbOld),
		uintptr(cbNew),
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}
