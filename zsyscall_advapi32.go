package xwindows

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

/*
I_QueryTagInformation

_Must_inspect_result_
DWORD
WINAPI
I_QueryTagInformation(_In_opt_ LPCWSTR pszMachineName,

	_In_ TAG_INFO_LEVEL 	eInfoLevel,
	_Inout_ PVOID 			pTagInfo
	);
*/
func I_QueryTagInformation(pszMachineName uintptr, eInfoLevel uintptr, pTagInfo uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procIQueryTagInformation.Addr(),
		pszMachineName,
		eInfoLevel,
		pTagInfo,
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
RegDeleteTreeA
以递归方式删除指定键的子项和值

LSTATUS RegDeleteTreeA(

	// 打开的注册表项的句柄, 必须已使用以下访问权限打开密钥: DELETE、KEY_ENUMERATE_SUB_KEYS 和 KEY_QUERY_VALUE
	[in]           HKEY   hKey,
	// 键的名称。 此键必须是 由 hKey 参数标识的密钥的子项。 如果此参数为 NULL，则删除 hKey 的子项和值。
	[in, optional] LPCSTR lpSubKey
	);

如果函数成功，则返回值为 ERROR_SUCCESS。
如果函数失败，则返回值为 Winerror.h 中定义的非零错误代码。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/winreg/nf-winreg-regdeletetreea
*/
func RegDeleteTreeA(key windows.Handle, subKey string) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(
		procRegDeleteTreeA.Addr(),
		uintptr(key),
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(subKey))),
	)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}
