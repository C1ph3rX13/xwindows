package xwindows

import "syscall"

/*
The AllocADsMem function allocates a block of memory of the specified size.

LPVOID AllocADsMem(
	[in] DWORD cb
	);

Type: LPVOID

When successful, the function returns a non-NULL pointer to the allocated memory. The caller must free this memory when it is no longer required by passing the returned pointer to FreeADsMem.

Returns NULL if not successful. Call ADsGetLastError to obtain extended error status. For more information about error code values, see ADSI Error Codes.
*/

func AllocADsMem(cb uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procAllocADsMem.Addr(), cb)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
The FreeADsMem function frees the memory allocated by AllocADsMem or ReallocADsMem.

BOOL FreeADsMem(
	[in] LPVOID pMem
	);

The function returns TRUE if successful, otherwise it returns FALSE.
*/

func FreeADsMem(pMem uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procFreeADsMem.Addr(), pMem)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}

/*
_Must_inspect_result_
DWORD
WINAPI
I_QueryTagInformation(_In_opt_ LPCWSTR pszMachineName,
	_In_ TAG_INFO_LEVEL 	eInfoLevel,
	_Inout_ PVOID 			pTagInfo
	)
*/

func IQueryTagInformation(pszMachineName uintptr, eInfoLevel uintptr, pTagInfo uintptr) (value uintptr, err error) {
	r1, _, e1 := syscall.SyscallN(procIQueryTagInformation.Addr(), pszMachineName, eInfoLevel, pTagInfo)
	value = r1
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}
