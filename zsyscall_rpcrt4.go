package xwindows

import "syscall"

/*
The UuidFromString function converts a string to a UUID.

Return value
RPC_S_OK: The call succeeded.
RPC_S_INVALID_STRING_UUID: The string UUID is invalid.


RPC_STATUS UuidFromStringA(
	RPC_CSTR StringUuid,
	UUID     *Uuid
	);

Link: https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-uuidfromstringa
*/

func UuidFromStringA(stringUuid uintptr, uuid uintptr) (value uintptr, err error) {
	r0, _, e1 := syscall.SyscallN(procUuidFromStringA.Addr(), stringUuid, uuid)
	value = r0
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}
