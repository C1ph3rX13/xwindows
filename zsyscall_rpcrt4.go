package xwindows

import (
	"syscall"
	"unsafe"
)

/*
UuidFromStringA
UuidFromString 函数将字符串转换为 UUID。

RPC_STATUS UuidFromStringA(

	RPC_CSTR StringUuid,
	UUID     *Uuid
	);

返回值
RPC_S_OK: 调用成功。
RPC_S_INVALID_STRING_UUID: 字符串 UUID 无效。

Link: https://learn.microsoft.com/zh-cn/windows/win32/api/rpcdce/nf-rpcdce-uuidfromstringa
*/
func UuidFromStringA(stringUuid *byte, uuid uintptr) (value uintptr, err error) {
	r0, _, e1 := syscall.SyscallN(
		procUuidFromStringA.Addr(),
		uintptr(unsafe.Pointer(stringUuid)), // 指向 UUID 的字符串表示形式的指针
		uuid,                                // 返回指向二进制形式的 UUID 的指针
	)
	value = r0
	if value == 0 {
		err = errnoErr(e1)
	}
	return
}
