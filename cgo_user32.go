package xwindows

/*
#include <windows.h>

static BOOL EnumThreadWindowsCGO(DWORD dwThreadId, WNDENUMPROC lpfn, LPARAM lParam) {
    return EnumThreadWindows(dwThreadId, lpfn, lParam);


}
*/
import "C"
import "unsafe"

func EnumThreadWindowsC(dwThreadId uint32, lpfn uintptr, lParam uintptr) bool {
	r1 := C.EnumThreadWindowsCGO(
		C.DWORD(dwThreadId),
		(C.WNDENUMPROC)(unsafe.Pointer(lpfn)),
		C.LPARAM(lParam),
	)

	if r1 != 0 {
		return true
	}

	return false
}
