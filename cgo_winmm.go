package xwindows

/*
   #cgo LDFLAGS: -lwinmm
   #include <windows.h>
   #include <mmsystem.h>

   DWORD TimeGetTimeCGO() {
       return timeGetTime();
   }
*/
import "C"

func TimeGetTimeC() uint32 {
	return uint32(C.TimeGetTimeCGO())
}
