package xwindows

import "errors"

var (
	// 内存操作类错误
	ErrAllocFailed    = errors.New("memory allocation failed")
	ErrFreeFailed     = errors.New("memory release failed")
	ErrLockFailed     = errors.New("memory locking failed")
	ErrProtectFailed  = errors.New("memory protection failed")
	ErrInvalidAddress = errors.New("invalid memory address")

	// 权限相关错误
	ErrAccessDenied      = errors.New("access denied")
	ErrPrivilegeRequired = errors.New("privilege not held")

	// 参数验证类错误
	ErrInvalidHandle    = errors.New("invalid handle")
	ErrInvalidParameter = errors.New("invalid parameter")
	ErrInvalidSize      = errors.New("invalid size parameter")
	ErrNullPointer      = errors.New("null pointer reference")

	// 系统API通用错误
	ErrAPICallFailed  = errors.New("system API call failed")
	ErrTimeout        = errors.New("operation timed out")
	ErrNotImplemented = errors.New("function not implemented")

	// 资源管理类错误
	ErrResourceNotFound = errors.New("specified resource not found")
	ErrResourceExists   = errors.New("resource already exists")
	ErrResourceBusy     = errors.New("resource is in use")

	// 安全相关错误
	ErrInvalidSignature = errors.New("invalid digital signature")
	ErrMemoryNotExec    = errors.New("memory is not executable")

	// 进程/线程操作错误
	ErrProcessCreate   = errors.New("process creation failed")
	ErrThreadOperation = errors.New("thread operation failed")

	// 系统状态错误
	ErrInsufficientBuffer = errors.New("buffer size insufficient")
	ErrNotReady           = errors.New("system not in ready state")
)
