# xwindows

Go interface to DLLs functions

Base on  `golang.org/x/sys/windows`

## Note

Please do not consider this code, particularly the autogenerated code, as stable. Identifiers names may still be subject to change.

## Description

This package makes selected `DLLs` functions directly available in Go programs. At the moment, types and functions for accessing kernel objects and the Registry are included. The goal is to, eventually, cover all available functions.

## What’s Changed

### 2024.8.14

1. 新增`mkwinsyscall`工具实现API代码生成 - 待完善
2. 新增`actived, advapi, winmm`等DLL
3. 修复多个API参数类型不对应

### 2024.3.1

1. 修复多个函数的Bug
2. 添加文档
3. 新增多个未公开的函数

### 2024.2.26

[variant](https://github.com/C1ph3rX13/variant) 项目衍生库

1. 基于`golang.org/x/sys/windows`
2. 使用`syscall.SyscallN()`作为`syscall`的调用，增加了绝大多数`Go loader`所使用的函数
3. 包含了[variant](https://github.com/C1ph3rX13/variant) 项目所有的函数，同步更新

## Uasge

```go
xwindows.EnumPageFilesW()
```

