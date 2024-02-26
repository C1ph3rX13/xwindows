# xwindows

Powerful `golang.org/x/sys/windows`

## Description

[variant](https://github.com/C1ph3rX13/variant) 项目衍生库

1. 基于`golang.org/x/sys/windows`
2. 使用`syscall.SyscallN()`作为`syscall`的调用，增加了绝大多数`Go loader`所使用的函数
3. 包含了[variant](https://github.com/C1ph3rX13/variant) 项目所有的函数，同步更新

## Uasge

```go
xwindows.EnumPageFilesW()
```

