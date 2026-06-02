# 致谢

[English](ACKNOWLEDGEMENTS.md) | [简体中文](ACKNOWLEDGEMENTS.zh-CN.md)

libgunwinder 感谢以下开源项目和已有工作。

## uthash

本仓库 vendored 了 [uthash](https://troydhanson.github.io/uthash/) 项目中的 `include/uthash.h` 和 `include/utlist.h`，该项目作者为 Troy D. Hanson。

这些 vendored 头文件保留了原始 BSD-style 版权和许可证声明。重新分发这些头文件时需要保留相应声明。

## elfutils

libgunwinder 链接了 elfutils 的 `libelf`、`libdw` 等库。部分 DWARF 和栈
回溯行为开发时参考了 [elfutils](https://sourceware.org/elfutils/) 的概念指导，
并与 libdw 行为做过交叉校验。libgunwinder 保留自己的数据结构、parser/cache
布局和 stack-snapshot 回溯流程。

elfutils 上游说明其许可证策略为：

- libraries 和 backends：GPL-2.0-or-later / LGPL-3.0-or-later 双许可证
- utilities：GPL-3.0-or-later

libgunwinder 使用 `LGPL-3.0-or-later`，与 elfutils libraries/backends 可用的 LGPLv3-or-later 选项对齐。

本仓库未 vendored 或复制 elfutils 源文件。如果后续变更导入或改写 elfutils
源码，需要保留对应文件级版权和许可证声明，并重新确认这些文件的许可证义务。

## 链接

- [README 中文](README.zh-CN.md)
- [项目声明](NOTICE)
- [许可证](LICENSE)
