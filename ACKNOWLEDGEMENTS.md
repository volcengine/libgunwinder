# Acknowledgements

[English](ACKNOWLEDGEMENTS.md) | [简体中文](ACKNOWLEDGEMENTS.zh-CN.md)

libgunwinder benefits from the following open-source projects and prior work.

## uthash

This repository vendors `include/uthash.h` and `include/utlist.h` from [uthash](https://troydhanson.github.io/uthash/), created by Troy D. Hanson.

The vendored headers keep their original BSD-style copyright and license notices. Redistribution of those headers must preserve those notices.

## elfutils

libgunwinder links against elfutils libraries, including `libelf` and `libdw`.
Parts of libgunwinder's DWARF and stack unwinding behavior were developed with
conceptual guidance from [elfutils](https://sourceware.org/elfutils/) and
cross-checked against libdw behavior. libgunwinder keeps its own data
structures, parser/cache layout, and stack-snapshot unwind flow.

Upstream elfutils describes its licensing as:

- libraries and backends: dual GPL-2.0-or-later / LGPL-3.0-or-later
- utilities: GPL-3.0-or-later

libgunwinder uses `LGPL-3.0-or-later`, which aligns with the LGPLv3-or-later option available to elfutils libraries and backends.

No elfutils source files are vendored or copied in this repository. If future
changes import or adapt elfutils source code, keep the relevant file-level
copyright and license notices and reassess the license obligations for those
files.

## Links

- [README](README.md)
- [Project notice](NOTICE)
- [License](LICENSE)
