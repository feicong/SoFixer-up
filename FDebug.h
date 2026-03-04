//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2018/7/4.
//                   Copyright (c) 2018. All rights reserved.
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
// 文件功能：提供统一日志输出宏，打印函数名与行号以便定位问题。

#ifndef ANDDBG_ALOG_H
#define ANDDBG_ALOG_H

//#if !defined(NDEBUG)
#if true

// 字符串化宏
#define TOSTR(fmt) #fmt
// 日志前缀格式：函数名+行号
#define FLFMT TOSTR([%s:%d])
#define FNLINE TOSTR(\n)

// 统一日志宏
#define FLOGE(fmt, ...) printf(FLFMT fmt FNLINE, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define FLOGD(fmt, ...) printf(FLFMT fmt FNLINE, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define FLOGW(fmt, ...) printf(FLFMT fmt FNLINE, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define FLOGI(fmt, ...) printf(FLFMT fmt FNLINE, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define FLOGV(fmt, ...) printf(FLFMT fmt FNLINE, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define FLOGE(fmt, ...)
#define FLOGD(fmt, ...)
#define FLOGW(fmt, ...)
#define FLOGI(fmt, ...)
#define FLOGV(fmt, ...)
#endif

#endif //ANDDBG_ALOG_H
