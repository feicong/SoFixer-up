//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2021/1/5.
//===----------------------------------------------------------------------===//
// ElfReader for Obfuscated so file
//===----------------------------------------------------------------------===//
// 文件功能：定义面向dump/壳场景的读取器扩展接口，支持程序头修正与动态段回填。
#ifndef SOFIXER_OBELFREADER_H
#define SOFIXER_OBELFREADER_H

#include "ElfReader.h"
class ElfRebuilder;

// ObElfReader：面向内存dump场景的ELF读取器
class ObElfReader: public ElfReader {
public:
    // 释放动态段缓存
    ~ObElfReader() override;
    // the phdr informaiton in dumped so may be incorrect,
    // try to fix it
    // 修正dump so中的程序头（常见于壳导致的段信息异常）
    void FixDumpSoPhdr();

    // 重载加载流程，支持从base so补动态段
    bool Load() override;
    // 从base so中提取动态段内容
    bool LoadDynamicSectionFromBaseSource();

    // 设置dump so的内存基址
    void setDumpSoBaseAddr(Elf_Addr base) { dump_so_base_ = base; }

    // 设置原始base so路径
    void setBaseSoName(const char* name) {
        baseso_ = name;
    }

//    void GetDynamicSection(Elf_Dyn** dynamic, size_t* dynamic_count, Elf_Word* dynamic_flags) override;
    // 检查动态段是否已经位于任意可加载段内
    bool haveDynamicSectionInLoadableSegment();

private:
    // 把读取到的动态段写入当前加载缓冲并修正对应phdr
    void ApplyDynamicSection();

    // dump so在内存中的基址
    Elf_Addr dump_so_base_ = 0;

    // 原始base so路径
    const char* baseso_ = nullptr;

    // 从base so提取出的动态段缓存
    void* dynamic_sections_ = nullptr;
    size_t dynamic_count_ = 0;
    Elf_Word dynamic_flags_ = 0;

    friend class ElfRebuilder;

};


#endif //SOFIXER_OBELFREADER_H
