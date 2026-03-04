//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2017/6/3.
//                   Copyright (c) 2017. All rights reserved.
//===----------------------------------------------------------------------===//
//  Parse and read elf file.
//===----------------------------------------------------------------------===//
// 文件功能：定义ELF读取器接口，负责加载流程与程序头/动态段访问能力。

#ifndef SOFIXER_ELFREADER_H
#define SOFIXER_ELFREADER_H

#include "macros.h"
#include "FileReader.h"

#include <cstdint>
#include <cstddef>
#include <memory.h>

class ElfRebuilder;
class ObElfReader;



class ElfReader {
public:
    // 初始化读取器状态，不做任何IO操作
    ElfReader();
    // 释放已分配的程序头缓冲、加载缓冲和文件句柄
    virtual ~ElfReader();

    // 执行完整的ELF加载流程（头校验->程序头读取->段加载->定位已加载phdr）
    virtual bool Load();
    // 设置输入文件路径并打开文件
    bool setSource(const char* source);

    // 返回程序头数量
    size_t phdr_count() { return phdr_num_; }
    // 返回已分配的加载起始地址
    uint8_t * load_start() { return load_start_; }
    // 返回加载地址范围大小
    Elf_Addr load_size() { return load_size_; }
    // 返回加载偏移基址（load_bias）
    uint8_t * load_bias() { return load_bias_; }
    // 返回内存中的程序头表地址
    const Elf_Phdr* loaded_phdr() { return loaded_phdr_; }

    // 返回原始ELF头快照
    const Elf_Ehdr* record_ehdr() { return &header_; }

protected:
    // 读取ELF文件头
    bool ReadElfHeader();
    // 校验ELF魔数、位数和字节序等基础属性
    bool VerifyElfHeader();
    // 读取程序头表
    bool ReadProgramHeader();
    // 预留加载地址空间（可附加padding）
    bool ReserveAddressSpace(uint32_t padding_size = 0);
    // 将所有PT_LOAD段读入内存缓冲
    bool LoadSegments();
    // 在已加载镜像中定位有效的程序头表地址
    bool FindPhdr();
    // 校验给定程序头地址是否位于可加载段内
    bool CheckPhdr(uint8_t *);
    // If I have change anything in phtr_table_, just apply the chagnes into loaded_phdr.
    // 将临时程序头表回写到加载镜像中的程序头区域
    void ApplyPhdrTable();

    // 解析动态段并返回动态表指针、数量和标志
    virtual void GetDynamicSection(Elf_Dyn** dynamic, size_t* dynamic_count, Elf_Word* dynamic_flags);

    // 输入文件路径
    const char* name_;
    // 文件读取器
    FileReader* source_ = nullptr;

    // ELF头缓存
    Elf_Ehdr header_;
    // 程序头数量
    size_t phdr_num_;

    // 程序头原始缓冲
    void* phdr_mmap_;
    // 程序头表地址
    Elf_Phdr* phdr_table_;
    // 程序头表字节大小
    Elf_Addr phdr_size_;

    // First page of reserved address space.
    // 已分配加载缓冲起始地址
    uint8_t * load_start_;
    // Size in bytes of reserved address space.
    // 已分配加载范围大小
    Elf_Addr load_size_;
    // 额外预留的padding大小
    Elf_Addr pad_size_;
    // 输入文件大小
    size_t file_size;
    // Load bias.
    // 运行时虚拟地址到缓冲地址的偏移
    uint8_t * load_bias_;

    // Loaded phdr.
    // 加载后可直接访问的程序头表地址
    const Elf_Phdr* loaded_phdr_;


private:

    friend class ElfRebuilder;
    friend class ObElfReader;

};



// 计算所有PT_LOAD段覆盖的页对齐地址范围大小
size_t
phdr_table_get_load_size(const Elf_Phdr* phdr_table,
                         size_t phdr_count,
                         Elf_Addr* min_vaddr = NULL,
                         Elf_Addr* max_vaddr = NULL);

// 恢复只读段保护属性（当前实现保留接口）
int
phdr_table_protect_segments(const Elf_Phdr* phdr_table,
                            int               phdr_count,
                            uint8_t * load_bias);

// 临时放宽段保护属性（当前实现保留接口）
int
phdr_table_unprotect_segments(const Elf_Phdr* phdr_table,
                              int               phdr_count,
                              uint8_t * load_bias);

// 对GNU RELRO区域设置保护（当前实现保留接口）
int
phdr_table_protect_gnu_relro(const Elf_Phdr* phdr_table,
                             int               phdr_count,
                             uint8_t *load_bias);


// 读取.ARM.exidx段地址和项数量
int phdr_table_get_arm_exidx(const Elf_Phdr* phdr_table,
                         int               phdr_count,
                         uint8_t * load_bias,
                         Elf_Addr**      arm_exidx,
                         unsigned*         arm_exidix_count);

// 从程序头中定位动态段并输出动态表信息
void
phdr_table_get_dynamic_section(const Elf_Phdr* phdr_table,
                               int               phdr_count,
                               uint8_t * load_bias,
                               Elf_Dyn**       dynamic,
                               size_t*           dynamic_count,
                               Elf_Word*       dynamic_flags);


#endif //SOFIXER_ELFREADER_H
