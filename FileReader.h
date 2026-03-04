//===------------------------------------------------------------*- C++ -*-===//
//
//                     Created by F8LEFT on 2021/1/5.
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//
// 文件功能：提供跨平台文件打开、定位和读取能力，供ELF解析阶段统一调用。
#ifndef SOFIXER_FILEREADER_H
#define SOFIXER_FILEREADER_H

#include "macros.h"
#include "FDebug.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <limits>

// FileReader：跨平台文件读取封装，支持大文件偏移读取
class FileReader {
public:
    // 仅记录路径，不立即打开
    FileReader(const char* name): source(name){}
    // 析构时自动关闭文件
    ~FileReader() {
        Close();
    }
    // 打开文件并获取文件大小
    bool Open() {
        if (IsValid()) {
            return false;
        }
        fp = fopen(source, "rb");
        if (fp == nullptr) {
            return false;
        }
#if defined(_WIN32)
        if (_fseeki64(fp, 0, SEEK_END) != 0) {
            Close();
            return false;
        }
        auto end = _ftelli64(fp);
        if (end < 0) {
            Close();
            return false;
        }
        file_size = static_cast<uint64_t>(end);
        if (_fseeki64(fp, 0, SEEK_SET) != 0) {
            Close();
            return false;
        }
#else
        if (fseeko(fp, 0, SEEK_END) != 0) {
            Close();
            return false;
        }
        auto end = ftello(fp);
        if (end < 0) {
            Close();
            return false;
        }
        file_size = static_cast<uint64_t>(end);
        if (fseeko(fp, 0, SEEK_SET) != 0) {
            Close();
            return false;
        }
#endif
        return true;
    }
    // 关闭文件句柄
    bool Close() {
        if (IsValid()) {
            auto err = fclose(fp);
            fp = nullptr;
            return err == 0;
        }
        return false;
    }
    // 判断文件句柄是否有效
    bool IsValid() {
        return fp != nullptr;
    }
    // 获取源文件路径
    const char* getSource() {
        return source;
    }
    // 从指定偏移读取len字节；offset缺省时按当前文件指针读取
    size_t Read(void *addr, size_t len, uint64_t offset = std::numeric_limits<uint64_t>::max()) {
        if (!IsValid()) {
            return 0;
        }
        if (offset != std::numeric_limits<uint64_t>::max()) {
#if defined(_WIN32)
            if (offset > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) ||
                _fseeki64(fp, static_cast<int64_t>(offset), SEEK_SET) != 0) {
                FLOGE("\"%s\" seek failed at %llx", source, static_cast<unsigned long long>(offset));
                return 0;
            }
#else
            if (offset > static_cast<uint64_t>(std::numeric_limits<off_t>::max()) ||
                fseeko(fp, static_cast<off_t>(offset), SEEK_SET) != 0) {
                FLOGE("\"%s\" seek failed at %llx", source, static_cast<unsigned long long>(offset));
                return 0;
            }
#endif
        }
        auto rc = fread(addr, 1, len, fp);
        if (rc != len) {
            if (offset == std::numeric_limits<uint64_t>::max()) {
                FLOGE("\"%s\" has no enough data for %zx bytes, not a valid file or you need to dump more data", source, len);
            } else {
                FLOGE("\"%s\" has no enough data at %llx:%zx, not a valid file or you need to dump more data",
                      source,
                      static_cast<unsigned long long>(offset),
                      len);
            }
            return rc;
        }
        return rc;
    }
    // 返回文件总大小
    uint64_t FileSize() {
        return file_size;
    }
private:
    FILE* fp = nullptr;
    const char* source = nullptr;
    uint64_t file_size = 0;
};

#endif //SOFIXER_FILEREADER_H
