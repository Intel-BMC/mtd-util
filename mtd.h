/*
 * MIT License
 *
 * Copyright (c) 2017 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 *
 * Abstract: MTD interface
 */

#ifndef __CPP_MTD_H__
#define __CPP_MTD_H__

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "util.h" // cbspan type

#define BIG_BLOCK_SIZE (64 * 1024)
#define SMALL_BLOCK_SIZE (4 * 1024)
#define BIG_BLOCK_MASK (BIG_BLOCK_SIZE - 1)
#define SMALL_BLOCK_MASK (SMALL_BLOCK_SIZE - 1)

#ifdef MTD_EMULATION
extern int mtd_use_4k_sectors;
#endif

class hw_mtd
{
  protected:
    size_t _size;
    int _erase_size;
    int _is_4k;
    int _fd;

  public:
    hw_mtd() : _size(0), _erase_size(0), _is_4k(0), _fd(-1)
    {
    }
    ~hw_mtd()
    {
        if (_fd >= 0)
            ::close(_fd);
    }

    int open(const std::string& path);
    void erase(uint32_t addr, size_t len);
    int write_raw(uint32_t addr, const cbspan& in_buf);

    int erase_size() const
    {
        return _erase_size;
    }
    size_t size() const
    {
        return _size;
    }
    int is_4k() const
    {
        return _is_4k;
    }
};

#define DEFAULT_MTD_EMU_SZ (16 * 1024 * 1024)
class file_mtd_emulation
{
  protected:
    size_t _size;
    int _is_4k;
    int _fd;

  public:
#ifdef MTD_EMULATION
    file_mtd_emulation() : _size(0), _is_4k(mtd_use_4k_sectors), _fd(-1)
    {
    }
#else
    file_mtd_emulation() : _size(0), _is_4k(0), _fd(-1)
    {
    }
#endif
    ~file_mtd_emulation()
    {
        if (_fd >= 0)
            ::close(_fd);
    }

    int open(const std::string& path);
    void erase(uint32_t addr, size_t len);
    int write_raw(uint32_t addr, const cbspan& in_buf);

    int erase_size() const
    {
        return (64 * 1024);
    }
    size_t size() const
    {
        return _size;
    }
    int is_4k() const
    {
        return _is_4k;
    }
};

template <typename deviceClassT>
class mtd
{
  protected:
    deviceClassT _impl;
    std::string _path;
    int _fd;

  public:
    typedef std::shared_ptr<mtd> ptr;
    mtd();
    ~mtd();

    /* after creating, one must call open, which may throw things */
    void open(const std::string& path);

    /* read into a buffer out_buf.size() bytes */
    int read(uint32_t addr, std::vector<uint8_t>& out_buf);
    /* write with an implied erase */
    int write(uint32_t addr, const cbspan& in_buf);
    /* write without an erase */
    int write_raw(uint32_t addr, const cbspan& in_buf);
    void erase(uint32_t addr, size_t len);
    size_t erase_size(void) const
    {
        return _impl.erase_size();
    }
    size_t size(void) const
    {
        return _impl.size();
    }
    size_t is_4k(void) const
    {
        return _impl.is_4k();
    }
};

#ifdef MTD_EMULATION
typedef mtd<file_mtd_emulation> mtd_type;
#define PROC_MTD_FILE "proc/mtd"
#define MTD_DEV_BASE "dev/"
#else /* !MTD_EMULATION */
typedef mtd<hw_mtd> mtd_type;
#define PROC_MTD_FILE "/proc/mtd"
#define MTD_DEV_BASE "/dev/"
#endif /* MTD_EMULATION */
#define MTD_DEV_MTD0 MTD_DEV_BASE "mtd0"

#endif /* __MTD_H__ */
