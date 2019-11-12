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

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
// file emulation uses these
#include <fcntl.h>
#include <mtd/mtd-user.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <thread>

#include "debug.h"
#include "exceptions.h"
#include "mtd.h"
#include "util.h"

#define SMALL_PER_BIG_BLOCKS (BIG_BLOCK_SIZE / SMALL_BLOCK_SIZE)
#define SMALL_PER_BIG_MASK (SMALL_PER_BIG_BLOCKS - 1)

int hw_mtd::open(const std::string& path)
{
    std::string dname = path.substr(path.find_last_of("/") + 1);
    _fd = ::open(path.c_str(), O_RDWR);
    if (_fd < 0)
        THROW(FileIOError() << boost::errinfo_errno(errno));
    // find erase size and size
    std::string line;
    std::ifstream proc_mtd(PROC_MTD_FILE);
    std::getline(proc_mtd, line);
    while (std::getline(proc_mtd, line))
    {
        std::string dev, sz, esz, name;
        std::istringstream iss(line);
        if (!(iss >> dev >> sz >> esz >> name))
        {
            continue;
        }
        dev.pop_back();
        if (dev != dname)
            continue;
        _size = std::stoul(sz, nullptr, 16);
        _erase_size = std::stoul(esz, nullptr, 16);
    }
    return _fd;
}

void hw_mtd::erase(uint32_t addr, size_t len)
{
    FWDEBUG2("addr: " << std::hex << addr << ", len: " << len);
    erase_info_t eraser;
    eraser.start = addr;
    eraser.length = len;
    if (ioctl(_fd, MEMERASE, &eraser) < 0)
        THROW(FileIOError() << boost::errinfo_errno(errno));
}

int hw_mtd::write_raw(uint32_t addr, const cbspan& in_buf)
{
    int br;
    if (lseek(_fd, addr, SEEK_SET) < 0)
        THROW(FileIOError() << boost::errinfo_errno(errno));
    br = ::write(_fd, in_buf.data(), in_buf.size());
    if (br < 0)
        THROW(FileIOError() << boost::errinfo_errno(errno));
    return br;
}

int file_mtd_emulation::open(const std::string& path)
{
    struct stat sb;

    _fd = ::open(path.c_str(), O_RDWR | O_CREAT,
                 S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (_fd < 0)
        THROW(FileIOError() << boost::errinfo_errno(errno));
    if (fstat(_fd, &sb) < 0)
    {
        // truncate to a default size
        if (ftruncate(_fd, DEFAULT_MTD_EMU_SZ) < 0)
            THROW(FileIOError() << boost::errinfo_errno(errno));
        _size = DEFAULT_MTD_EMU_SZ;
    }
    else
    {
        _size = sb.st_size;
    }
    return _fd;
};

void file_mtd_emulation::erase(uint32_t addr, size_t len)
{
    int br;
    FWDEBUG2("addr: " << std::hex << addr << ", len: " << len);
    std::vector<uint8_t> ffs(len, 0xff);
    if (lseek(_fd, addr, SEEK_SET) < 0)
        THROW(FileIOError() << boost::errinfo_errno(errno));
    br = ::write(_fd, ffs.data(), ffs.size());
    if (br < 0)
        THROW(FileIOError() << boost::errinfo_errno(errno));
    // pretend that this actually takes some time....
    // std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

// this particular function is more complex than the hardware one
// because writing to nor flash is an AND operation; meaning
// the result can only clear the bit, it cannot set it.
// setting the bit require erase (empty nor is 0xff).
// so we must read in the current value, AND it, and write it back.
int file_mtd_emulation::write_raw(uint32_t addr, const cbspan& in_buf)
{
    int br;
    if (lseek(_fd, addr, SEEK_SET) < 0)
        THROW(FileIOError() << boost::errinfo_errno(errno));
    std::vector<uint8_t> nor(in_buf.size());
    br = ::read(_fd, nor.data(), nor.size());
    if (br < 0)
        THROW(FileIOError() << boost::errinfo_errno(errno));
    std::transform(nor.begin(), nor.end(), in_buf.begin(), nor.begin(),
                   std::bit_and<uint8_t>());
    if (lseek(_fd, addr, SEEK_SET) < 0)
        THROW(FileIOError() << boost::errinfo_errno(errno));
    br = ::write(_fd, nor.data(), nor.size());
    if (br < 0)
        THROW(FileIOError() << boost::errinfo_errno(errno));
    return br;
}

template <typename deviceClassT>
mtd<deviceClassT>::mtd() : _impl(), _path()
{
}

template <typename deviceClassT>
void mtd<deviceClassT>::open(const std::string& path)
{
    if (path.length() == 0)
    {
        THROW(InvalidMtdDevice());
    }
    else
    {
        _path = path;
    }

    _fd = _impl.open(_path);
    if (!_impl.size() || !_impl.erase_size())
        THROW(InvalidMtdDevice());
    FWINFO(_path << ": " << (_impl.size() >> 20) << "MB");
}

template <typename deviceClassT>
mtd<deviceClassT>::~mtd()
{
}

template <typename deviceClassT>
int mtd<deviceClassT>::read(uint32_t addr, std::vector<uint8_t>& out_buf)
{
    int br;
    if (lseek(_fd, addr, SEEK_SET) < 0)
        THROW(FileIOError() << boost::errinfo_errno(errno));
    br = ::read(_fd, out_buf.data(), out_buf.size());
    if (br < 0)
        THROW(FileIOError() << boost::errinfo_errno(errno));
    return br;
}

template <typename deviceClassT>
int mtd<deviceClassT>::write(uint32_t addr, const cbspan& in_buf)
{
    unsigned int buf_idx;
    unsigned int first_block, last_block;
    size_t end, len = in_buf.size();
    const uint8_t* buf = in_buf.data();
    std::vector<uint8_t> buffer(BIG_BLOCK_SIZE);

    end = addr + len;

    FWDEBUG("(" << std::hex << addr << ", " << (void*)in_buf.data() << ", "
                << in_buf.size() << ")");
    if (end > _impl.size())
    {
        FWCRITICAL("not enough space to write "
                   << in_buf.size() << " bytes at offset " << std::hex << addr);
        return 3;
    }
    first_block = (addr & ~SMALL_BLOCK_MASK) / SMALL_BLOCK_SIZE;
    last_block = ((addr + len - 1) & ~SMALL_BLOCK_MASK) / SMALL_BLOCK_SIZE;

    FWINFO("writing blocks " << first_block / SMALL_PER_BIG_BLOCKS << "."
                             << (first_block & SMALL_PER_BIG_MASK) << ".."
                             << last_block / SMALL_PER_BIG_BLOCKS << "."
                             << (last_block & SMALL_PER_BIG_MASK)
                             << " inclusive (" << len << " bytes)");

    buf_idx = 0;
    while (addr < end)
    {
        uint32_t block_size;
        unsigned int block_addr;
        uint32_t ci_idx, ci_len; // copy in index and length

        FWDEBUG2("addr = " << std::hex << addr << ", buf_idx = " << buf_idx
                           << ", end = " << end);
        // initial determiniation of block size based on start
        if (addr & BIG_BLOCK_MASK)
        {
            // starting in middle of large sector, possibly small block
            // we need to read in [start of block]..addr into buffer
            // so we don't overwrite that data
            if (_impl.is_4k())
            {
                // if flash is 4k erase, no need to emulate it
                block_addr = addr & ~SMALL_BLOCK_MASK;
                block_size = SMALL_BLOCK_SIZE;
            }
            else
            {
                // no 4k erase, emulate
                block_addr = addr & ~BIG_BLOCK_MASK;
                block_size = BIG_BLOCK_SIZE;
            }
        }
        else
        {
            block_addr = addr; // beginning address is already block-aligned
            if (_impl.is_4k() && (end - addr) < BIG_BLOCK_SIZE)
            {
                // if flash is 4k erase, no need to emulate it
                block_size = SMALL_BLOCK_SIZE;
            }
            else
            {
                // no 4k erase, emulate
                block_size = BIG_BLOCK_SIZE;
            }
        }
        ci_idx = addr - block_addr;
        ci_len = (end - block_addr) - ci_idx;

        // possibly reduce block size based on capabilities and end address
        if (ci_len < block_size)
        {
            // working on last partial sector(s)
            if (_impl.is_4k())
            {
                block_size = SMALL_BLOCK_SIZE;
            }
        }
        else
        {
            ci_len = block_size;
        }
        if ((ci_idx + ci_len) > block_size)
            ci_len = block_size - ci_idx;

        buffer.resize(block_size);
        FWDEBUG2("block_size=" << std::hex << block_size << ", block_addr="
                               << block_addr << ", buf_idx=" << buf_idx
                               << ", ci_idx=" << ci_idx
                               << ", ci_len=" << ci_len);
        if (ci_idx != 0 || ci_len != block_size)
        {
            // must read in a block
            mtd::read(block_addr, buffer);
            FWDEBUG2("std::copy(" << std::hex << (void*)buf << '+' << buf_idx
                                  << ", " << (void*)buf << '+' << buf_idx << '+'
                                  << ci_len << ", " << (void*)buffer.data()
                                  << '+' << ci_idx);
            std::copy(buf + buf_idx, buf + buf_idx + ci_len,
                      buffer.data() + ci_idx);
        }
        else
        {
            FWDEBUG2("buf max = " << std::hex << len << ", access at "
                                  << buf_idx << ".." << buf_idx + block_size);
            // buffer = std::vector<uint8_t>(&buf[buf_idx],
            //        &buf[buf_idx + block_size]);
            std::copy(&buf[buf_idx], &buf[buf_idx + block_size],
                      std::begin(buffer));
        }
        erase(block_addr, block_size);
        write_raw(block_addr, buffer);
        addr = block_addr + block_size;
        buf_idx += ci_len;
    }
    FWDEBUG("cleaning up.  Copied " << std::dec << buf_idx << " (" << std::hex
                                    << buf_idx << ") bytes");
    return 0;
}

template <typename deviceClassT>
int mtd<deviceClassT>::write_raw(uint32_t addr, const cbspan& in_buf)
{
    return _impl.write_raw(addr, in_buf);
}

template <typename deviceClassT>
void mtd<deviceClassT>::erase(uint32_t addr, size_t len)
{
    FWDEBUG2("addr: " << std::hex << addr << ", len: " << len);
    if (_impl.is_4k())
    {
        if (addr & SMALL_BLOCK_MASK)
        {
            len += block_round(addr, SMALL_BLOCK_SIZE) - addr;
            addr &= ~SMALL_BLOCK_MASK;
        }
        len = block_round(len, SMALL_BLOCK_SIZE);
    }
    else
    {
        if (addr & BIG_BLOCK_MASK)
        {
            len += block_round(addr, BIG_BLOCK_MASK) - addr;
            addr &= ~BIG_BLOCK_MASK;
        }
        len = block_round(len, BIG_BLOCK_SIZE);
    }
    _impl.erase(addr, len);
    FWDEBUG2(std::hex << "erased " << addr << " +" << len);
}

#ifdef MTD_EMULATION
int mtd_use_4k_sectors = 0;

/* forward declarations of templated types */
template mtd<file_mtd_emulation>::mtd();
template mtd<file_mtd_emulation>::~mtd();
template void mtd<file_mtd_emulation>::open(const std::string& path);
template int mtd<file_mtd_emulation>::read(uint32_t addr,
                                           std::vector<uint8_t>& out_buf);
template int mtd<file_mtd_emulation>::write(uint32_t addr,
                                            const cbspan& in_buf);
template int mtd<file_mtd_emulation>::write_raw(uint32_t addr,
                                                const cbspan& in_buf);
template void mtd<file_mtd_emulation>::erase(uint32_t addr, size_t len);
template size_t mtd<file_mtd_emulation>::size(void) const;
#else  /* ! MTD_EMULATION */
template mtd<hw_mtd>::mtd();
template mtd<hw_mtd>::~mtd();
template void mtd<hw_mtd>::open(const std::string& path);
template int mtd<hw_mtd>::read(uint32_t addr, std::vector<uint8_t>& out_buf);
template int mtd<hw_mtd>::write(uint32_t addr, const cbspan& in_buf);
template int mtd<hw_mtd>::write_raw(uint32_t addr, const cbspan& in_buf);
template void mtd<hw_mtd>::erase(uint32_t addr, size_t len);
template size_t mtd<hw_mtd>::size(void) const;
#endif /* MTD_EMULATION */
