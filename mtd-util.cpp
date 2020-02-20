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
 * Abstract: MTD utility application
 */

#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <boost/iostreams/device/mapped_file.hpp>
#include <cstdint>
#include <iostream>
#include <pfr.hpp>
#include <string>
#include <vector>

#include "debug.h"
#include "exceptions.h"
#include "mtd.h"

template <typename deviceClassT>
int erase_flash(mtd<deviceClassT>& dev, size_t start, size_t len)
{
    if ((start + len) > dev.size())
    {
        std::cerr << "not enough space to erase at offset (" << std::hex
                  << start << " + " << len << " > " << dev.size() << ")"
                  << std::endl;
        return 3;
    }
    dev.erase(start, len);
    return 0;
}

template <typename deviceClassT>
int buf_to_flash(mtd<deviceClassT>& dev, const uint8_t* fbuf, size_t start,
                 size_t len)
{
    if ((start + len) > dev.size())
    {
        std::cerr << "not enough space to write at offset (" << std::hex
                  << start << " + " << len << " > " << dev.size() << ")"
                  << std::endl;
        return 3;
    }

    std::vector<uint8_t> contents(fbuf, fbuf + len);
    dev.write(start, contents);

    return 0;
}

template <typename deviceClassT>
int cp_to_flash(mtd<deviceClassT>& dev, std::string& filename, size_t start)
{
    boost::iostreams::mapped_file file(filename,
                                       boost::iostreams::mapped_file::readonly);

    std::vector<uint8_t> contents(file.const_data(),
                                  file.const_data() + file.size());

    dev.write(start, contents);

    return 0;
}

template <typename deviceClassT>
int cp_to_file(mtd<deviceClassT>& dev, std::string& filename, size_t start,
               size_t len)
{
    if ((start + len) > dev.size())
    {
        std::cerr << "access beyond end of flash (" << std::hex << start
                  << " + " << len << " > " << dev.size() << ")" << std::endl;
    }

    boost::iostreams::mapped_file_params params(filename);
    params.new_file_size = len;
    params.flags = boost::iostreams::mapped_file::readwrite;
    boost::iostreams::mapped_file file(params);

    std::vector<uint8_t> contents(file.size());
    dev.read(start, contents);
    std::copy(contents.begin(), contents.end(), file.data());

    return 0;
}

void dump_buf(size_t flash_addr, const gsl::span<const uint8_t>& buf)
{
    unsigned int i = 0, l;
    std::stringstream hex, ascii;
    auto cb = buf.begin();

    /*  0         1         2         3         4         5         6
     *  0123456789012345678901234567890123456789012345678901234567890123456789
     *  0000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
     */

    std::cout << "dumping " << buf.length() << " bytes from " << std::hex
              << flash_addr << '\n';
    hex << std::hex << std::setfill('0');
    while (cb != buf.end())
    {
        hex.str("");
        ascii.str("");
        hex << std::setw(7) << (flash_addr + i) << ": ";
        for (l = 0; l < 16 && (cb != buf.end()); l++)
        {
            hex << std::setw(2) << (unsigned int)*cb;
            if (l & 1)
                hex << ' ';
            if (isprint(*cb))
                ascii << (char)(*cb);
            else
                ascii << '.';
            cb++;
            i++;
        }
        std::cout << std::left << std::setw(50) << hex.str() << ascii.str()
                  << std::endl;
    }
    std::cout << std::setw(0);
}

template <typename deviceClassT>
int dump_flash(mtd<deviceClassT>& dev, size_t start, size_t len)
{
    int ret = 0;

    if ((start + len) > dev.size())
    {
        std::cerr << "access beyond end of flash (" << std::hex << start
                  << " + " << len << " > " << dev.size() << ")" << std::endl;
        return 3;
    }

    std::vector<uint8_t> mbuf(len);
    dev.read(start, mbuf);
    dump_buf(start, mbuf);

    return ret;
}

std::string locate_active_device()
{
    // TODO: lookup the real device.
    return "/dev/mtd1";
}

std::string locate_backup_device()
{
    // TODO: lookup the real device.
    return "/dev/mtd2";
}

typedef enum
{
    ACTION_NONE = 0,
    ACTION_ERASE,
    ACTION_CP_TO_FILE,
    ACTION_CP_TO_FLASH,
    ACTION_WRITE_TO_FLASH,
    ACTION_DUMP,
    ACTION_PFR_AUTH,
    ACTION_PFR_WRITE,
    ACTION_MAX,
} ACTION;

void usage(void)
{
    std::cerr
        << "Usage: mtd-util [-v] [-d <mtd-device>] e[rase] start +len\n"
           "       mtd-util [-v] [-d <mtd-device>] e[rase] start end\n"
           "       mtd-util [-v] [-d <mtd-device>] c[p] file offset\n"
           "       mtd-util [-v] [-d <mtd-device>] [-f] c[p] offset file len\n"
           "       mtd-util [-v] [-d <mtd-device>] w[rite] offset Xx [Xx ...]\n"
           "       mtd-util [-v] [-d <mtd-device>] d[ump] offset [len]\n"
           "       mtd-util [-v] [-d <mtd-device>] p[fr] a[uthenticate] file\n"
           "       mtd-util [-v] [-d <mtd-device>] [-r] p[fr] w[rite] file\n"
           "            * for ease of use, commands can be abbreviated\n"
           "              to the first letter of the command: c, d, p, etc.\n"
           "            * -v for verbose, can be used multiple times\n"
           "            * mtd-device defaults to /dev/mtd0\n"
           "            * all addresses, offsets, and values are in hex\n"
           "            * dump len defaults to 256 bytes\n"
           "            * cp to flash does read/erase/cp/write to preserve "
           "flash\n"
           "            * erase rounds to nearest 4kB boundaries\n"
           "            * -f allows a forced overwrite of an existing file\n"
           "            * -r reset erase-only regions for PFR write\n";
    exit(1);
}

const std::string default_device(MTD_DEV_BASE "mtd0");
const std::string active_device("active");
const std::string backup_device("backup");

int main(int argc, char* argv[])
{
    struct stat sb;
    size_t start = 0, len = 0;
    int ret = 0;
    uint8_t* buf = NULL;
    char* endptr;
    std::string flash_dev;
    std::string filename;
    int optind = 1; /* skip argv[0] */
    bool force_overwrite = false;
    bool recovery_reset = false;
    ACTION action = ACTION_NONE;
    dbg_level verbosity = PRINT_ERROR;

    while (optind < argc && argv[optind][0] == '-')
    {
        if (argv[optind][1] == 'd')
        {
            flash_dev = argv[++optind];
            if (flash_dev == active_device)
                flash_dev = locate_active_device();
            else if (flash_dev == backup_device)
                flash_dev = locate_backup_device();
        }
        else if (argv[optind][1] == 'f')
        {
            force_overwrite = true;
        }
        else if (argv[optind][1] == 'r')
        {
            recovery_reset = true;
        }
        else if (argv[optind][1] == 'v')
        {
            verbosity = static_cast<dbg_level>(static_cast<int>(verbosity) + 1);
        }
        optind++;
    }
    if (flash_dev.length() == 0)
        flash_dev = default_device;

    if ((optind + 2) > argc)
        usage();

    fw_update_set_dbg_level(verbosity);

    if (argv[optind][0] == 'e')
    {
        int offset = 0;
        action = ACTION_ERASE;
        /* parse erase args */
        optind++;
        if ((optind + 2) != argc)
            usage();
        start = strtoul(argv[optind], &endptr, 16);
        if (*endptr)
        {
            std::cerr << "failed to parse '" << argv[optind] << "' as integer"
                      << std::endl;
            return 1;
        }
        optind++;
        if (argv[optind][0] == '+')
            offset = 1;
        len = strtoul(argv[optind] + offset, &endptr, 16);
        if (*endptr)
        {
            std::cerr << "failed to parse '" << argv[optind] + offset
                      << "' as integer" << std::endl;
            return 1;
        }
        if (!offset)
            len -= start;
    }
    else if (argv[optind][0] == 'c')
    {
        optind++;
        // printf("cp mode, optind = %d, argc = %d\n", optind, argc);
        if ((optind + 2) == argc)
        {
            // puts("file to flash");
            /* file to flash mode */
            action = ACTION_CP_TO_FLASH;
            if (stat(argv[optind], &sb) < 0)
            {
                std::cerr << argv[optind] << " does not exist" << std::endl;
                return 1;
            }
            filename = argv[optind];
            optind++;
            start = strtoul(argv[optind], &endptr, 16);
            if (*endptr)
            {
                std::cerr << "failed to parse '" << argv[optind]
                          << "' as integer" << std::endl;
                return 1;
            }
        }
        else if ((optind + 3) == argc)
        {
            // puts("flash to file");
            action = ACTION_CP_TO_FILE;
            start = strtoul(argv[optind], &endptr, 16);
            if (*endptr)
            {
                std::cerr << "failed to parse '" << argv[optind]
                          << "' as integer" << std::endl;
                return 1;
            }
            optind++;
            if (!force_overwrite && stat(argv[optind], &sb) == 0)
            {
                std::cerr << argv[optind]
                          << " exists, cowardly refusing to overwrite"
                          << std::endl;
                return 1;
            }
            filename = argv[optind];
            optind++;
            len = strtoul(argv[optind], &endptr, 16);
            if (*endptr)
            {
                std::cerr << "failed to parse '" << argv[optind]
                          << "' as integer" << std::endl;
                return 1;
            }
        }
        optind++;
    }
    else if (argv[optind][0] == 'w')
    {
        action = ACTION_WRITE_TO_FLASH;
        optind++;
        start = strtoul(argv[optind], &endptr, 16);
        if (*endptr)
        {
            std::cerr << "failed to parse '" << argv[optind] << "' as integer"
                      << std::endl;
            return 1;
        }
        optind++;
        len = argc - optind;
        buf = new uint8_t[len];
        if (buf == NULL)
            return 1;
        while (optind < argc)
        {
            buf[optind + len - argc] = strtoul(argv[optind], &endptr, 16);
            if (*endptr)
            {
                std::cerr << "failed to parse '" << argv[optind]
                          << "' as integer" << std::endl;
                delete buf;
                return 1;
            }
            optind++;
        }
    }
    else if (argv[optind][0] == 'd')
    {
        action = ACTION_DUMP;
        optind++;
        len = 256;
        start = strtoul(argv[optind], &endptr, 16);
        if (*endptr)
        {
            std::cerr << "failed to parse '" << argv[optind] << "' as integer"
                      << std::endl;
            return 1;
        }
        optind++;
        if (optind < argc)
        {
            len = strtoul(argv[optind], &endptr, 16);
            if (*endptr)
            {
                std::cerr << "failed to parse '" << argv[optind]
                          << "' as integer" << std::endl;
                return 1;
            }
        }
    }
    else if (argv[optind][0] == 'p')
    {
        if ((optind + 2) >= argc)
        {
            usage();
        }
        optind++;
        if (argv[optind][0] == 'a')
        {
            action = ACTION_PFR_AUTH;
        }
        else if (argv[optind][0] == 'w')
        {
            action = ACTION_PFR_WRITE;
        }
        optind++;
        filename = argv[optind];
    }
    else
    {
        usage();
    }
#ifdef MTD_EMULATION
    mtd<file_mtd_emulation> dev;
#else
    mtd<hw_mtd> dev;
#endif
    try
    {
        dev.open(flash_dev);

        switch (action)
        {
            case ACTION_ERASE:
                ret = erase_flash(dev, start, len);
                break;
            case ACTION_CP_TO_FILE:
                ret = cp_to_file(dev, filename, start, len);
                break;
            case ACTION_CP_TO_FLASH:
                ret = cp_to_flash(dev, filename, start);
                break;
            case ACTION_WRITE_TO_FLASH:
                ret = buf_to_flash(dev, buf, start, len);
                delete buf;
                break;
            case ACTION_DUMP:
                ret = dump_flash(dev, start, len);
                break;
            case ACTION_PFR_AUTH:
                ret = !pfr_authenticate(filename);
                break;
            case ACTION_PFR_WRITE:
                ret = !pfr_write(dev, filename, recovery_reset);
                break;
            default:
                usage();
        }
    }
    catch (boost::exception& e)
    {
        std::cerr << diagnostic_information(e) << std::endl;
        ret = 1;
    }

    return ret;
}
