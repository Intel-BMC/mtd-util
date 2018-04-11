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
 * Abstract: MTD test utility
 */

#include <iostream>
#include <string>
#include <vector>
#include <boost/iostreams/device/mapped_file.hpp>

#include <cstdint>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "debug.h"
#include "mtd.h"
#include "exceptions.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#if 0
int erase_flash(mtd &dev, size_t start, size_t len)
{
	if ((start + len) > dev.size())
	{
		std::cerr << "not enough space to erase at offset ("
			<< std::hex << start << " + " << len
			<< " > " << dev.size() << ")" << std::endl;
		return 3;
	}
	dev.erase(start, len);
	return 0;
}

int buf_to_flash(mtd &dev, const uint8_t *fbuf, size_t start, size_t len)
{
	if ((start + len) > dev.size())
	{
		std::cerr << "not enough space to write at offset ("
			<< std::hex << start << " + " << len
			<< " > " << dev.size() << ")" << std::endl;
		return 3;
	}

	std::vector<uint8_t> contents(fbuf, fbuf + len);
	dev.write(start, contents);

	return 0;
}

int cp_to_flash(mtd &dev, const char *filename, size_t start)
{
	boost::iostreams::mapped_file file(filename, boost::iostreams::mapped_file::readonly);

	std::vector<uint8_t> contents(file.const_data(), file.const_data()+file.size());

	dev.write(start, contents);

	return 0;
}

int cp_to_file(mtd &dev, const char *filename, size_t start, size_t len)
{
	if ((start + len) > dev.size()) {
		std::cerr << "access beyond end of flash ("
			<< std::hex << start << " + " << len
			<< " > " << dev.size() << ")" << std::endl;
	}

	boost::iostreams::mapped_file_params params(filename);
	params.new_file_size = len;
	params.flags = boost::iostreams::mapped_file::readwrite;
	boost::iostreams::mapped_file file(params);

	std::vector<uint8_t> contents(file.data(), file.data()+file.size());
	dev.read(start, contents);

	return 0;
}

int dump_flash(mtd &dev, size_t start, size_t len)
{
	int ret = 0;

	if ((start + len) > dev.size())
	{
		std::cerr << "access beyond end of flash ("
			<< std::hex << start << " + " << len
			<< " > " << dev.size() << ")" << std::endl;
		return 3;
	}

	std::vector<uint8_t> mbuf(len);
	dev.read(start, mbuf);
	_dump("mtd-util", 0, dev.name().c_str(), mbuf.data(), len);

	return ret;
}

typedef enum
{
	ACTION_NONE = 0,
	ACTION_ERASE,
	ACTION_CP_TO_FILE,
	ACTION_CP_TO_FLASH,
	ACTION_WRITE_TO_FLASH,
	ACTION_DUMP,
	ACTION_MAX,
} ACTION;

void usage(void)
{
	std::cerr << "Usage: mtd-util [ -d <mtd-device> ] e[rase] start +len\n"
	             "       mtd-util [ -d <mtd-device> ] e[rase] start end\n"
	             "       mtd-util [ -d <mtd-device> ] c[p] file offset\n"
	             "       mtd-util [ -d <mtd-device> ] [-f] c[p] offset file len\n"
	             "       mtd-util [ -d <mtd-device> ] w[rite] offset Xx [Xx ...]\n"
	             "       mtd-util [ -d <mtd-device> ] d[ump] offset [len]\n"
	             "            * mtd-device defaults to /dev/mtd0\n"
	             "            * all addresses, offsets, and values are in hex\n"
	             "            * dump len defaults to 256 bytes\n"
	             "            * cp to flash does read/erase/cp/write to preserve flash\n"
	             "            * erase rounds to nearest 4kB boundaries\n"
	             "            * -f allows a forced overwrite of an existing file\n";
	exit(1);
}

int main(int argc, char *argv[])
{
	struct stat sb;
	size_t start, len;
	int ret = 0;
	uint8_t *buf = NULL;
	char *endptr;
	const char *flash_dev = "/dev/mtd0";
	const char *filename;
	int optind = 1; /* skip argv[0] */
	int force_overwrite = 0;
	ACTION action = ACTION_NONE;

	while (optind < argc && argv[optind][0] == '-') {
		if (argv[optind][1] == 'd')
		{
			flash_dev = argv[++optind];
		}
		else if (argv[optind][1] == 'f')
		{
			force_overwrite = 1;
		}
		optind++;
	}

	if ((optind + 2) > argc)
		usage();

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
			std::cerr << "failed to parse '" << argv[optind]
				<< "' as integer" << std::endl;
			return 1;
		}
		optind++;
		if (argv[optind][0] == '+')
			offset = 1;
		len = strtoul(argv[optind]+offset, &endptr, 16);
		if (*endptr)
		{
			std::cerr << "failed to parse '" << argv[optind]+offset
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
					<< " exists, cowardly refusing to overwrite" << std::endl;
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
			std::cerr << "failed to parse '" << argv[optind]
				<< "' as integer" << std::endl;
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
			std::cerr << "failed to parse '" << argv[optind]
				<< "' as integer" << std::endl;
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
	else
	{
		usage();
	}
	mtd dev(flash_dev);
	try {
		dev.open();

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
		default:
			usage();
		}
	} catch (boost::exception &e) {
		std::cerr << diagnostic_information(e) << std::endl;
		ret = 1;
	}

	return ret;
}

#endif /* 0 */

TEST(AvahiTest, GetHostName) {
	
}


