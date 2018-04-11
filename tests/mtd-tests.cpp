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
#include <fstream>
#include <string>
#include <vector>
#include <random>
#include <memory>
#include <boost/iostreams/device/mapped_file.hpp>

#include <cstdint>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "debug.h"
#include "mtd.h"
#include "util.h"
#include "exceptions.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#define vector_dump(V) _dump(__FUNCTION__, __LINE__, #V, V.data(), V.size())

#define MTD_TEST_DEV MTD_DEV_BASE "mtd0"
#ifdef MTD_EMULATION
const std::string proc_mtd_file_default_contents(
	"dev:    size   erasesize  name\n"
	"mtd0: 04000000 00010000 \"flash-0\"\n"
	"mtd1: 01c00000 00010000 \"image-a\"\n"
	"mtd2: 01c00000 00010000 \"image-b\"\n"
	"mtd3: 00400000 00010000 \"CONF\"\n"
	"mtd4: 00080000 00010000 \"SEL\"\n"
	"mtd5: 00200000 00010000 \"PNV\"\n"
	"mtd6: 02000000 00001000 \"flash-1\"\n"
);
// when MTD_EMULATION is enable, we need to make sure that the 
// required paths and directories are available and valid
// or the rest of the test is invalid
bool mtd_emulation_env_ok()
{
	struct stat sb;
	// require PROC_CMDLINE (not yet?)
	// require PROC_MTD_FILE
	if (stat(PROC_MTD_FILE, &sb) < 0) {
		if (stat("proc", &sb) < 0) {
			if (mkdir("proc",
						S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH) < 0) {
				return false;
			}
		}
		std::ofstream fout(PROC_MTD_FILE);
		if (!fout.is_open())
			return false;
		fout << proc_mtd_file_default_contents;
		fout.close();
	}
	if (stat(MTD_TEST_DEV, &sb) < 0) {
		if (stat(MTD_DEV_BASE, &sb) < 0) {
			if (mkdir(MTD_DEV_BASE,
						S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH) < 0) {
				return false;
			}
		}
		int fd = open(MTD_TEST_DEV, O_CREAT|O_RDWR,
				S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
		if (fd < 0)
			return false;
		if (ftruncate(fd, DEFAULT_MTD_EMU_SZ) < 0) {
			close(fd);
			return false;
		}
		close(fd);
	}
	return true;
}
#endif

void read_single_test(uint32_t addr, size_t sz)
{
#ifdef MTD_EMULATION
	ASSERT_TRUE(mtd_emulation_env_ok());
#endif
	auto mtd_p = std::make_unique<mtd_type>();
	try {
		mtd_p->open(MTD_TEST_DEV);
	} catch (std::exception &e) {
		FAIL() << "failed to open " << MTD_TEST_DEV;
	}
	// read in the sector a first time
	std::vector<uint8_t> sector_data(sz);
	EXPECT_EQ(mtd_p->read(addr, sector_data), int(sz));
	// read another sector at a different address
	std::vector<uint8_t> temp_sector(sz);
	EXPECT_EQ(mtd_p->read(2*addr, temp_sector), int(sz));
	// re-read the first sector so we can compare
	std::vector<uint8_t> sector_data2(sz);
	EXPECT_EQ(mtd_p->read(addr, sector_data2), int(sz));
	// compare first and second readings
	EXPECT_EQ(sector_data, sector_data2);
}

TEST(NonDestructiveMtdTests, SingleSector4kRead) {
	// read the third 4k ector (0 indexed addresses)
	uint32_t addr = 2 * SMALL_BLOCK_SIZE;
	read_single_test(addr, SMALL_BLOCK_SIZE);
}

TEST(NonDestructiveMtdTests, SingleSector64kRead) {
	uint32_t addr = 2 * BIG_BLOCK_SIZE;
	read_single_test(addr, BIG_BLOCK_SIZE);
}

TEST(NonDestructiveMtdTests, Cross4kSectorRead) {
	// read across the fifth 4k sector boundary (0 indexed addresses)
	uint32_t addr = 4 * SMALL_BLOCK_SIZE - 737;
	read_single_test(addr, SMALL_BLOCK_SIZE);
}

TEST(NonDestructiveMtdTests, Cross64kSectorRead) {
	// read across the fifth 64k sector boundary (0 indexed addresses)
	uint32_t addr = 4 * BIG_BLOCK_SIZE - 15389;
	read_single_test(addr, BIG_BLOCK_SIZE);
}

/* seek back from the end of the device seek_back bytes
 * so in case this possibly destructive test case fails,
 * we still might be able to boot :)
 */
void erase_single_test(uint32_t seek_back, size_t sz, bool require_4k)
{
#ifdef MTD_EMULATION
	ASSERT_TRUE(mtd_emulation_env_ok());
	if (require_4k)
		mtd_use_4k_sectors = 1;
	else
		mtd_use_4k_sectors = 0;
#endif
	auto mtd_p = std::make_unique<mtd_type>();
	try {
		mtd_p->open(MTD_TEST_DEV);
	} catch (std::exception &e) {
		FAIL() << "failed to open " << MTD_TEST_DEV;
	}
	ASSERT_TRUE(!require_4k || mtd_p->is_4k());

	auto addr = mtd_p->size() - seek_back;
	// require that we are working on a 64k capable device (this should ALWAYS be true)
	EXPECT_EQ(mtd_p->erase_size(), BIG_BLOCK_SIZE);
	// read in the second-to-last sector (tricky rounding to account
	// for unaligned erases, which automatically get rounded to erase
	// entire sectors over the addr:addr+len segment)
	auto saved_addr = addr;
	auto saved_sz = sz;
	if (mtd_p->is_4k()) {
		if (saved_addr & SMALL_BLOCK_MASK) {
			saved_sz += block_round(saved_addr, SMALL_BLOCK_SIZE) - saved_addr;
			saved_addr &= ~SMALL_BLOCK_MASK;
		}
		saved_sz = block_round(saved_sz, SMALL_BLOCK_SIZE);
	} else {
		if (saved_addr & BIG_BLOCK_MASK) {
			saved_sz += block_round(saved_addr, BIG_BLOCK_MASK) - saved_addr;
			saved_addr &= ~BIG_BLOCK_MASK;
		}
		saved_sz = block_round(saved_sz, BIG_BLOCK_SIZE);
	}
	std::vector<uint8_t> sector_data(saved_sz);
	EXPECT_EQ(mtd_p->read(saved_addr, sector_data), int(saved_sz));
	// erase the second-to-last sector
	mtd_p->erase(addr, sz);
	// read in the erased sector to see that it is all 0xff
	std::vector<uint8_t> erased_sector(sz);
	EXPECT_EQ(mtd_p->read(addr, erased_sector), int(sz));
	std::vector<uint8_t> ffs(sz, 0xff);
	EXPECT_EQ(erased_sector, ffs);
	// write the saved copy back to the second-to-last sector
	EXPECT_EQ(mtd_p->write_raw(saved_addr, sector_data), int(saved_sz));
	// re-read the sector and see that we wrote out the same data
	std::vector<uint8_t> check_data(saved_sz);
	EXPECT_EQ(mtd_p->read(saved_addr, check_data), int(saved_sz));
	EXPECT_EQ(check_data, sector_data);
}

TEST(PossiblyDestructiveMtdTests, SingleSector4kErase) {
	// this will fail on a system that does not support 4k or is not emulated
	// not ideal, but not sure how to skip a test (without reporting it passed)
	uint32_t seek_back = SMALL_BLOCK_SIZE;
	erase_single_test(seek_back, SMALL_BLOCK_SIZE, true);
}

TEST(PossiblyDestructiveMtdTests, SingleSector4kEraseEmu) {
	uint32_t seek_back = BIG_BLOCK_SIZE + SMALL_BLOCK_SIZE;
	erase_single_test(seek_back, SMALL_BLOCK_SIZE, false);
}

TEST(PossiblyDestructiveMtdTests, SingleSector64kErase) {
	uint32_t seek_back = 2 * BIG_BLOCK_SIZE;
	erase_single_test(seek_back, BIG_BLOCK_SIZE, false);
}

TEST(PossiblyDestructiveMtdTests, CrossSector4kErase) {
	// this will fail on a system that does not support 4k or is not emulated
	// not ideal, but not sure how to skip a test (without reporting it passed)
	uint32_t seek_back = SMALL_BLOCK_SIZE + 737;
	erase_single_test(seek_back, SMALL_BLOCK_SIZE, true);
}

TEST(PossiblyDestructiveMtdTests, CrossSector4kEraseEmu) {
	// this will fail on a system that does not support 4k or is not emulated
	// not ideal, but not sure how to skip a test (without reporting it passed)
	uint32_t seek_back = BIG_BLOCK_SIZE + SMALL_BLOCK_SIZE + 737;
	erase_single_test(seek_back, SMALL_BLOCK_SIZE, false);
}

TEST(PossiblyDestructiveMtdTests, CrossSector64kErase) {
	uint32_t seek_back = 2 * BIG_BLOCK_SIZE + 15389;
	erase_single_test(seek_back, BIG_BLOCK_SIZE, false);
}

/* seek back from end of device and do a write
 * so in case this possibly destructive test case fails,
 * we still might be able to boot :)
 */
void write_single_test(uint32_t seek_back, size_t sz, bool require_4k)
{
#ifdef MTD_EMULATION
	ASSERT_TRUE(mtd_emulation_env_ok());
	if (require_4k)
		mtd_use_4k_sectors = 1;
	else
		mtd_use_4k_sectors = 0;
#endif
	auto mtd_p = std::make_unique<mtd_type>();
	try {
		mtd_p->open(MTD_TEST_DEV);
	} catch (std::exception &e) {
		FAIL() << "failed to open " << MTD_TEST_DEV;
	}
	ASSERT_TRUE(!require_4k || mtd_p->is_4k());

	auto addr = mtd_p->size() - seek_back;
	// require that we are working on a 64k capable device (this should ALWAYS be true)
	EXPECT_EQ(mtd_p->erase_size(), BIG_BLOCK_SIZE);
	// read in the second-to-last sector (tricky rounding to account
	// for unaligned erases, which automatically get rounded to erase
	// entire sectors over the addr:addr+len segment)
	auto saved_addr = addr;
	auto saved_sz = sz;
	if (mtd_p->is_4k()) {
		if (saved_addr & SMALL_BLOCK_MASK) {
			saved_sz += block_round(saved_addr, SMALL_BLOCK_SIZE) - saved_addr;
			saved_addr &= ~SMALL_BLOCK_MASK;
		}
		saved_sz = block_round(saved_sz, SMALL_BLOCK_SIZE);
	} else {
		if (saved_addr & BIG_BLOCK_MASK) {
			saved_sz += block_round(saved_addr, BIG_BLOCK_MASK) - saved_addr;
			saved_addr &= ~BIG_BLOCK_MASK;
		}
		saved_sz = block_round(saved_sz, BIG_BLOCK_SIZE);
	}
	std::vector<uint8_t> sector_data(saved_sz);
	EXPECT_EQ(mtd_p->read(saved_addr, sector_data), int(saved_sz));
	// write some data to the sector (with an implied erase)
	std::random_device rd;
	std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
	std::uniform_int_distribution<uint8_t> dist(0, 255);
	std::vector<uint8_t> rnd_data(sz);
	std::generate(std::begin(rnd_data), std::end(rnd_data), [&]() { return dist(gen); });
	mtd_p->write(addr, rnd_data);
	// read in the written sector to see that it is what was written
	std::vector<uint8_t> written_sector(sz);
	EXPECT_EQ(mtd_p->read(addr, written_sector), int(sz));
	EXPECT_EQ(written_sector, rnd_data);
	// write the saved copy back to the second-to-last sector
	mtd_p->erase(saved_addr, saved_sz);
	EXPECT_EQ(mtd_p->write_raw(saved_addr, sector_data), int(saved_sz));
	// re-read the sector and see that we wrote out the same data
	std::vector<uint8_t> check_data(saved_sz);
	EXPECT_EQ(mtd_p->read(saved_addr, check_data), int(saved_sz));
	EXPECT_EQ(check_data, sector_data);
}

TEST(PossiblyDestructiveMtdTests, SingleSector4kWriteStart) {
	// this will fail on a system that does not support 4k or is not emulated
	// not ideal, but not sure how to skip a test (without reporting it passed)
	uint32_t seek_back = BIG_BLOCK_SIZE;
	write_single_test(seek_back, SMALL_BLOCK_SIZE, true);
}

TEST(PossiblyDestructiveMtdTests, SingleSector4kWriteMiddle) {
	// this will fail on a system that does not support 4k or is not emulated
	// not ideal, but not sure how to skip a test (without reporting it passed)
	uint32_t seek_back = 3*SMALL_BLOCK_SIZE;
	write_single_test(seek_back, SMALL_BLOCK_SIZE, true);
}

TEST(PossiblyDestructiveMtdTests, SingleSector4kWriteEnd) {
	// this will fail on a system that does not support 4k or is not emulated
	// not ideal, but not sure how to skip a test (without reporting it passed)
	uint32_t seek_back = SMALL_BLOCK_SIZE;
	write_single_test(seek_back, SMALL_BLOCK_SIZE, true);
}

TEST(PossiblyDestructiveMtdTests, SingleSector4kWriteStartEmu) {
	// this will fail on a system that does not support 4k or is not emulated
	// not ideal, but not sure how to skip a test (without reporting it passed)
	uint32_t seek_back = 2*BIG_BLOCK_SIZE;
	write_single_test(seek_back, SMALL_BLOCK_SIZE, false);
}

TEST(PossiblyDestructiveMtdTests, SingleSector4kWriteMiddleEmu) {
	// this will fail on a system that does not support 4k or is not emulated
	// not ideal, but not sure how to skip a test (without reporting it passed)
	uint32_t seek_back = 2*BIG_BLOCK_SIZE+3*SMALL_BLOCK_SIZE;
	write_single_test(seek_back, SMALL_BLOCK_SIZE, false);
}

TEST(PossiblyDestructiveMtdTests, SingleSector4kWriteEndEmu) {
	// this will fail on a system that does not support 4k or is not emulated
	// not ideal, but not sure how to skip a test (without reporting it passed)
	uint32_t seek_back = 2*BIG_BLOCK_SIZE+SMALL_BLOCK_SIZE;
	write_single_test(seek_back, SMALL_BLOCK_SIZE, false);
}

TEST(PossiblyDestructiveMtdTests, SingleSector64kWrite) {
	uint32_t seek_back = 2 * BIG_BLOCK_SIZE;
	write_single_test(seek_back, BIG_BLOCK_SIZE, false);
}

TEST(PossiblyDestructiveMtdTests, CrossSector4kWrite) {
	// this will fail on a system that does not support 4k or is not emulated
	// not ideal, but not sure how to skip a test (without reporting it passed)
	uint32_t seek_back = SMALL_BLOCK_SIZE + 737;
	write_single_test(seek_back, SMALL_BLOCK_SIZE, true);
}

TEST(PossiblyDestructiveMtdTests, CrossSector4kWriteEmu) {
	uint32_t seek_back = BIG_BLOCK_SIZE + SMALL_BLOCK_SIZE + 737;
	write_single_test(seek_back, SMALL_BLOCK_SIZE, false);
}

TEST(PossiblyDestructiveMtdTests, CrossSector64kWrite) {
	uint32_t seek_back = 2 * BIG_BLOCK_SIZE + 15389;
	write_single_test(seek_back, BIG_BLOCK_SIZE, false);
}

