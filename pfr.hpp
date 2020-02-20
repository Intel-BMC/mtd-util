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
 * Abstract: PFR image capabilities
 */

#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <boost/iostreams/device/mapped_file.hpp>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

#include "debug.h"
#include "exceptions.h"
#include "mtd.h"

static constexpr size_t pfr_blk_size = 0x1000; /* 4k block size */
static constexpr uint32_t blk0_magic = 0xb6eafd19;
struct blk0
{
    uint32_t magic;
    uint32_t pc_length;
    uint32_t pc_type;
    uint32_t rsvd1;
    uint8_t sha256[32];
    uint8_t sha384[48];
    uint8_t pad[32];
} __attribute__((packed));

static constexpr uint32_t blk1_magic = 0xf27f28d7;
struct blk1
{
    uint32_t magic;
    uint32_t rsvd[3];
    uint8_t data[880]; /* signature chain (length varies, but extended with
                          padding so blk0+blk1 is 1024 bytes) */
} __attribute__((packed));
static constexpr size_t blk0blk1_size = sizeof(blk0) + sizeof(blk1);

static constexpr uint32_t root_key_magic = 0xa747a046;
struct key_entry
{
    uint32_t magic;
    uint32_t curve;
    uint32_t permissions;
    uint32_t key_id;
    uint8_t key_x[48];
    uint8_t key_y[48];
    uint8_t resvd[20];
} __attribute__((packed));

static constexpr uint32_t csk_key_magic = 0x14711c2f;
static constexpr uint32_t curve_secp256r1 = 0xc7b88c74;
static constexpr uint32_t curve_secp384r1 = 0x08f07b47;
static constexpr uint32_t sig_magic_secp256r1 = 0xde64437d;
static constexpr uint32_t sig_magic_secp384r1 = 0xea2a50e9;
struct csk_entry
{
    key_entry csk;
    uint32_t sig_magic;
    uint8_t sig_r[48];
    uint8_t sig_s[48];
} __attribute__((packed));

static constexpr uint32_t pfm_magic = 0x02b3ce1d;
static constexpr size_t pfm_block_size = 128;
struct pfm
{
    uint32_t magic;
    uint8_t svn;
    uint8_t bkc;
    uint16_t pfm_revision;
    uint32_t resvd;
    uint8_t oem_data[16];
    uint32_t length;
    // pfm_data
    // padding to 128-byte boundary
} __attribute__((packed));

struct spi_region
{
    uint8_t type;
    uint8_t mask;
    uint16_t hash_info;
    uint32_t resvd;
    uint32_t start;
    uint32_t end;
    // hash 1 if present
    // hash 2 if present
} __attribute__((packed));
static constexpr uint8_t sha256_present = 0x01;
static constexpr uint8_t sha384_present = 0x02;
static constexpr size_t sha256_size = (256 / 8);
static constexpr size_t sha384_size = (384 / 8);

struct smbus_rule
{
    uint8_t type;
    uint32_t resvd;
    uint8_t bus;
    uint8_t rule;
    uint8_t addr;
    uint8_t whitelist[32];
} __attribute__((packed));
static constexpr uint8_t type_spi_region = 1;
static constexpr uint8_t type_smbus_rule = 2;

static constexpr uint32_t pbc_magic = 0x5f404243;
struct pbc
{
    uint32_t magic;
    uint32_t version;
    uint32_t page_size;
    uint32_t pattern_size;
    uint32_t pattern;
    uint32_t bitmap_size;
    uint32_t payload_length;
    uint8_t resvd[100];
    // active
    // compression
    // payload
} __attribute__((packed));

bool pfr_authenticate(const std::string& filename)
{
    boost::iostreams::mapped_file file(filename,
                                       boost::iostreams::mapped_file::readonly);
    const auto blk0_header = reinterpret_cast<const blk0*>(file.const_data());
    // check for basic shape
    if (file.size() < blk0blk1_size ||
        (blk0_header->pc_length + blk0blk1_size) != file.size())
    {
        FWERROR("bad file size");
        return false;
    }
    // check blk0 magic
    if (blk0_header->magic != blk0_magic)
    {
        FWERROR("bad blk0 magic");
        return false;
    }
    // check pc_length/pc_type
    // calculate image hash (save for later when decrypting signature)
    return true;
}

template <typename deviceClassT>
bool pfr_write(mtd<deviceClassT>& dev, const std::string& filename,
               bool recovery_reset)
{
    if (!pfr_authenticate(filename))
    {
        return false;
    }
    boost::iostreams::mapped_file file(filename,
                                       boost::iostreams::mapped_file::readonly);
    auto map_base = reinterpret_cast<const uint8_t*>(file.const_data());
    auto offset = reinterpret_cast<const uint8_t*>(file.const_data());
    auto img_size = reinterpret_cast<const uint32_t>(file.size());

    FWDEBUG("file mapped " << file.size() << " bytes at 0x" << std::hex
                           << reinterpret_cast<unsigned long>(offset));

    /* if its non-PFR to PFR migration/factory reset then
     * we also have to erase static regions and to flash the recovery region
     * with compressed image.
     */
    if (recovery_reset)
    {
        constexpr uint32_t rc_img_addr = 0x2a00000;
        constexpr uint32_t rc_img_size = 0x2000000;
        cbspan rc_img_data(offset, offset + img_size);
        // erase static regions before writing.
        dev.erase(0x0, 0x80000);             // u-boot - 512K
        dev.erase(0xb00000, 0x1f00000);      // fitImage - 31MB
        dev.erase(rc_img_addr, rc_img_size); // recovery - 32MB
        // write compressed image to recovery region
        dev.write_raw(rc_img_addr, rc_img_data);
    }

    // walk the bitmap, erase and copy
    offset += blk0blk1_size * 2; // one blk0blk1 for package, one for pfm
    auto pfm_hdr = reinterpret_cast<const pfm*>(offset);
    FWDEBUG("pfm header at " << std::hex << pfm_hdr
                             << " (magic:" << pfm_hdr->magic << ")");
    FWDEBUG("pfm length is 0x" << std::hex << pfm_hdr->length);
    size_t pfm_size = block_round(pfm_hdr->length, pfm_block_size);
    cbspan pfm_data(offset - blk0blk1_size, offset + pfm_size);
    offset += pfm_size;
    auto pbc_hdr = reinterpret_cast<const pbc*>(offset);
    FWDEBUG("pbc header at " << std::hex << pbc_hdr
                             << " (magic:" << pbc_hdr->magic << ")");
    FWDEBUG("pbc bitmap size 0x" << std::hex << pbc_hdr->bitmap_size);
    offset += sizeof(pbc);
    auto act_map = reinterpret_cast<const uint8_t*>(offset);
    FWDEBUG("active map at 0x" << std::hex
                               << reinterpret_cast<unsigned long>(act_map));
    offset += pbc_hdr->bitmap_size / 8;
    auto pbc_map = reinterpret_cast<const uint8_t*>(offset);
    FWDEBUG("pbc map at 0x" << std::hex
                            << reinterpret_cast<unsigned long>(pbc_map));

    // copy the pfm manually (not part of the compression bitmap)
    constexpr size_t pfm_address = 0x80000;
    constexpr size_t pfm_region_size = 0x20000;
    dev.erase(pfm_address, pfm_region_size);
    dev.write_raw(pfm_address, pfm_data);
    // set offset to the beginning of the compressed data
    offset += pbc_hdr->bitmap_size / 8;
    uint32_t wr_count = 1;
    uint32_t er_count = 1;
    for (uint32_t blk = 0; blk < pbc_hdr->bitmap_size; blk += wr_count)
    {
        if ((blk % 8) == 0)
        {
            wr_count = 1;
            er_count = 1;
            if ((blk + 8) < pbc_hdr->bitmap_size)
            {
                uint32_t b8 = blk / 8;
                // try to do 64k first
                // 64k erase is fine if all erase bits are set and either
                // all copy bits or no copy bits are set
                er_count =
                    (act_map[b8] == 0xff && act_map[b8 + 1] == 0xff) ? 16 : 1;
                wr_count = ((pbc_map[b8] == 0xff && pbc_map[b8 + 1] == 0xff) ||
                            (pbc_map[b8] == 0 && pbc_map[b8 + 1] == 0))
                               ? 16
                               : 1;
            }
        }
        bool erase = (act_map[blk / 8] >> (7 - blk % 8)) & 1;
        bool copy = (pbc_map[blk / 8] >> (7 - blk % 8)) & 1;
        if (!erase)
        {
            continue;
        }
        if (!copy)
        {
            // skip erase if the block is in an unsigned segment
            auto region_offset = reinterpret_cast<const uint8_t*>(pfm_hdr + 1);
            auto region_end = region_offset + pfm_size;
            bool region_is_unsigned = true;
            while (region_offset < region_end)
            {
                auto region =
                    reinterpret_cast<const spi_region*>(region_offset);
                if (region->type == type_spi_region)
                {
                    // check if the first block is within this region
                    if (region->start <= blk * pfr_blk_size)
                    {
                        // check if the last block is within this region
                        if ((blk + er_count) * pfr_blk_size <= region->end)
                        {
                            region_is_unsigned = (region->hash_info == 0);
                            break;
                        }
                        // check if a single block is within this region
                        if ((blk + 1) * pfr_blk_size <= region->end)
                        {
                            er_count = 1;
                            region_is_unsigned = (region->hash_info == 0);
                            break;
                        }
                    }
                    region_offset +=
                        sizeof(spi_region) +
                        (region->hash_info & sha256_present ? sha256_size : 0) +
                        (region->hash_info & sha384_present ? sha384_size : 0);
                }
                else if (region->type == type_smbus_rule)
                {
                    region_offset += sizeof(smbus_rule);
                }
                else
                {
                    break;
                }
            }
            if (region_is_unsigned && !recovery_reset)
            {
                FWDEBUG("skipping erase on unsigned block"
                        << (er_count == 16 ? "s" : "") << " @" << std::hex
                        << pfr_blk_size * blk);
                continue;
            }
        }
        if (blk % 16 == 0)
        {
            if (er_count == 1)
            {
                FWDEBUG("block " << std::hex << pfr_blk_size * blk
                                 << " has erase size 1; erasing 64k");
                er_count = 16;
            }
            FWDEBUG("erase(" << std::hex << pfr_blk_size * blk << ", "
                             << pfr_blk_size * er_count << ")");
            dev.erase(pfr_blk_size * blk, pfr_blk_size * er_count);
        }

        if (copy)
        {
            cbspan data(offset, offset + pfr_blk_size * wr_count);
            // DUMP(PRINT_ERROR, data);
            FWDEBUG("write(" << std::hex << pfr_blk_size * blk << ", "
                             << pfr_blk_size * wr_count << "), offset = 0x"
                             << (offset - map_base));
            dev.write_raw(pfr_blk_size * blk, data);

            offset += pfr_blk_size * wr_count;
        }
    }
    return true;
}
