/*
 * MIT License
 *
 * Copyright (c) 2020 Intel Corporation
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

#include "pfr.hpp"

#include <fcntl.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <fstream>

static const void* base_addr = NULL;
static unsigned int image_offset(const void* thing)
{
    return static_cast<unsigned int>(static_cast<const uint8_t*>(thing) -
                                     static_cast<const uint8_t*>(base_addr));
}

/**
 * @brief Class to handle non-consecutive hashing
 */
class Hash
{
  public:
    Hash(const EVP_MD* dgst, const cbspan& expected) :
        ctx{}, hash(EVP_MAX_MD_SIZE), expected(expected)
    {
        ctx = EVP_MD_CTX_new();
        if (!ctx)
        {
            throw std::bad_alloc();
        }
        EVP_MD_CTX_init(ctx);
        EVP_DigestInit_ex(ctx, dgst, nullptr);
    }
    ~Hash()
    {
        EVP_MD_CTX_free(ctx);
    }
    void update(const uint8_t* data, size_t len)
    {
        if (finalized)
        {
            throw std::logic_error("update after finalize");
        }
        EVP_DigestUpdate(ctx, data, len);
    }
    const std::vector<uint8_t>& digest() const
    {
        if (finalized)
        {
            return hash;
        }
        finalized = true;
        unsigned int len = hash.size();
        EVP_DigestFinal_ex(ctx, hash.data(), &len);
        hash.resize(len);
        return hash;
    }
    bool verify() const
    {
        digest();
        bool match = std::equal(hash.cbegin(), hash.cend(), expected.cbegin(),
                                expected.cend());
        if (!match)
        {
            auto expected_ = &expected[0];
            auto computed = &hash[0];
            DUMP(PRINT_ERROR, expected_, expected.size());
            DUMP(PRINT_ERROR, computed, hash.size());
        }
        return match;
    }

  private:
    mutable bool finalized = false;
    EVP_MD_CTX* ctx;
    mutable std::vector<uint8_t> hash;
    const cbspan expected;
};

/**
 * @brief This function hashes data with SHA384
 *
 * @param data pointer to the start address of data to hash
 * @param len length of data to hash
 * @param buffer to store output digest
 *
 * @return void
 */
static void hash_sha384(const uint8_t* data, size_t len, uint8_t* digest)
{
    unsigned int digest_sz = SHA384_DIGEST_LENGTH;
    EVP_Digest(data, len, digest, &digest_sz, EVP_sha384(), nullptr);
}

/**
 * @brief This function hashes data and compares to an expected hash
 *
 * @param expected pointer to the sha384 hash
 * @param data pointer to the start address of data to hash
 * @param len length of data to hash
 *
 * @return true if this data hashes to expected; false, otherwise
 */
static bool verify_sha384(const uint8_t* expected, const uint8_t* data,
                          size_t len)
{
    uint8_t digest[SHA384_DIGEST_LENGTH];
    hash_sha384(data, len, digest);
    bool match = std::equal(expected, expected + SHA384_DIGEST_LENGTH, digest,
                            digest + SHA384_DIGEST_LENGTH);
    if (!match)
    {
        DUMP(PRINT_ERROR, expected, SHA384_DIGEST_LENGTH);
        DUMP(PRINT_ERROR, digest, SHA384_DIGEST_LENGTH);
    }
    return match;
}

/**
 * @brief This function decrypts an ecdsa signature and compares it to a hash
 *
 * @param pointer to ec key x
 * @param pointer to ec key y
 * @param pointer to ec sig r
 * @param pointer to ec sig s
 * @param ec curve magic
 * @param data pointer to the start address of data to hash
 * @param len length of data to hash
 *
 * @return true if this data hashes to expected; false, otherwise
 */
static bool verify_ecdsa_and_sha(const uint8_t* key_x, const uint8_t* key_y,
                                 const uint8_t* sig_r, const uint8_t* sig_s,
                                 uint32_t curve, const uint8_t* data,
                                 size_t len)
{

    EC_KEY* key = nullptr;
    size_t keybits = 0;
    uint8_t digest[EVP_MAX_MD_SIZE];
    switch (curve)
    {
        case curve_secp256r1:
        {
            FWERROR("ecdsa-256 + sha256 not supported");
            return false;
            break;
        }
        case curve_secp384r1:
        {
            constexpr size_t secp384r1_keybits = 384;
            keybits = secp384r1_keybits;
            key = EC_KEY_new_by_curve_name(NID_secp384r1);
            hash_sha384(data, len, digest);
            break;
        }
        default:
            FWERROR("bad curve requested");
            return false;
    }
    if (!key)
    {
        FWERROR("failed to create EC key");
        return false;
    }

    BIGNUM* bn_x = BN_bin2bn(key_x, keybits / 8, nullptr);
    BIGNUM* bn_y = BN_bin2bn(key_y, keybits / 8, nullptr);
    // key takes ownership of BIGNUMs
    EC_KEY_set_public_key_affine_coordinates(key, bn_x, bn_y);

    ECDSA_SIG* sig = ECDSA_SIG_new();
    if (!sig)
    {
        EC_KEY_free(key);
        FWERROR("failed to create EC sig");
        return false;
    }
    BIGNUM* bn_r = BN_bin2bn(sig_r, keybits / 8, nullptr);
    BIGNUM* bn_s = BN_bin2bn(sig_s, keybits / 8, nullptr);
    // sig takes ownership of BIGNUMs
    ECDSA_SIG_set0(sig, bn_r, bn_s);

    int ec_ret = ECDSA_do_verify(digest, keybits / 8, sig, key);

    EC_KEY_free(key);
    ECDSA_SIG_free(sig);

    if (ec_ret != 1)
    {
        // 1 = sig OK; 0 = sig mismatch; -1 = other error
        FWERROR("EC signature mismatch: ec_ret=" << ec_ret);
        return false;
    }
    return true;
}

/**
 * @brief This function verifies that a block matches a value
 *
 * @param data pointer to data to check
 * @param len size of data to check
 * @param val value to compare with data
 *
 * @ return true if len bytes of data match val; false otherwise
 */
static bool mem_check(const uint8_t* data, size_t len, uint8_t val)
{
    if (!data || !len)
    {
        return false;
    }
    bool has_mismatch = false;
    for (size_t ind = 0; ind < len; ind++)
    {
        has_mismatch |= (data[ind] ^ val);
    }
    return !has_mismatch;
}

/**
 * @brief This function checks the validity of Block 0
 *
 * @param b0 pointer to the block 0
 * @param protected_content the start address of protected content
 *
 * @return bool true if this Block 0 is valid; false, otherwise
 */
static bool is_block0_valid(const blk0* b0, const uint8_t* protected_content)
{
    // Verify magic number
    if (b0->magic != blk0_magic)
    {
        FWERROR("bad b0 magic: offset=0x" << std::hex
                                          << image_offset(&b0->magic));
        return false;
    }

    // Verify that size of PC must be multiple of 128 bytes
    if ((b0->pc_length < 128) || (b0->pc_length % 128 != 0))
    {
        FWERROR("b0 pc_length wrong size");
        return false;
    }

    // Verify length of Protected Content (PC) is not larger than allowed
    uint32_t pc_type = b0->pc_type;
    if ((pc_type == pfr_pc_type_cpld_update) ||
        (pc_type == pfr_pc_type_pfr_decommission))
    {
        // The PC length of a CPLD update capsule should not exceed 1MB.
        // A valid signed CPLD update capsule for a larger device may be sent to
        // a smaller CPLD device for update. That can potentially corrupt the
        // recovery image.
        if (b0->pc_length > pfr_cpld_update_size)
        {
            FWERROR("cpld image wrong size");
            return false;
        }
    }
    else if (pc_type == pfr_pc_type_pch_update)
    {
        if (b0->pc_length > pfr_pch_max_size)
        {
            FWERROR("pch image too big");
            return false;
        }
    }
    else if (pc_type == pfr_pc_type_bmc_update)
    {
        // For PFM, there's no max size, but it should be smaller than a capsule
        // size for sure.
        if (b0->pc_length > pfr_bmc_max_size)
        {
            FWERROR("bmc image too big");
            return false;
        }
    }
    else if ((pc_type == pfr_pc_type_pch_pfm) ||
             (pc_type == pfr_pc_type_bmc_pfm))
    {
        if (b0->pc_length > pfr_pfm_max_size)
        {
            FWERROR("pfm/fvm image too big");
            return false;
        }
    }
    else if (pc_type == pfr_pc_type_afm_update)
    {
        if (b0->pc_length > pfr_afm_max_size)
        {
            FWERROR("afm image too big");
            return false;
        }
    }
    else if (pc_type == pfr_pc_type_combined_cpld_update)
    {
        if (b0->pc_length > pfr_combined_cpld_max_size)
        {
            FWERROR("combined image too big");
            return false;
        }
    }

    // Check for the 0s in the reserved field
    // This reduces the degree of freedom for attackers
    for (size_t word_i = 0; word_i < blk0_pad_size; word_i++)
    {
        if (b0->pad[word_i] != 0)
        {
            FWERROR("bad padding in block0");
            return false;
        }
    }

    // Verify Hash256 is 0xff and Hash384 matches PC
    if (!mem_check(b0->sha256, b0->pc_length, 0xff))
    {
        FWWARN("sha256 signature is not empty");
        // do not enforce until images are generated correctly
    }
    // require the sha384 signature to be correct
    return verify_sha384(b0->sha384, protected_content, b0->pc_length);
}

/**
 * @brief This function finds the in-flash pfm's root key
 *
 * @param root_key reference to key_entry where to store root key
 * @return true if the root key was found, false otherwise
 */
static bool root_key_from_pfm(key_entry& root_key)
{
    int fd = open(MTD_DEV_BASE "mtd/pfm", O_RDONLY);
    if (fd < 0)
    {
        FWERROR("failed to open pfm");
        return false;
    }
    blk1 pfm_root;
    if (lseek(fd, sizeof(blk0), SEEK_SET) < 0)
    {
        FWERROR("failed to seek to blk1 in pfm");
        close(fd);
        return false;
    }

    if (read(fd, &pfm_root, sizeof(pfm_root)) != sizeof(pfm_root))
    {
        FWERROR("failed to read pfm");
        close(fd);
        return false;
    }
    close(fd);
    root_key = pfm_root.root_key;

    return true;
}

/**
 * @brief This function validates a Block 1 root entry
 *
 * @param root_entry pointer to the Block 1 root entry
 * @return true if this root entry is valid; false, otherwise
 */
static bool is_root_entry_valid(const key_entry* root_entry,
                                bool check_root_key)
{
    // Verify magic number
    if (root_entry->magic != root_key_magic)
    {
        FWERROR("bad root entry magic: offset=0x"
                << std::hex << image_offset(&root_entry->magic));
        return false;
    }

    // Verify curve magic number
    if (root_entry->curve != curve_secp256r1 &&
        root_entry->curve != curve_secp384r1)
    {
        FWERROR("bad root curve: offset=0x"
                << std::hex << image_offset(&root_entry->curve));
        return false;
    }

    // Must have the required permissions (-1).
    if (root_entry->permissions != pfr_perm_sign_all)
    {
        FWERROR("bad root permissions: offset=0x"
                << std::hex << image_offset(&root_entry->permissions));
        return false;
    }

    // Must have the required cancellation (-1).
    if (root_entry->key_id != key_non_cancellable)
    {
        FWERROR("bad root key ID: offset=0x"
                << std::hex << image_offset(&root_entry->key_id));
        return false;
    }

    const uint8_t* key_x = root_entry->key_x;
    const uint8_t* key_y = root_entry->key_y;
    key_entry root_key;

    if (!check_root_key)
    {
        return true;
    }

    if (!root_key_from_pfm(root_key))
    {
        FWERROR("failed to read root key from pfm");
        return false;
    }

    bool match;
    match = std::equal(key_x, key_x + sizeof(key_entry::key_x), root_key.key_x,
                       root_key.key_x + sizeof(key_entry::key_x));
    if (!match)
    {
        DUMP(PRINT_ERROR, key_x, sizeof(key_entry::key_x));
        DUMP(PRINT_ERROR, root_key.key_x, sizeof(key_entry::key_x));
        FWERROR("image root key signature_x does not match root key from pfm");
        return false;
    }

    match = std::equal(key_y, key_y + sizeof(key_entry::key_y), root_key.key_y,
                       root_key.key_y + sizeof(key_entry::key_y));
    if (!match)
    {
        DUMP(PRINT_ERROR, key_y, sizeof(key_entry::key_y));
        DUMP(PRINT_ERROR, root_key.key_y, sizeof(key_entry::key_y));
        FWERROR("image root key signature_y does not match root key from pfm");
        return false;
    }

    return true;
}

static inline uint32_t get_required_perm(uint32_t pc_type)
{
    switch (pc_type)
    {
        case pfr_pc_type_cpld_update:
            return pfr_perm_sign_cpld_update;
        case pfr_pc_type_pch_pfm:
            return pfr_perm_sign_pch_pfm;
        case pfr_pc_type_pch_update:
            return pfr_perm_sign_pch_update;
        case pfr_pc_type_bmc_pfm:
            return pfr_perm_sign_bmc_pfm;
        case pfr_pc_type_bmc_update:
            return pfr_perm_sign_bmc_update;
        case pfr_pc_type_partial_update:
            return pfr_perm_sign_pch_pfm | pfr_perm_sign_pch_update;
        case pfr_pc_type_afm_update:
            return pfr_perm_sign_afm_update;
        case pfr_pc_type_cancel_cert:
            return pfr_perm_sign_all;
        case pfr_pc_type_pfr_decommission:
            return pfr_perm_sign_cpld_update;
        case pfr_pc_type_combined_cpld_update:
            return pfr_perm_sign_combined_cpld_update;

        default:
            FWERROR("bad pc_type: " << pc_type);
            return 0;
    }
}

static inline bool is_csk_key_valid(uint32_t pc_type, uint32_t key_id)
{
    // without pfr, we cannot check this
    return key_id <= pfr_max_key_id;
}

/**
 * @brief This function validates a Block 1 csk entry
 *
 * @param key_perm_mask The required key permission mask
 * @param root_entry Previous entry (the root entry)
 * @param csk_entry pointer to the Block 1 csk entry
 *
 * @return bool true if this csk entry is valid; false, otherwise
 */
static bool is_csk_entry_valid(const key_entry* root_entry,
                               const csk_entry* csk, uint32_t pc_type)
{
    // Verify magic number
    if (csk->key.magic != csk_key_magic)
    {
        FWERROR("csk bad magic");
        return false;
    }

    // Verify curve magic number
    if (csk->key.curve != root_entry->curve)
    {
        FWERROR("csk bad curve");
        return false;
    }

    // The key must have the required permissions
    if (!(csk->key.permissions & get_required_perm(pc_type)))
    {
        FWERROR("csk bad permissions: " << std::hex << csk->key.permissions
                                        << "&" << get_required_perm(pc_type));
        return false;
    }

    // Check the CSK key ID
    if (!is_csk_key_valid(pc_type, csk->key.key_id))
    {
        FWERROR("csk bad key ID");
        return false;
    }

    // Check for the 0s in the reserved field
    // This reduces the degree of freedom for attackers
    for (size_t word_i = 0; word_i < key_entry_rsvd_size; word_i++)
    {
        if (csk->key.rsvd[word_i] != 0)
        {
            FWERROR("csk bad padding");
            return false;
        }
    }

    // A signature over the hashed region using the Root Key in the previous
    // entry must be valid. The hashed region starts at the curve magic field
    if (verify_ecdsa_and_sha(root_entry->key_x, root_entry->key_y, csk->sig_r,
                             csk->sig_s, root_entry->curve,
                             reinterpret_cast<const uint8_t*>(&csk->key.curve),
                             block1_csk_entry_hash_region_size))
    {
        return true;
    }
    FWERROR("csk signature check failed");
    return false;
}

/**
 * @brief This function validates a Block 1 block 0 entry
 *
 * @param root_entry entry in the Block 1 prior to this entry (the csk entry)
 * @param b0_entry pointer to the Block 1 block 0 entry
 * @param b0 pointer to Block 0
 *
 * @return bool true if this block 0 entry is valid; false, otherwise
 */
static bool is_block0_sig_entry_valid(uint32_t curve, const uint8_t* root_key_x,
                                      const uint8_t* root_key_y,
                                      const block0_sig_entry* block0_sig,
                                      const blk0* b0)
{
    // Verify magic number
    if (block0_sig->magic != block0_sig_entry_magic)
    {
        FWERROR("block0_sig magic invalid");
        return 0;
    }

    // The signature over the hash of block 0 using the CSK Pubkey must be
    // valid.
    if (verify_ecdsa_and_sha(root_key_x, root_key_y, block0_sig->sig_r,
                             block0_sig->sig_s, curve,
                             reinterpret_cast<const uint8_t*>(b0), sizeof(*b0)))
    {
        return true;
    }
    FWERROR("block0_sig signature check failed");
    return false;
}

/**
 * @brief This function validates Block 1
 *
 * @param b0 pointer to block 0
 * @param b1 pointer to block 1
 * @param is_key_cancellation_cert true if this signature is part of a signed
 * key cancellation certificate.
 *
 * @return bool true if this Block 1 is valid; false, otherwise
 */
static bool is_block1_valid(const blk0* b0, const blk1* b1,
                            bool is_key_cancellation_cert, bool check_root_key)
{
    // Verify magic number
    if (b1->magic != blk1_magic)
    {
        FWERROR("b1 magic invalid");
        return false;
    }

    // Validate Block1 Root Entry
    const key_entry* root_entry = &b1->root_key;
    if (!is_root_entry_valid(root_entry, check_root_key))
    {
        FWERROR("root_entry invalid");
        return false;
    }

    if (is_key_cancellation_cert)
    {
        // In the signature of the Key Cancellation Certificate, there's no CSK
        // entry
        const block0_sig_entry* b0_entry = &b1->block0_sig;

        // Validate Block 0 Entry in Block 1
        return is_block0_sig_entry_valid(root_entry->curve, root_entry->key_x,
                                         root_entry->key_y, b0_entry, b0);
    }

    // Validate Block1 CSK Entry
    const csk_entry* csk = &b1->csk;
    if (!is_csk_entry_valid(root_entry, csk, b0->pc_type))
    {
        FWERROR("csk_entry invalid");
        return false;
    }

    // Validate Block 0 Entry in Block 1
    const block0_sig_entry* block0_sig = &b1->block0_sig;
    if (is_block0_sig_entry_valid(root_entry->curve, csk->key.key_x,
                                  csk->key.key_y, block0_sig, b0))
    {
        return true;
    }
    FWERROR("block0_sig_entry invalid");
    return false;
}

/**
 * @brief This function validates the content of a key cancellation certificate.
 * The 124 bytes of reserved field must be all 0s. The CSK Key ID must be within
 * 0-127 (inclusive).
 *
 * @param cert pointer to the key cancellation certificate.
 *
 * @return uint32_t 1 if this key cancellation certificate is valid; 0,
 * otherwise
 */
static uint32_t is_key_can_cert_valid(const cancel_cert* cert)
{
    // Check for the 0s in the reserved field
    // This reduces the degree of freedom for attackers
    const uint32_t* key_can_cert_reserved = cert->rsvd;
    for (uint32_t word_i = 0; word_i < cancel_pad_size / 4; word_i++)
    {
        if (key_can_cert_reserved[word_i] != 0)
        {
            return 0;
        }
    }
    const cancel_payload* cancel =
        reinterpret_cast<const cancel_payload*>(cert + 1);

    // If the key ID is within 0-127 (inclusive), return 1
    return cancel->csk_id <= pfr_max_key_id;
}

/**
 * @brief This function authenticate a given signed payload.
 * Please refer to the specification regarding the format of signed payload.
 * This function authenticate the Block 0 (containing hash of the payload)
 * first, then authenticate the Block 1 (containing signature over Block0). For
 * key cancellation certificate, this function also validate the certificate
 * content for security reasons.
 *
 * @param sig the start address of the signed payload (i.e. beginning of a
 * signature.)
 *
 * @return uint32_t true if this keychain is valid; false, otherwise
 */
static bool is_signature_valid(const b0b1_signature* sig, bool check_root_key)
{
    const blk0* b0 = &sig->b0;
    const blk1* b1 = &sig->b1;
    bool is_key_cancellation_cert = b0->pc_type & pfr_pc_type_cancel_cert;

    // Get pointer to protected content
    const uint8_t* pc = reinterpret_cast<const uint8_t*>(sig + 1);
    if (is_key_cancellation_cert)
    {
        // Check the size of the cancellation certificate
        if (b0->pc_length != pfr_cancel_cert_size)
        {
            return false;
        }

        // Validate the cancellation certificate content
        if (!is_key_can_cert_valid(reinterpret_cast<const cancel_cert*>(pc)))
        {
            FWERROR("cancel cert invalid");
            return false;
        }
    }

    // Validate block0 (contains hash of the protected content)
    if (is_block0_valid(b0, pc))
    {
        // Validate block1 (contains the signature chain used to sign block0)
        if (is_block1_valid(b0, b1, is_key_cancellation_cert, check_root_key))
        {
            return true;
        }
        FWERROR("block1 failed authentication");
        return false;
    }
    FWERROR("block0 failed authentication");
    return false;
}

static uint32_t read_saved_layout(void)
{
    static constexpr const char layout_file[] =
        "/var/sofs/factory-settings/layout/fitc";
    uint32_t layout = 0;
    try
    {
        std::ifstream file(layout_file);
        file >> layout;
    }
    catch (const std::exception& e)
    {
        // ignore errors, defaulting to zero,
        // which is the default layout anyway
    }
    return layout;
}

static bool pfm_cfm_authenticate(const uint8_t* base_addr, bool check_root_key,
                                 const size_t max_size)
{

    auto offset =
        reinterpret_cast<const uint8_t*>(base_addr + blk0blk1_size * 2);

    if (offset < base_addr || offset > (base_addr + max_size))
    {
        FWERROR("An invalid pointer reference");
        return false;
    }
    static constexpr const char prod_id_file[] = "/var/cache/private/prodID";
    uint32_t prod_id;
    std::ifstream file(prod_id_file);

    if (!file.is_open())
    {
        FWERROR("failed to open prodID file");
        return false;
    }

    file >> std::hex >> prod_id;

    // Validate PFM
    auto pfm_str = reinterpret_cast<const pfm*>(offset);
    if (pfm_str->magic != pfm_magic)
    {
        FWERROR("pfm magic number not valid");
        return false;
    }

    if (pfm_str->platform_type != prod_id)
    {
        FWERROR("product id not valid");
        return false;
    }

    offset += pfm_hdr_size;

    // Validate FW Type of CPU/SCM/DEBUG CPLD
    auto cpu_cpld_addr_str = reinterpret_cast<const cpld_addr_def*>(offset);

    if (cpu_cpld_addr_str->fw_type != CPUfwType)
    {
        FWERROR("fwType is not CPU");
        return false;
    }

    auto CPU_cpld_strt_offset = cpu_cpld_addr_str->img_strt_offset;
    offset += CPLD_addr_ref_hdr_size;

    auto scm_cpld_addr_str = reinterpret_cast<const cpld_addr_def*>(offset);

    if (scm_cpld_addr_str->fw_type != SCMfwType)
    {
        FWERROR("fwType is not SCM");
        return false;
    }

    auto SCM_cpld_strt_offset = scm_cpld_addr_str->img_strt_offset;
    offset += CPLD_addr_ref_hdr_size;

    auto debug_cpld_addr_str = reinterpret_cast<const cpld_addr_def*>(offset);

    if (debug_cpld_addr_str->fw_type != DebugfwType)
    {
        FWERROR("fwType is not Debug");
        return false;
    }

    auto DBG_cpld_strt_offset = debug_cpld_addr_str->img_strt_offset;

    // CPU CPLD signature validation
    offset = reinterpret_cast<const uint8_t*>(base_addr + CPU_cpld_strt_offset);

    auto cpu_img_sig = reinterpret_cast<const b0b1_signature*>(offset);

    if (!is_signature_valid(cpu_img_sig, check_root_key))
    {
        FWERROR("CPU CPLD signature is not valid");
        return false;
    }

    offset += blk0blk1_size;

    // CPU CPLD CFM validation
    auto cpu_cfm_str = reinterpret_cast<const cfm*>(offset);

    if (cpu_cfm_str->magic != cfm_magic)
    {
        FWERROR("CPU cfm magic is not valid");
        return false;
    }

    if (cpu_cfm_str->fw_type != CPUfwType)
    {
        FWERROR("fwType is not CPU");
        return false;
    }

    // SCM CPLD signature validation
    offset = reinterpret_cast<const uint8_t*>(base_addr + SCM_cpld_strt_offset);
    auto scm_img_sig = reinterpret_cast<const b0b1_signature*>(offset);

    if (!is_signature_valid(scm_img_sig, check_root_key))
    {
        FWERROR("SCM CPLD signature is not valid");
        return false;
    }

    offset += blk0blk1_size;

    // SCM CPLD CFM validation
    auto scm_cfm_str = reinterpret_cast<const cfm*>(offset);

    if (scm_cfm_str->magic != cfm_magic)
    {
        FWERROR("SCM cfm magic is not valid");
        return false;
    }

    if (scm_cfm_str->fw_type != SCMfwType)
    {
        FWERROR("fwType is not SCM");
        return false;
    }

    // Debug CPLD signature validation
    offset = reinterpret_cast<const uint8_t*>(base_addr + DBG_cpld_strt_offset);
    auto debug_img_sig = reinterpret_cast<const b0b1_signature*>(offset);

    if (!is_signature_valid(debug_img_sig, check_root_key))
    {
        FWERROR("DEBUG CPLD signature is not valid");
        return false;
    }

    offset += blk0blk1_size;

    if (offset < base_addr || offset > (base_addr + max_size))
    {
        FWERROR("An invalid pointer reference");
        return false;
    }

    // Debug CPLD CFM validation
    auto debug_cfm_str = reinterpret_cast<const cfm*>(offset);

    if (debug_cfm_str->magic != cfm_magic)
    {
        FWERROR("Debug cfm magic is not valid");
        return false;
    }

    if (debug_cfm_str->fw_type != DebugfwType)
    {
        FWERROR("fwType is not Debug");
        return false;
    }

    return true;
}

static bool fvm_authenticate(const b0b1_signature* img_sig)
{
    // sig (full image signature) has already been authenticated; immediately
    // following should be the fvm signature, which should not be incorrect,
    // but it is authenticated as follows:
    const b0b1_signature* sig = img_sig + 1;
    const blk0* b0 = &sig->b0;
    const blk1* b1 = &sig->b1;
    const uint8_t* pc = reinterpret_cast<const uint8_t*>(sig + 1);

    if (!is_block0_valid(b0, pc))
    {
        FWERROR("block0 failed authentication");
        return false;
    }
    // Validate block1 (contains the signature chain used to sign block0)
    if (!is_block1_valid(b0, b1, false, false))
    {
        FWERROR("block1 failed authentication");
        return false;
    }
    auto map_base = reinterpret_cast<const uint8_t*>(img_sig);
    auto offset = reinterpret_cast<const uint8_t*>(img_sig);
    offset += blk0blk1_size * 2; // one blk0blk1 for package, one for fvm
    auto fvm_hdr = reinterpret_cast<const fvm*>(offset);
    FWDEBUG("fvm header at " << std::hex << fvm_hdr
                             << " (magic:" << fvm_hdr->magic << ")");
    FWDEBUG("fvm length is 0x" << std::hex << fvm_hdr->length);
    size_t fvm_size = block_round(fvm_hdr->length, fvm_block_size);
    offset += sizeof(*fvm_hdr);
    auto fvm_end = reinterpret_cast<const uint8_t*>(fvm_hdr) + fvm_size;

    // loop through until we find fvm address structs
    DUMP(PRINT_DEBUG, fvm_hdr, sizeof(*fvm_hdr) + (fvm_end - offset));
    DUMP(PRINT_DEBUG, offset, 2 * SHA256_DIGEST_LENGTH);
    auto pbc_hdr = reinterpret_cast<const pbc*>(fvm_end);
    auto payload = reinterpret_cast<const uint8_t*>(pbc_hdr + 1);
    auto act_map = reinterpret_cast<const uint8_t*>(payload);
    FWDEBUG("active map at 0x" << std::hex
                               << (reinterpret_cast<unsigned long>(act_map) -
                                   reinterpret_cast<unsigned long>(map_base)));
    payload += pbc_hdr->bitmap_size / 8;
    auto pbc_map = reinterpret_cast<const uint8_t*>(payload);
    FWDEBUG("pbc map at 0x" << std::hex
                            << (reinterpret_cast<unsigned long>(pbc_map) -
                                reinterpret_cast<unsigned long>(map_base)));
    FWDEBUG("payload starts at "
            << std::hex
            << (reinterpret_cast<unsigned long>(payload) -
                reinterpret_cast<unsigned long>(map_base)));
    payload += pbc_hdr->bitmap_size / 8;
    while (offset < fvm_end)
    {
        FWDEBUG("offset: " << std::hex << (const void*)offset << " < "
                           << (const void*)fvm_end);
        // first byte of struct is type
        if (*offset == type_spi_region)
        {
            FWINFO("parse FVM: spi_region");
            auto info = reinterpret_cast<const spi_region*>(offset);
            offset += sizeof(*info);
            std::unique_ptr<Hash> hash256 = nullptr;
            std::unique_ptr<Hash> hash384 = nullptr;
            // size of spi region depends on hashes present
            if (info->hash_info & sha256_present)
            {
                FWINFO("           spi_region + sha256 not supported");
                // For now, allow images that are dual hashed to pass
                // but reject images that are only sha256 hashed
                if (!(info->hash_info & sha384_present))
                {
                    return false;
                }
            }
            if (info->hash_info & sha384_present)
            {
                FWINFO("           spi_region + sha384 (" << sha384_size
                                                          << " bytes)");
                hash384 = std::make_unique<Hash>(EVP_sha384(),
                                                 cbspan(offset, sha384_size));
                offset += sha384_size;
            }
            // hash the parts by walking the pbc
            if (pbc_hdr->magic != pbc_magic)
            {
                FWERROR("pbc magic incorrect: " << std::hex << pbc_hdr->magic
                                                << " != " << pbc_magic);
                return false;
            }
            uint8_t ffs[pbc_hdr->page_size];
            std::fill_n(ffs, pbc_hdr->page_size, 0xff);
            for (size_t pg = info->start / pbc_hdr->page_size;
                 pg < info->end / pbc_hdr->page_size; pg++)
            {
                const uint8_t* data;
                FWDEBUG("er: " << std::hex << (int)act_map[pg / 8]
                               << ", cp: " << (int)pbc_map[pg / 8]);
                bool erase = (act_map[pg / 8] >> (7 - pg % 8)) & 1;
                bool copy = (pbc_map[pg / 8] >> (7 - pg % 8)) & 1;
                if (copy)
                {
                    data = payload;
                    FWDEBUG("data page " << pg << " at " << std::hex
                                         << (payload - map_base));
                    payload += pbc_hdr->page_size;
                }
                else if (erase)
                {
                    FWDEBUG("empty page at " << pg);
                    data = ffs;
                }
                else
                {
                    data = nullptr;
                }
                if (data)
                {
                    if (hash256)
                    {
                        hash256->update(data, pbc_hdr->page_size);
                    }
                    if (hash384)
                    {
                        hash384->update(data, pbc_hdr->page_size);
                    }
                }
            }
            if (hash256)
            {
                if (hash256->verify())
                {
                    FWINFO("FVM SHA-256 verify ok");
                }
                else
                {
                    FWERROR("FVM SHA-256 verify failed");
                    return false;
                }
            }
            if (hash384)
            {
                if (hash384->verify())
                {
                    FWINFO("FVM SHA-384 verify ok");
                }
                else
                {
                    FWERROR("FVM SHA-384 verify failed");
                    return false;
                }
            }
        }
        else if (*offset == type_smbus_rule)
        {
            FWINFO("parse FVM: smbus_rule");
            auto info = reinterpret_cast<const smbus_rule*>(offset);
            offset += sizeof(*info);
        }
        else if (*offset == type_fvm_address)
        {
            FWINFO("parse FVM: fvm_address");
            auto info = reinterpret_cast<const fvm_address*>(offset);
            offset += sizeof(*info);
        }
        else if (*offset == type_fvm_capabilities)
        {
            auto info = reinterpret_cast<const fvm_capabilities*>(offset);
            FWINFO("parse FVM: fvm_capabilities\n"
                   << "    pkg version: "
                   << static_cast<int>(info->version.major) << "."
                   << static_cast<int>(info->version.minor) << "."
                   << static_cast<int>(info->version.release) << "+"
                   << static_cast<int>(info->version.hotfix) << '\n'
                   << "    layout ID: " << std::hex << info->layout);
            // check that the saved layout matches the incoming layout
            uint32_t layout = read_saved_layout();
            if (layout != info->layout)
            {
                FWERROR("Layout ID does not match: saved="
                        << layout << ", image=" << info->layout);
                return false;
            }
            offset += sizeof(*info);
        }
        else if (*offset == 0)
        {
            // check padding to end
            FWDEBUG("parse FVM: padding");
            while (offset < fvm_end)
            {
                if (*offset != 0)
                {
                    FWERROR("Invalid non-zero padding at "
                            << std::hex << (offset - map_base));
                    return false;
                }
                offset++;
            }
        }
        else
        {
            FWERROR("parse FVM: unexpected bytes at offset 0x"
                    << std::hex << (offset - map_base));
            DUMP(PRINT_ERROR, offset, SHA256_DIGEST_LENGTH);
            return false;
        }
    }
    return true;
}

bool pfr_authenticate(const std::string& filename, bool check_root_key)
{
    boost::iostreams::mapped_file file(filename,
                                       boost::iostreams::mapped_file::readonly);
    base_addr = file.const_data();
    const auto sig = reinterpret_cast<const b0b1_signature*>(file.const_data());
    // check for basic shape
    if (file.size() < blk0blk1_size ||
        (sig->b0.pc_length + blk0blk1_size) != file.size())
    {
        FWERROR("bad file size");
        return false;
    }

    if (!is_signature_valid(sig, check_root_key))
    {
        FWERROR("FVM signature not valid");
        return false;
    }

    if (sig->b0.pc_type == pfr_pc_type_combined_cpld_update)
    {
        auto offset = reinterpret_cast<const uint8_t*>(file.const_data());
        offset += blk0blk1_size;

        const auto pfm_sig = reinterpret_cast<const b0b1_signature*>(offset);

        if (!is_signature_valid(pfm_sig, check_root_key))
        {
            FWERROR("PFM signature not valid");
            return false;
        }

        return pfm_cfm_authenticate(reinterpret_cast<const uint8_t*>(base_addr),
                                    check_root_key, file.size());
    }
    // partial images should have the FVM signature checked as well
    else if (sig->b0.pc_type == pfr_pc_type_partial_update)
    {
        // check PFM for FVMs to authenticate
        return fvm_authenticate(sig);
    }
    // non-partial packages only need the outside signature checked
    return true;
}
