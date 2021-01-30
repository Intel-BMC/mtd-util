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

static const void* base_addr = NULL;
static unsigned int image_offset(const void* thing)
{
    return static_cast<unsigned int>(static_cast<const uint8_t*>(thing) -
                                     static_cast<const uint8_t*>(base_addr));
}

/**
 * @brief This function hashes data with SHA256
 *
 * @param data pointer to the start address of data to hash
 * @param len length of data to hash
 * @param buffer to store output digest
 *
 * @return void
 */
static void hash_sha256(const uint8_t* data, size_t len, uint8_t* digest)
{
    unsigned int digest_sz = SHA256_DIGEST_LENGTH;
    EVP_Digest(data, len, digest, &digest_sz, EVP_sha256(), nullptr);
}

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
 * @param expected pointer to the sha256 hash
 * @param data pointer to the start address of data to hash
 * @param len length of data to hash
 *
 * @return true if this data hashes to expected; false, otherwise
 */
static bool verify_sha256(const uint8_t* expected, const uint8_t* data,
                          size_t len)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    hash_sha256(data, len, digest);
    bool match = std::equal(expected, expected + SHA256_DIGEST_LENGTH, digest,
                            digest + SHA256_DIGEST_LENGTH);
    if (!match)
    {
        DUMP(PRINT_ERROR, expected, SHA256_DIGEST_LENGTH);
        DUMP(PRINT_ERROR, digest, SHA256_DIGEST_LENGTH);
    }
    return match;
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
            constexpr size_t secp256r1_keybits = 256;
            keybits = secp256r1_keybits;
            key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
            hash_sha256(data, len, digest);
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
    else if ((pc_type == pfr_pc_type_pch_pfm) ||
             (pc_type == pfr_pc_type_pch_update))
    {
        // For PFM, there's no max size, but it should be smaller than a capsule
        // size for sure.
        if (b0->pc_length > pfr_pch_max_size)
        {
            FWERROR("pch image too big");
            return false;
        }
    }
    else if ((pc_type == pfr_pc_type_bmc_pfm) ||
             (pc_type == pfr_pc_type_bmc_update))
    {
        // For PFM, there's no max size, but it should be smaller than a capsule
        // size for sure.
        if (b0->pc_length > pfr_bmc_max_size)
        {
            FWERROR("bmc image too big");
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

    // Verify Hash256 of PC
    return verify_sha256(b0->sha256, protected_content, b0->pc_length);
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
        case pfr_pc_type_cancel_cert:
            return pfr_perm_sign_all;
        case pfr_pc_type_pfr_decommission:
            return pfr_perm_sign_cpld_update;
        default:
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
    return is_signature_valid(sig, check_root_key);
}
