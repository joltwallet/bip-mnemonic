#ifndef __BIP_MNEMONIC_H__
#define __BIP_MNEMONIC_H__

#include "jolttypes.h"

#define BM_HARDENED 0x80000000
#define BM_BITS_PER_WORD 11
#define BM_MNEMONIC_BUF_LEN (24 * 10 + 1)
#define BM_PASSPHRASE_BUF_LEN 256

jolt_err_t bm_mnemonic_generate(char buf[], uint16_t buf_len, uint16_t strength);

jolt_err_t bm_entropy_to_mnemonic(char buf[], const uint16_t buf_len,
        const uint256_t entropy, const uint16_t strength);

int16_t bm_search_wordlist(char *word, uint8_t word_len);

jolt_err_t bm_verify_mnemonic(const char mnemonic[]);

void bm_master_seed_to_private_key(uint256_t private_key, uint512_t master_seed, char * bip32_key,
        uint8_t path_len, ...);

jolt_err_t bm_mnemonic_to_master_seed(uint512_t master_seed, 
        const char mnemonic[], const char passphrase[]);

#endif
