#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "sodium.h"
#include "esp_err.h"

#include "bipmnemonic.h"
#include "jolttypes.h"
#include "joltcrypto.h"
#include "../word_list/bip39_en.h"


static uint8_t get_word_count(const char *str);
static void entropy256(uint256_t ent);
static uint8_t get_word_len(char **start, const char *str);

static void entropy256(uint256_t ent){
    /* Generates random 256-bits
     * Uses randombytes_random() from libsodium.
     * If libsodium is properly ported, this is a cryptographically secure
     * source.
     */
    CONFIDENTIAL uint32_t rand_buffer;

    for(uint8_t i=0; i<8; i++){
        rand_buffer = randombytes_random();
        memcpy(ent + 4*i, &rand_buffer, 4);
    }
    sodium_memzero(&rand_buffer, sizeof(rand_buffer));
}

jolt_err_t bm_mnemonic_generate(char buf[], uint16_t buf_len, uint16_t strength){
    /* Strength in bits; shoudl really always be 256 */
    jolt_err_t res;
    CONFIDENTIAL uint256_t entropy;
    entropy256(entropy);
    res = bm_bin_to_mnemonic(buf, buf_len, entropy, strength);
    sodium_memzero(entropy, sizeof(entropy));
    return res;
}

jolt_err_t bm_bin_to_mnemonic(char buf[], const uint16_t buf_len,
        const uint256_t entropy, const uint16_t strength){
    /* Derives mnemonic from provided entropy into the buffer buf.
     * Sets Buf to a space separated mnemonic string with length according to 
     * strength.
     */
    if(strength % 32 || strength < 128 || strength > 256){
        return E_INVALID_STRENGTH;
    }

    /* Generate Checksum; there are ENT/32 bits in the checksum */
    // 128->4; 192->6; 256->8
    uint8_t entropy_len = strength / 8;
    uint8_t m_len = entropy_len * 3 / 4; //number of mnemonic words
    CONFIDENTIAL unsigned char cs_entropy[sizeof(uint256_t) + 1];

    if(buf_len < (m_len * 10 + 1)){
        return E_INSUFFICIENT_BUF;
    }

    // Make cs_entropy first entropy_len bits be entropy, remaining
    // bits (up to 8 needed) be the first bits from the sha256 hash
    crypto_hash_sha256(cs_entropy, entropy, entropy_len);
    cs_entropy[entropy_len] = cs_entropy[0];
    memcpy(cs_entropy, entropy, entropy_len);

    CONFIDENTIAL uint16_t list_idx;
    uint8_t i, j;
    uint16_t bit_idx;
    for (i = 0; i < m_len; i++, buf++) {
        for (j=0, list_idx=0, bit_idx = i * BM_BITS_PER_WORD;
                j < BM_BITS_PER_WORD;
                j++, bit_idx++) {
            list_idx <<=1;
            list_idx += ( cs_entropy[bit_idx / 8] & 
                          (1 << (7 - bit_idx % 8))
                        ) > 0;
        }
        // Copy the word over from the mnemonic word list
        strcpy(buf, wordlist[list_idx]);
        buf += strlen(wordlist[list_idx]);
        buf[0] = (i < m_len - 1) ? ' ' : 0;
    }
    sodium_memzero(&list_idx, sizeof(list_idx));
    sodium_memzero(cs_entropy, sizeof(cs_entropy));

    return E_SUCCESS;
}

jolt_err_t bm_mnemonic_to_bin(unsigned char *buf, size_t buf_len, const char *mnemonic) {
    /* Expects a null-terminated mnemonic string.
     * bin must either be 32-bytes (256-bits) or NULL;
     * if bin is NULL, this function only verifies the mnemonic checksum
     * The mnemonic can have arbitrary whitespace leading, trailing, and
     * between workds
     */
    int8_t j;
    uint8_t m_len, i_word;
    CONFIDENTIAL uint8_t current_word_len;
    int16_t bit_idx;
    CONFIDENTIAL int16_t mnemonic_index;
    char *current_word, *start;
    CONFIDENTIAL unsigned char bin[sizeof(uint256_t)] = {0};
    jolt_err_t res;

    // Check number of words in mnemonic
    m_len = get_word_count(mnemonic);
    if ( m_len!=12 && m_len!=18 && m_len!=24 ) {
        res = E_INVALID_MNEMONIC_LEN;
        goto exit;
    }

    // Iterate through words in user's mnemonic
    for(i_word=0, bit_idx=0, current_word=(char *)mnemonic;
            i_word < m_len;
            i_word++, current_word+=current_word_len){
        current_word_len = get_word_len(&start, current_word);
        current_word = start;
        mnemonic_index = bm_search_wordlist(current_word, current_word_len);
        if( mnemonic_index == -1 ) {
            res = E_INVALID_MNEMONIC;
            goto exit;
        }
        for( j=BM_BITS_PER_WORD-1; j>=0; j--, bit_idx++ ) {
            if(mnemonic_index & (1 << j)){
                bin[bit_idx/8] |= 1 << (7 - (bit_idx % 8)) ;
            }
        }
    }

    // Verify Checksum; checksum is at most 8-bits
    uint8_t byte_len = m_len*4/3;
    CONFIDENTIAL unsigned char user_checksum = bin[byte_len];
    CONFIDENTIAL unsigned char computed_checksum[sizeof(uint256_t)] = {0};
    crypto_hash_sha256(computed_checksum, bin, byte_len);
    if ( (m_len == 12 && (computed_checksum[0] & 0xF0) == (user_checksum & 0xF0)) ||
         (m_len == 18 && (computed_checksum[0] & 0xFC) == (user_checksum & 0xFC)) ||
         (m_len == 24 && (computed_checksum[0] == user_checksum)) ) {
        if( NULL != buf ) {
            if( buf_len < m_len ) {
                return E_INSUFFICIENT_BUF;
            }
            memcpy(buf, bin, sizeof(byte_len));
        }
        res = E_SUCCESS;
    }
    else {
        res = E_INVALID_CHECKSUM;
    }
exit:
    sodium_memzero(&user_checksum, sizeof(user_checksum));
    sodium_memzero(computed_checksum, sizeof(computed_checksum));
    sodium_memzero(bin, sizeof(bin));
    sodium_memzero(&mnemonic_index, sizeof(mnemonic_index));
    sodium_memzero(&current_word_len, sizeof(current_word_len));
    return res;
}

int16_t bm_search_wordlist(const char *word, uint8_t word_len){
    /* Performs binary search on the wordlist
     *
     * Returns the index of the word that starts with parameter word.
     * Returns -1 if word is not found
     */
    uint16_t index = (1<<(BM_BITS_PER_WORD-1)) - 1;
    char word_lower[10];

    if( NULL == word || 0 == word_len || word_len >= sizeof(word_lower)){
        return -1;
    }

    strncpy(word_lower, word, word_len);
    word_lower[word_len] = '\0';
    strlwr(word_lower);

    // Minimalistic Binary search for [0,2046]
    for(uint16_t depth=(1<<(BM_BITS_PER_WORD-1)); depth>0;){
        depth>>=1;

        int res = strcmp(word_lower, wordlist[index]);
        if(res>0){
            index += depth;
        }
        else if(res < 0){
            index -= depth;
        }
        else if( strlen(wordlist[index]) == word_len ){
            return index;
        }
        else{
            return -1;
        }
    }
    // Check if it's zoo (index 2047)
    if(strcmp(word_lower, wordlist[2047])==0){
        return 2047;
    }

    return -1;
}

static uint8_t get_word_len(char **start, const char *str){
    /* gets the length of a word and pointer to where it starts 
     * ignores whitespace, newlines, and tabs*/
    bool state = false;
    uint8_t cc = 0;
    *start = NULL;
    for(; *str; str++){
        if (*str != ' ' && *str != '\n' && *str != '\t'){
            if(!state){
                *start = (char *) str;
            }
            state = true;
            cc++;
        }
        else if (state){
            return cc;
        }
    }
    return cc;
}

static uint8_t get_word_count(const char *str){
    /* counts the number of words separated by possibly multiple spaces,
     * newlines, and tabs. */
    uint8_t wc = 0;  // word count
    char *start;
    uint8_t cc;
    while((cc = get_word_len(&start, str))>0 ){
        wc++;
        str = start + cc;
    }
    return wc;
}

jolt_err_t bm_verify_mnemonic(const char mnemonic[]){
    /* Expects a null-terminated mnemonic string.
     * The mnemonic can have arbitrary whitespace leading, trailing, and
     * between workds
     */
    return bm_mnemonic_to_bin(NULL, 0, mnemonic);
}

jolt_err_t bm_mnemonic_to_master_seed(uint512_t master_seed, 
        const char mnemonic[], const char passphrase[]){
    /* mnemonic must be a null terminated string.
     * passphrase must be a null terminated string. Up to BM_PASSPHRASE_BUF_LEN bytes
     * It is recommended to verify the mnemonic before calling this function.
     */
    /* Filter the input mnemonic */
    CONFIDENTIAL char salt[8+BM_PASSPHRASE_BUF_LEN+1];
    CONFIDENTIAL char clean_mnemonic[BM_MNEMONIC_BUF_LEN];
    uint8_t m_len;
    uint8_t word_len;
    char *word_ptr;
    char *m_ptr;

    if(strlen(passphrase) > BM_PASSPHRASE_BUF_LEN){
        return E_INSUFFICIENT_BUF;
    }

    m_len = get_word_count(mnemonic);
    if (m_len!=12 && m_len!=18 && m_len!=24){
        return E_INVALID_MNEMONIC_LEN;
    }

    /* Filter out extra whitespace in mnemonic*/
    m_ptr = clean_mnemonic;
    for(uint8_t i=0; i<m_len; i++, m_ptr++){
        word_len = get_word_len(&word_ptr, mnemonic);
        mnemonic = word_ptr + word_len;
        memcpy(m_ptr, word_ptr, word_len);
        m_ptr += word_len;
        *m_ptr = ' ';
    }
    *(m_ptr-1) = '\0';

    memcpy(salt, "mnemonic", 8);
    strcpy(salt + 8, passphrase);
    pbkdf2_hmac_sha512(
            (uint8_t *) clean_mnemonic, strlen(clean_mnemonic), 
            (uint8_t *) salt, strlen(salt),
            (uint8_t *) master_seed, sizeof(uint512_t),
            2048);
    sodium_memzero(salt, strlen(salt));
    sodium_memzero(clean_mnemonic, strlen(clean_mnemonic));
    return E_SUCCESS;
}
