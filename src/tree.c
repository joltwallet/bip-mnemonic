/* bip-mnemonic - ESP32 Any functions related to seed/private keys for Nano
 Copyright (C) 2018  Brian Pugh, James Coxon, Michael Smaili
 https://www.joltwallet.com/
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include "sodium.h"
#include "sodium/private/common.h"
#include "freertos/FreeRTOS.h"
#include "esp_err.h"

#include "bipmnemonic.h"
#include "jolttypes.h"
#include "joltcrypto.h"

static inline unsigned int __bswap_32 (unsigned int __bsx)
{
  return ((((__bsx) & 0xff000000) >> 24) | (((__bsx) & 0x00ff0000) >>  8) |
	  (((__bsx) & 0x0000ff00) <<  8) | (((__bsx) & 0x000000ff) << 24));
}

static void hd_node_init(hd_node_t *node, const uint512_t master_seed, 
        const char *key){
    /* key - null-terminated string. Typically "ed25519 seed" or "Bitcoin Seed" */
    CONFIDENTIAL uint512_t digest;
    CONFIDENTIAL crypto_auth_hmacsha512_state state;

    crypto_auth_hmacsha512_init(&state, (uint8_t *)key, strlen(key));
    crypto_auth_hmacsha512_update(&state, master_seed, BIN_512);
    crypto_auth_hmacsha512_final(&state, digest);

    memcpy(node->key, digest, 32);
    memcpy(node->chain_code, digest + 32, 32);

    sodium_memzero(digest, sizeof(digest));
    sodium_memzero(&state, sizeof(state));
}

void hd_node_copy(hd_node_t *dst, hd_node_t *src) {
    memcpy(dst, src, sizeof(hd_node_t));
}

void hd_node_iterate(hd_node_t *node, uint32_t val) {
    /* Overwrites node values according to val */
    CONFIDENTIAL uint512_t digest;
    CONFIDENTIAL crypto_auth_hmacsha512_state state;
    unsigned char data[1+32+4] = {0};

    val = __bswap_32(val);

    memcpy(data+1, node->key, sizeof(node->key));
    memcpy(data+1+32, &val, sizeof(val) );

    crypto_auth_hmacsha512_init(&state, node->chain_code, sizeof(node->chain_code));
    crypto_auth_hmacsha512_update(&state, data, sizeof(data));
    crypto_auth_hmacsha512_final(&state, digest);

    memcpy(node->key, digest, 32);
    memcpy(node->chain_code, digest + 32, 32);

    sodium_memzero(digest, sizeof(digest));
    sodium_memzero(&state, sizeof(state));
}

static void vbm_master_seed_to_node(hd_node_t *node, uint512_t master_seed, char *bip32_key,
        uint8_t path_len, va_list ap) {
    /* Derives node from master_seed along specified path 
     *
     * Typically bip32_key is "Bitcoin seed" or "ed25519 seed"
     *
     * Each path should be a uint32_t;
     * Or the value with 0x80000000 to be hardened
     * */
    if( path_len <= 1 || bip32_key==NULL ) {
        return;
    }

    hd_node_init(node, master_seed, bip32_key);
    for(uint8_t i=0; i<path_len; i++) {
        hd_node_iterate(node, va_arg(ap, uint32_t));
    }
}
void bm_master_seed_to_node(hd_node_t *node, uint512_t master_seed, char *bip32_key,
        uint8_t path_len, ...) {
    va_list ap;
    va_start(ap, path_len);
    vbm_master_seed_to_node(node, master_seed, bip32_key, path_len, ap);
    va_end(ap);
}

void bm_master_seed_to_private_key(uint256_t private_key, uint512_t master_seed, char * bip32_key,
        uint8_t path_len, ...) {
    /* Stores results in private_key
     * Derives private_key from master_seed along specified path 
     *
     * Typically bip32_key is "Bitcoin seed" or "ed25519 seed"
     *
     * Each path should be a uint32_t;
     * Or the value with 0x80000000 to be hardened
     * */
    if( path_len <= 1 || bip32_key==NULL ) {
        return;
    }
    va_list ap;
    va_start(ap, path_len);
    CONFIDENTIAL hd_node_t node;
    vbm_master_seed_to_node(&node, master_seed, bip32_key, path_len, ap);
    va_end(ap);
    memcpy(private_key, node.key, sizeof(node.key));
    sodium_memzero( &node, sizeof(node) );
}
