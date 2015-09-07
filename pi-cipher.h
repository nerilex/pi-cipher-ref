/* pi16cipher.h */
/*
    This file is part of the AVR-Crypto-Lib.
    Copyright (C) 2015 Daniel Otte (daniel.otte@rub.de)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef PI_CIPHER_H_
#define PI_CIPHER_H_

/* pi16cipher.c */
/*
    This file is part of the AVR-Crypto-Lib.
    Copyright (C) 2006-2015 Daniel Otte (bg@nerilex.org)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "pi16_parameter.h"

#define PI_N 4

#define PI_IS_BITS (4 * PI_N * PI_WORD_SIZE)

#define PI_RATE_BITS (PI_IS_BITS / 2)
#define PI_CAPACITY_BITS PI_BITS - PI_RATE_BITS

#define PI_RATE_BYTES (PI_RATE_BITS / 8)
#define PI_CAPACITY_BYTES (PI_CAPACITY_BITS / 8)

#define PI_SMN_LENGTH_BITS  PI_RATE_BITS
#define PI_SMN_LENGTH_BYTES (PI_RATE_BITS / 8)

#define PI_AD_BLOCK_LENGTH_BITS PI_RATE_BITS
#define PI_AD_BLOCK_LENGTH_BYTES (PI_AD_BLOCK_LENGTH_BITS / 8)

#define PI_PT_BLOCK_LENGTH_BITS PI_RATE_BITS
#define PI_PT_BLOCK_LENGTH_BYTES (PI_PT_BLOCK_LENGTH_BITS / 8)

#define PI_CT_BLOCK_LENGTH_BITS PI_RATE_BITS
#define PI_CT_BLOCK_LENGTH_BYTES (PI_CT_BLOCK_LENGTH_BITS / 8)

#define PI_ROUNDS 3


#define CTX_NAME(x)                     pi ## x ## _ctx_t
#define INIT_NAME(x)                    pi ## x ## _init
#define PROCESS_AD_BLOCK_NAME(x)        pi ## x ## _process_ad_block
#define PROCESS_AD_LAST_BLOCK_NAME(x)   pi ## x ## _process_ad_last_block
#define PROCESS_SMN_NAME(x)             pi ## x ## _process_smn
#define ENCRYPT_BLOCK_NAME(x)           pi ## x ## _encrypt_block
#define ENCRYPT_LAST_BLOCK_NAME(x)      pi ## x ## _encrypt_last_block
#define EXTRACT_TAG_NAME(x)             pi ## x ## _extract_tag
#define DECRYPT_BLOCK_NAME(x)           pi ## x ## _decrypt_block
#define DECRYPT_LAST_BLOCK_NAME(x)      pi ## x ## _decrypt_last_block
#define ENCRYPT_SIMPLE_NAME(x)          pi ## x ## _encrypt_simple

#define NAME(f,x) f(x)

#define PI_CTX                          NAME(CTX_NAME, PI_WORD_SIZE)
#define PI_INIT                         NAME(INIT_NAME, PI_WORD_SIZE)
#define PI_PROCESS_AD_BLOCK             NAME(PROCESS_AD_BLOCK_NAME, PI_WORD_SIZE)
#define PI_PROCESS_AD_LAST_BLOCK        NAME(PROCESS_AD_LAST_BLOCK_NAME, PI_WORD_SIZE)
#define PI_PROCESS_SMN                  NAME(PROCESS_SMN_NAME, PI_WORD_SIZE)
#define PI_ENCRYPT_BLOCK                NAME(ENCRYPT_BLOCK_NAME, PI_WORD_SIZE)
#define PI_ENCRYPT_LAST_BLOCK           NAME(ENCRYPT_LAST_BLOCK_NAME, PI_WORD_SIZE)
#define PI_EXTRACT_TAG                  NAME(EXTRACT_TAG_NAME, PI_WORD_SIZE)
#define PI_DECRYPT_BLOCK                NAME(DECRYPT_BLOCK_NAME, PI_WORD_SIZE)
#define PI_DECRYPT_LAST_BLOCK           NAME(DECRYPT_LAST_BLOCK_NAME, PI_WORD_SIZE)
#define PI_ENCRYPT_SIMPLE               NAME(ENCRYPT_SIMPLE_NAME, PI_WORD_SIZE)

typedef struct {
    word_t cis[4][4];
    word_t tag[8];
    uint64_t ctr;
} PI_CTX;

int8_t PI_INIT(
        PI_CTX *ctx,
        const void *key,
        uint16_t key_length_b,
        const void *pmn,
        uint16_t pmn_length_b);

void PI_PROCESS_AD_BLOCK(
        PI_CTX *ctx,
        const void *ad,
        uint16_t ad_num );

void PI_PROCESS_AD_LAST_BLOCK(
        PI_CTX *ctx,
        const void *ad,
        uint16_t ad_length_b,
        uint16_t ad_num );

void PI_PROCESS_SMN(
        PI_CTX *ctx,
        void *c0,
        const void *smn);

void PI_ENCRYPT_BLOCK(
        PI_CTX *ctx,
        void *dest,
        const void *src,
        uint16_t num );

void PI_ENCRYPT_LAST_BLOCK(
        PI_CTX *ctx,
        void *dest,
        const void *src,
        uint16_t length_b,
        uint16_t num );

void PI_EXTRACT_TAG(
        PI_CTX *ctx,
        void *dest );

void PI_DECRYPT_BLOCK(
        PI_CTX *ctx,
        void *dest,
        const void *src,
        uint16_t num );

void PI_DECRYPT_LAST_BLOCK(
        PI_CTX *ctx,
        void *dest,
        const void *src,
        uint16_t *length_b,
        uint16_t num );

void PI_ENCRYPT_SIMPLE(
        void *cipher,
        uint16_t *cipher_len_B,
        void *tag,
        uint16_t *tag_length_B,
        const void *msg,
        uint16_t msg_len_B,
        const void *ad,
        uint16_t ad_len_B,
        const void *nonce_secret,
        const void *nonce_public,
        uint16_t nonce_public_len_B,
        const void *key,
        uint16_t key_len_B
        );


#endif /* PI_CIPHER_H_ */