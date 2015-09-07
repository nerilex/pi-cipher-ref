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
#include "pi-cipher.h"

#include <stdio.h>

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

static word_t rotl(word_t x, uint8_t n)
{
    return (x << n) | (x >> (16 - n));
}

typedef word_t state_t[4][4];

uint8_t dump;

void dump_state(const word_t* a)
{
    if (dump) {
        printf("\tCIS:\n");
        printf("\t%04"PRIx16" %04"PRIx16" %04"PRIx16" %04"PRIx16"\n",   a[ 0], a[ 1], a[ 2], a[ 3]);
        printf("\t%04"PRIx16" %04"PRIx16" %04"PRIx16" %04"PRIx16"\n",   a[ 4], a[ 5], a[ 6], a[ 7]);
        printf("\t%04"PRIx16" %04"PRIx16" %04"PRIx16" %04"PRIx16"\n",   a[ 8], a[ 9], a[10], a[11]);
        printf("\t%04"PRIx16" %04"PRIx16" %04"PRIx16" %04"PRIx16"\n\n", a[12], a[13], a[14], a[15]);
    }
}

static uint64_t load_u64_little(const void *mem)
{
	uint64_t ret;
	const uint8_t *x = (const uint8_t *)mem;
	ret =   (uint64_t)x[0] <<  0
	      | (uint64_t)x[1] <<  8
	      | (uint64_t)x[2] << 16
	      | (uint64_t)x[3] << 24
	      | (uint64_t)x[4] << 32
	      | (uint64_t)x[5] << 40
	      | (uint64_t)x[6] << 48
	      | (uint64_t)x[7] << 56;
	return ret;
}

static uint32_t load_u32_little(const void *mem)
{
	uint32_t ret;
	const uint8_t *x = (const uint8_t *)mem;
	ret =   (uint32_t)x[0] <<  0
	      | (uint32_t)x[1] <<  8
	      | (uint32_t)x[2] << 16
	      | (uint32_t)x[3] << 24;
	return ret;
}

static uint16_t load_u16_little(const void *mem)
{
	uint16_t ret;
	const uint8_t *x = (const uint8_t *)mem;
	ret =   x[0] <<  0
	      | x[1] <<  8;
	return ret;
}

static void store_u64_little(void *mem, uint64_t val)
{
	uint8_t *x = (uint8_t *)mem;
	x[0] = val & 0xff; val >>= 8;
	x[1] = val & 0xff; val >>= 8;
	x[2] = val & 0xff; val >>= 8;
	x[3] = val & 0xff; val >>= 8;
	x[4] = val & 0xff; val >>= 8;
	x[5] = val & 0xff; val >>= 8;
	x[6] = val & 0xff; val >>= 8;
	x[7] = val & 0xff;
}

static void store_u32_little(void *mem, uint32_t val)
{
	uint8_t *x = (uint8_t *)mem;
	x[0] = val & 0xff; val >>= 8;
	x[1] = val & 0xff; val >>= 8;
	x[2] = val & 0xff; val >>= 8;
	x[3] = val & 0xff;
}

static void store_u16_little(void *mem, uint16_t val)
{
	uint8_t *x = (uint8_t *)mem;
	x[0] = val & 0xff; val >>= 8;
	x[1] = val & 0xff;
}

#if (PI_WORD_SIZE == 16)
#  define load_word_little(mem) load_u16_little(mem)
#  define store_word_little(mem, val) store_u16_little((mem), (val)
#elif (PI_WORD_SIZE == 32)
#  define load_word_little(mem) load_u32_little(mem)
#  define store_word_little(mem, val) store_u32_little((mem), (val)
#elif (PI_WORD_SIZE == 64)
#  define load_word_little(mem) load_u64_little(mem)
#  define store_word_little(mem, val) store_u64_little((mem), (val)
#endif

static void memxor(
		void *dest,
		const void *src,
		size_t length)
{
	char *d = (char *)dest;
	const char *s = (const char *)src;
	while(length--)
	{
		*d++ ^= *s++;
	}
}

static void phi(
        word_t dest[4],
        const word_t x[4],
        const word_t c[4],
        const uint8_t v[8],
        const uint8_t rot[4])
{
    word_t sum = 0;
    uint8_t i;
    i = 4;
    do {
        --i;
        sum += x[i];
    } while (i);
    i = 4;
    do {
        --i;
        dest[i] = rotl(
                c[i] +
                sum -
                x[v[i]],
                rot[i] );

    } while (i);
    sum = 0;
    i = 4;
    do {
        --i;
        sum ^= dest[i];
    } while (i);
    i = 4;
    do {
        --i;
        dest[i] ^= sum;
    } while (i);
}

static const word_t mu16_const[4] = PI_MU_CONST;

static const uint8_t mu16_v_const[4] = PI_MU_V_CONST;

static const uint8_t mu16_rot_const[4] = PI_MU_ROT_CONST;

static const word_t ny16_const[4] = PI_NY_CONST;

static const uint8_t ny16_v_const[4] = PI_NY_V_CONST;

static const uint8_t ny16_rot_const[4] = PI_NY_ROT_CONST;

static const word_t pi16_const[8][4] = PI_CONST;

static void mu(
        word_t dest[4],
        const word_t x[4])
{
    word_t t[4];
    phi(t, x, mu16_const, mu16_v_const, mu16_rot_const);
    dest[0] = t[2];
    dest[1] = t[3];
    dest[2] = t[0];
    dest[3] = t[1];
}

static void ny(
        word_t dest[4],
        const word_t x[4])
{
    phi(dest, x, ny16_const, ny16_v_const, ny16_rot_const);
}

static void sigma(
        word_t dest[4],
        const word_t x1[4],
        const word_t x2[4] )
{
    dest[3] = x1[0] + x2[0];
    dest[0] = x1[1] + x2[1];
    dest[1] = x1[2] + x2[2];
    dest[2] = x1[3] + x2[3];
}

static void ast(
        word_t dest[4],
        const word_t x[4],
        const word_t y[4] )
{
    word_t a[4], b[4];
    mu(a, x);
    ny(b, y);
    sigma(dest, a, b);
}

static void e1(
        word_t *dest,
        const word_t c[4],
        const word_t *i,
        uint8_t n )
{
    {
        word_t t[4];
        memcpy(t, c, sizeof(word_t) * 4);
        ast(dest, t, i);
    }
    --n;
    do {
        i = &i[4];
        ast(&dest[4], dest, i);
        dest = &dest[4];
    } while (--n);
}

static void e2(
        word_t *dest,
        const word_t c[4],
        const word_t *i,
        uint8_t n )
{
    --n;
    {
        word_t t[4];
        memcpy(t, c, sizeof(word_t) * 4);
        ast(&dest[4 * n], &i[4 * n], t);
    }
    while (n--) {
        ast(&dest[4 * n], &i[4 * n], &dest[4 * (n + 1)]);
    }
}

static void pi(
        word_t *a )
{
    uint8_t r = PI_ROUNDS;
    word_t t[4 * 4];
    const word_t *c = (const word_t *)pi16_const;
    do {
        e1(t, c, a, 4);
        c = &c[4];
        e2(a, c, t, 4);
        c = &c[4];
    } while (--r);
}

static void add_tag(
        PI_CTX *ctx,
        state_t a )
{
    uint8_t i;
    i = 3;
    do {
        ctx->tag[i + 0] += a[0][i];
        ctx->tag[i + 4] += a[2][i];
    } while(i--);
}

static void ctr_trans16(
        const PI_CTX *ctx,
        state_t a,
        uint16_t ctr )
{
    uint64_t t;
    if ((void *)ctx->cis != (void *)a) {
        memcpy(a, ctx->cis, sizeof(state_t));
    }
    t = ctx->ctr + ctr;
    a[0][0] ^= t >> 48;
    a[0][1] ^= t >> 32;
    a[0][2] ^= t >> 16;
    a[0][3] ^= t >>  0;
    pi((word_t*)a);
}

static void inject_block(
        state_t a,
        const void *block )
{
    memxor(&a[0][0], block, 8);
    memxor(&a[2][0], &((uint8_t*)block)[8], 8);
}

static void replace_block(
        state_t a,
        const void *block )
{
    memcpy(&a[0][0], block, 8);
    memcpy(&a[2][0], &((uint8_t*)block)[8], 8);
}

static void extract_block(
        void *block,
        state_t a)
{
    memcpy(block, a, 8);
    memcpy(&((uint8_t*)block)[8], &a[2][0], 8);
}


static void inject_last_block(
        state_t a,
        const void *block,
        uint16_t length_b )
{
    uint8_t t[PI_RATE_BYTES];
    if (length_b >= PI_RATE_BITS) {
        /* error */
        return;
    }
    memset(t, 0, sizeof(t));
    memcpy(t, block, (length_b + 7) / 8);
    t[length_b / 8] |= 1 << (length_b & 7);
    memxor(&a[0][0], t, 8);
    memxor(&a[2][0], &t[8], 8);
}

int8_t PI_INIT(
        PI_CTX *ctx,
        const void *key,
        uint16_t key_length_b,
        const void *pmn,
        uint16_t pmn_length_b)
{
    if (key_length_b / 8 + pmn_length_b / 8 + 1 > 4 * 4 * 2) {
        return -1;
    }
    memset(ctx->tag, 0, sizeof(ctx->tag));
    memset(ctx->cis, 0, sizeof(ctx->cis));
    memcpy(ctx->cis, key, key_length_b / 8);
    memcpy(&((uint8_t*)ctx->cis)[key_length_b / 8], pmn, pmn_length_b / 8);
    ((uint8_t*)ctx->cis)[key_length_b / 8 + pmn_length_b / 8] = 1;
    dump_state((word_t*)ctx->cis);
    pi((word_t*)ctx->cis);
    dump_state((word_t*)ctx->cis);
    memcpy(&ctx->ctr, &ctx->cis[1][0], 64 / 8);

    ctx->ctr  = (uint64_t)ctx->cis[1][0] << 48;
    ctx->ctr |= (uint64_t)ctx->cis[1][1] << 32;
    ctx->ctr |= (uint64_t)ctx->cis[1][2] << 16;
    ctx->ctr |= (uint64_t)ctx->cis[1][3] <<  0;

    printf("ctr: %08"PRIx32"%08"PRIx32"\n",  (uint32_t)(ctx->ctr >> 32), (uint32_t)ctx->ctr);
    return 0;
}

void PI_PROCESS_AD_BLOCK(
        PI_CTX *ctx,
        const void *ad,
        uint16_t ad_num )
{
    state_t a;
    ctr_trans16(ctx, a, ad_num);
    inject_block(a, ad);
    pi((word_t*)a);
    add_tag(ctx, a);
}

void PI_PROCESS_AD_LAST_BLOCK(
        PI_CTX *ctx,
        const void *ad,
        uint16_t ad_length_b,
        uint16_t ad_num )
{
    state_t a;
    while (ad_length_b >= PI_AD_BLOCK_LENGTH_BITS) {
        pi16_process_ad_block(ctx, ad, ad_num);
        ad_num++;
        ad_length_b -= PI_AD_BLOCK_LENGTH_BITS;
        ad = &((uint8_t*)ad)[PI_AD_BLOCK_LENGTH_BYTES];
    }

    ctr_trans16(ctx, a, ad_num);
    inject_last_block(a, ad, ad_length_b);
    pi((word_t*)a);
    {
        int q;
        printf("tempTag: ");
        for (q = 0; q < sizeof(ctx->tag) / sizeof(ctx->tag[0]); q++) {
            printf("%04"PRIx16" ", ctx->tag[q]);
        }
        printf("\n");
    }
    add_tag(ctx, a);
    ctx->ctr += ad_num;
    {
        int q;
        printf("tempTag: ");
        for (q = 0; q < sizeof(ctx->tag) / sizeof(ctx->tag[0]); q++) {
            printf("%04"PRIx16" ", ctx->tag[q]);
        }
        printf("\n");
    }
    inject_block(ctx->cis, ctx->tag);
    pi((word_t*)ctx->cis);
}

void PI_PROCESS_SMN(
        PI_CTX *ctx,
        void *c0,
        const void *smn)
{
    ctx->ctr++;
    ctr_trans16(ctx, ctx->cis, 0);
    inject_block(ctx->cis, smn);
    if (c0) {
        extract_block(c0, ctx->cis);
    }
    pi((word_t*)ctx->cis);
    add_tag(ctx, ctx->cis);
}

void PI_ENCRYPT_BLOCK(
        PI_CTX *ctx,
        void *dest,
        const void *src,
        uint16_t num )
{
    state_t a;
    ctr_trans16(ctx, a, num);
    inject_block(a, src);
    if (dest) {
        extract_block(dest, a);
    }
    pi((word_t*)a);
    add_tag(ctx, a);
}

void PI_ENCRYPT_LAST_BLOCK(
        PI_CTX *ctx,
        void *dest,
        const void *src,
        uint16_t length_b,
        uint16_t num )
{
    state_t a;
    while (length_b >= PI_PT_BLOCK_LENGTH_BITS) {
        pi16_encrypt_block(ctx, dest, src, num);
        num++;
        length_b -= PI_PT_BLOCK_LENGTH_BITS;
        src = &((uint8_t*)src)[PI_PT_BLOCK_LENGTH_BYTES];
        if (dest) {
            dest = &((uint8_t*)dest)[PI_CT_BLOCK_LENGTH_BYTES];
        }
    }
    ctr_trans16(ctx, a, num);
    inject_last_block(a, src, length_b);
    if (dest) {
        uint8_t tmp[PI_PT_BLOCK_LENGTH_BYTES];
        extract_block(tmp, a);
        memcpy(dest, tmp, (length_b + 7) / 8);
    }
    pi((word_t*)a);
    add_tag(ctx, a);
}

void PI_EXTRACT_TAG(
        PI_CTX *ctx,
        void *dest )
{
    memcpy(dest, ctx->tag, PI_TAG_BYTES);
}

void PI_DECRYPT_BLOCK(
        PI_CTX *ctx,
        void *dest,
        const void *src,
        uint16_t num )
{
    state_t a;
    ctr_trans16(ctx, a, num);
    inject_block(a, src);
    if (dest) {
        extract_block(dest, a);
    }
    replace_block(a, src);
    pi((word_t*)a);
    add_tag(ctx, a);
}

#define GET_BIT(buf, addr) ((((uint8_t*)(buf))[(addr) / 8] >> (addr & 7)) & 1)

void PI_DECRYPT_LAST_BLOCK(
        PI_CTX *ctx,
        void *dest,
        const void *src,
        uint16_t *length_b,
        uint16_t num )
{
    pi16_decrypt_block(ctx, dest, src, num);
    *length_b = PI_CT_BLOCK_LENGTH_BITS;
    while (*length_b > 0 && GET_BIT(dest, *length_b) == 0)
    {
        --length_b;
    }
}

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
        )
{
    unsigned i;
    PI_CTX ctx;
    dump = 0;
    if (pi16_init(&ctx, key, key_len_B * 8, nonce_public, nonce_public_len_B * 8)) {
        printf("ERROR! <%s %s %d>\n", __FILE__, __func__, __LINE__);
        return;
    }
    i = 1;
    dump_state((word_t*)ctx.cis);
    dump = 0;
    while (ad_len_B > PI_AD_BLOCK_LENGTH_BYTES) {
        pi16_process_ad_block(&ctx, ad, i++);
        ad_len_B -= PI_AD_BLOCK_LENGTH_BYTES;
        ad = &((const uint8_t*)ad)[PI_AD_BLOCK_LENGTH_BYTES];
    }
    dump = 1;
    pi16_process_ad_last_block(&ctx, ad, ad_len_B * 8, i);
    dump_state((word_t*)ctx.cis);
    *cipher_len_B = 0;
    if (nonce_secret) {
        pi16_process_smn(&ctx, cipher, nonce_secret);
        *cipher_len_B += PI_CT_BLOCK_LENGTH_BYTES;
        cipher = &((uint8_t*)cipher)[PI_CT_BLOCK_LENGTH_BYTES];
    }
    i = 1;
    while (msg_len_B > PI_PT_BLOCK_LENGTH_BYTES) {
        pi16_encrypt_block(&ctx, cipher, msg, i++);
        msg = &((const uint8_t*)msg)[PI_PT_BLOCK_LENGTH_BYTES];
        cipher = &((uint8_t*)cipher)[PI_CT_BLOCK_LENGTH_BYTES];
        *cipher_len_B += PI_CT_BLOCK_LENGTH_BYTES;
        msg_len_B -= PI_PT_BLOCK_LENGTH_BYTES;
    }
    pi16_encrypt_last_block(&ctx, cipher, msg, msg_len_B * 8, i);
    *cipher_len_B += msg_len_B;
    pi16_extract_tag(&ctx, tag);
    *tag_length_B = PI_TAG_BYTES;
}

