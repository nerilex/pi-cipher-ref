/* main-norx-test.c */
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


/* main-arcfour-test.c */
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
/*
 * arcfour (RC4 compatible) test-suit
 *
*/

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "pi-cipher.h"
#include "crypto_aead.h"

char *algo_name = "pi-cipher";

/*****************************************************************************
 *  additional validation-functions                                          *
 *****************************************************************************/

#define NUMOF(x) (sizeof(x) / sizeof((x)[0]))

static
void hexdump_block(
		const void *data,
		size_t length,
		unsigned short indent,
		unsigned short width)
{
	unsigned short column = 0;
	char f = 0;
	while (length--) {
		if (column == 0) {
			unsigned short i;
			if (f) {
				putchar('\n');
			} else {
				f = 1;
			}
			for (i = 0; i < indent; ++i) {
				putchar(' ');
			}
			column = width;
		}
		column -= 1;
		printf("%02x ", *((unsigned char *)data));
		data = (void *)((char *)data + 1);
	}
}

#define DUMP_LEN(x, l) do {                  \
	printf("\n%10s\n", #x ":");              \
	hexdump_block((x), l, 12, 16);           \
} while (0)


#define DUMP(x) DUMP_LEN(x, (sizeof(x)))



/*
 * int crypto_aead_encrypt(
	unsigned char *c,unsigned long long *clen,
	const unsigned char *m,unsigned long long mlen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k
);

int crypto_aead_decrypt(
	unsigned char *m,unsigned long long *mlen,
	unsigned char *nsec,
	const unsigned char *c,unsigned long long clen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
);

 *
 */

struct {
	uint8_t s[256];
	uint8_t i, j;
} arcfour_ctx;

void init_prng(const void *key, size_t length) {
	uint8_t t, i = 0, j = 0;
	do {
		arcfour_ctx.s[i] = i;
	} while (++i);

	do {
		t = arcfour_ctx.s[i];
		j += t + ((uint8_t *)key)[i % length];
		arcfour_ctx.s[i] = arcfour_ctx.s[j];
		arcfour_ctx.s[j] = t;
	} while (++i);

	arcfour_ctx.i = 0;
	arcfour_ctx.j = 0;
}

uint8_t get_random_byte(void) {
	uint8_t t;
	arcfour_ctx.i += 1;
	arcfour_ctx.j += arcfour_ctx.s[arcfour_ctx.i];
	t = arcfour_ctx.s[arcfour_ctx.i];
	arcfour_ctx.s[arcfour_ctx.i] = arcfour_ctx.s[arcfour_ctx.j];
	arcfour_ctx.s[arcfour_ctx.j] = t;
	return arcfour_ctx.s[(uint8_t)(arcfour_ctx.s[arcfour_ctx.i] + arcfour_ctx.s[arcfour_ctx.j])];
}

void fill_random(void *buf, size_t length) {
	while (length--) {
		*(uint8_t *)buf = get_random_byte();
		buf = (uint8_t *)buf + 1;
	}
}

void print_item(const char *label, const void* data, size_t length) {
	printf("%s (%zu) = ", label, length);
	while (length--) {
		printf("%02X", *(uint8_t*)data);
		data = (uint8_t*)data + 1;
	}
	putchar('\n');
}

void generate_single_testvector(
		const uint8_t *m, size_t mlen,
		const uint8_t *ad, size_t adlen,
		const uint8_t *nsec,
		const uint8_t *npub, size_t npub_len,
		const uint8_t *key, size_t key_len
	) {
	uint8_t c[PI_CT_BLOCK_LENGTH_BYTES + mlen + PI_TAG_BYTES];
	uint8_t m_check[mlen];
	uint8_t nsec_check[PI_PT_BLOCK_LENGTH_BYTES];
	size_t clen, mlen_check;
	int v;

	print_item("KEY", key, key_len);
	print_item("NPUB", npub, npub_len);
	print_item("NSEC", nsec, PI_PT_BLOCK_LENGTH_BYTES);
	print_item("MSG", m, mlen);
	print_item("AD", ad, adlen);

	fflush(stdout);
	PI_ENCRYPT_SIMPLE(c, &clen, &c[sizeof(c) - PI_TAG_BYTES], NULL, m, mlen, ad, adlen, nsec, npub, npub_len, key, key_len);

	print_item("CIPHER", c, clen + PI_TAG_BYTES);
	fflush(stdout);

	v = PI_DECRYPT_SIMPLE(m_check, &mlen_check, nsec_check, c, clen + PI_TAG_BYTES, ad, adlen, npub, npub_len, key, key_len);

	if (v) {
		printf("!verification failed (%d)\n", v);
	}

	if (mlen != mlen_check || memcmp(m, m_check, mlen)) {
		print_item("!ERROR MSG", m_check, mlen_check);
	}
	if (memcmp(nsec, nsec_check, PI_PT_BLOCK_LENGTH_BYTES)) {
		print_item("!ERROR MSG", m_check, mlen_check);
	}
	putchar('\n');
	fflush(stdout);
}

void generate_testvectors(size_t key_len, size_t npub_len) {
	size_t ad_len, msg_len, i, c = 1;
	uint8_t ad[3 * PI_PT_BLOCK_LENGTH_BYTES / 2];
	uint8_t msg[3 * PI_PT_BLOCK_LENGTH_BYTES / 2];
	uint8_t key[key_len];
	uint8_t npub[npub_len];
	uint8_t nsec[PI_PT_BLOCK_LENGTH_BYTES];
	{
		char seed[64];
		snprintf(seed, sizeof(seed), "%s%03zuv2 (%zu byte nonce)", pi_cipher_name, key_len * 8, npub_len);
		init_prng(seed, strlen(seed));
	}
	for (msg_len = 0; msg_len <= sizeof(msg); ++msg_len) {
		for (ad_len = 0; ad_len <= sizeof(ad); ++ad_len) {
			printf("[msg_len = %zu]\n", msg_len);
			printf("[ad_len = %zu]\n\n", ad_len);
			for (i = 0; i < 8; ++i) {
				printf("[vector #%zu (%zu)]\n", c, i + 1);
				++c;
				fill_random(key, sizeof(key));
				fill_random(npub, sizeof(npub));
				fill_random(nsec, sizeof(nsec));
				fill_random(ad, ad_len);
				fill_random(msg, msg_len);
				generate_single_testvector(msg, msg_len, ad, ad_len, nsec, npub, npub_len, key, key_len);
			}
		}
	}
}

/*****************************************************************************
 *  main                                                                     *
 *****************************************************************************/

int main(void) {
	printf("Testsystem for %s\n", pi_cipher_name); fflush(NULL);

#if PI_SIZE == 16
	size_t key_sizes[] = { 96, 128 };
	size_t npub_sizes[] = { 4 };
#elif PI_SIZE == 32
	size_t key_sizes[] = { 128, 256 };
	size_t npub_sizes[] = { 16 };
#elif PI_SIZE == 64
	size_t key_sizes[] = { 128, 256 };
	size_t npub_sizes[] = { 16 };
#else
#error
#endif

	int i, j;
	char fname[128];
	for (i = 0; i < NUMOF(key_sizes); ++i) {
		for (j = 0; j < NUMOF(npub_sizes); ++j) {
			snprintf(fname, sizeof(fname), "testvectors/%s%03zuv2_%zu.test-vectors", pi_cipher_name, key_sizes[i], npub_sizes[j]);
			freopen(fname, "w", stdout);
			printf("# Testvectors for %s\n", pi_cipher_name);
			printf("#   key size: %zu bits\n", key_sizes[i]);
			printf("#   nonce size: %zu bits\n\n", npub_sizes[j] * 8);
			generate_testvectors(key_sizes[i] / 8, npub_sizes[j]);
			fclose(stdout);
		}
	}

}


