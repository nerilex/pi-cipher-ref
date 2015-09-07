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
#include "pi-cipher.h"

char *algo_name = "pi16cipher";

/*****************************************************************************
 *  additional validation-functions                                          *
 *****************************************************************************/

hexdump_block(
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


void testrun_pi16(void)
{
    const uint8_t key[16] = { 0 };
    const uint8_t msg[1] = { 0xf };
    const uint8_t ad[1] = { 0 };
    const uint8_t nsec[16] = { 0 };
    const uint8_t npub[4] = { 0 };
    uint8_t crypt[16 + 1];
    uint8_t tag[16];
    uint16_t crypt_len, tag_len;
    pi16_encrypt_simple(crypt, &crypt_len, tag, &tag_len, msg, sizeof(msg), ad, sizeof(ad), nsec, npub, sizeof(npub), key, sizeof(key));
    DUMP(key);
    DUMP(msg);
    DUMP(ad);
    DUMP(nsec);
    DUMP(npub);
    DUMP(crypt);
    DUMP(tag);
    puts("");
}

int crypto_aead_encrypt(
unsigned char *c,unsigned long long *clen,
const unsigned char *m,unsigned long long mlen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *nsec,
const unsigned char *npub,
const unsigned char *k
);

void testrun_pi16_ref(void)
{
    const char key[16] = { 0 };
    const char msg[1] = { 0xf };
    const char ad[1] = { 0 };
    const char nsec[16] = { 0 };
    const char npub[4] = { 0 };
    unsigned char crypt[16 + 1 + 16];
    uint8_t* tag = &crypt[16 + 1];
    unsigned long long crypt_len = 16 + 1, tag_len = 16;
    crypto_aead_encrypt(crypt, &crypt_len, msg, sizeof(msg), ad, sizeof(ad), nsec, npub, key);
    DUMP(key);
    DUMP(msg);
    DUMP(ad);
    DUMP(nsec);
    DUMP(npub);
    DUMP_LEN(crypt, 16 + 1);
    DUMP_LEN(tag, tag_len);
    puts("");
}


/*****************************************************************************
 *  main                                                                     *
 *****************************************************************************/

int main(void) {

    testrun_pi16();

    testrun_pi16_ref();
}


