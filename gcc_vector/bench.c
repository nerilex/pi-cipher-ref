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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "pi-cipher.h"
#include "crypto_aead.h"

char *algo_name = "pi-cipher";

/*****************************************************************************
 *  additional validation-functions                                          *
 *****************************************************************************/

#define NUMOF(x) (sizeof(x) / sizeof((x)[0]))



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


/*****************************************************************************
 *  main                                                                     *
 *****************************************************************************/

int main(int argc, char *argv[]) {

	unsigned long r = 1000;

	if (argc > 1) {
		r = strtoul(argv[1], NULL, 0);
	}

	uint8_t key[16]= {0};
	uint8_t nonce[16] = {0};
	uint8_t msg[PI_PT_BLOCK_LENGTH_BYTES * 4] = {0};
	PI_CTX ctx;
	PI_INIT(&ctx, key, sizeof(key), nonce, 4);
	PI_PROCESS_AD_LAST_BLOCK(&ctx, NULL, 0, 1);

	do {
		PI_ENCRYPT_BLOCK_Q(&ctx, msg, msg, r * 4);
	} while (--r);

	return 0;
}


