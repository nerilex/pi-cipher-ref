/*
 * test_001.c
 *
 *  Created on: 13.10.2015
 *      Author: bg
 */

#include <stdio.h>
#include <inttypes.h>
#include "pi16_parameter.h"

typedef uint16_t word_t;
typedef word_t chunk_t __attribute__((vector_size(4 * sizeof(word_t))));
typedef chunk_t qchunk_t[4];

#define ROTL(x, n) (((x) << (n)) | ((x) >> (sizeof(word_t) * 8 - (n))))

static inline chunk_t rotl_q(chunk_t x, uint8_t n)
{
    return (x << n) | (x >> ((PI_WORD_SIZE) - n));
}

static inline
void mu_q (
		qchunk_t dest,
        const qchunk_t x)
{
    chunk_t sum = x[0] + x[1] + x[2] + x[3];
    dest[0] = rotl_q( PI_MU_CONST_0 + sum - x[3], PI_MU_ROT_CONST_0 );
    dest[1] = rotl_q( PI_MU_CONST_1 + sum - x[2], PI_MU_ROT_CONST_1 );
    dest[2] = rotl_q( PI_MU_CONST_2 + sum - x[1], PI_MU_ROT_CONST_2 );
    dest[3] = rotl_q( PI_MU_CONST_3 + sum - x[0], PI_MU_ROT_CONST_3 );
    sum = dest[0] ^ dest[1] ^ dest[2] ^ dest[3];
    dest[0] ^= sum;
    dest[1] ^= sum;
    dest[2] ^= sum;
    dest[3] ^= sum;
}

#define NUMOF(x) (sizeof(x) / sizeof((x)[0]))

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




/*****************************************************************************
 *  main                                                                     *
 *****************************************************************************/

int main(void) {
	printf("Testsystem for mu16\n"); fflush(NULL);

	qchunk_t x =
	{ { 46258, 46258, 46258, 46258 },
	  { 45484, 45484, 45484, 45484 },
	  { 43689, 43689, 43689, 43689 },
	  { 42661, 42661, 42661, 42661 } }, y;

	printf("== x ==\n");
	hexdump_block(&x, sizeof(x), 4, 8);
	mu_q(y, x);
	printf("\n== y ==\n");
	hexdump_block(&y, sizeof(y), 4, 8);
	putchar('\n');
	return 0;
}
