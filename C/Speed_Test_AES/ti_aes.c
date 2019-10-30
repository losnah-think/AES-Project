/**************************************************************
						AES128
Author:   Uli Kretzschmar
			 MSP430 Systems
			 Freising
AES software support for encryption and decryption
ECCN 5D002 TSU - Technology / Software Unrestricted
**************************************************************/
#pragma warning(disable:4996)
#include "msp430x26x.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <io.h>
#define False 0
#define True 1
// foreward sbox
const unsigned char sbox[256] = {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; //F   
	// inverse sbox
const unsigned char rsbox[256] =
{ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb
, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb
, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e
, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25
, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92
, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84
, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06
, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b
, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73
, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e
, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b
, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4
, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f
, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef
, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61
, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
// round constant
const unsigned char Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

static const unsigned char pr2six[256] =
{
	/* Base64 ASCII table */
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
	64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
	64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
	64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

static const char basis_64[] =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// expand the key
void expandKey(unsigned char *expandedKey,
	unsigned char *key)
{
	unsigned short ii, buf1;
	for (ii = 0; ii < 16; ii++)
		expandedKey[ii] = key[ii];
	for (ii = 1; ii < 11; ii++) {
		buf1 = expandedKey[ii * 16 - 4];
		expandedKey[ii * 16 + 0] = sbox[expandedKey[ii * 16 - 3]] ^ expandedKey[(ii - 1) * 16 + 0] ^ Rcon[ii];
		expandedKey[ii * 16 + 1] = sbox[expandedKey[ii * 16 - 2]] ^ expandedKey[(ii - 1) * 16 + 1];
		expandedKey[ii * 16 + 2] = sbox[expandedKey[ii * 16 - 1]] ^ expandedKey[(ii - 1) * 16 + 2];
		expandedKey[ii * 16 + 3] = sbox[buf1] ^ expandedKey[(ii - 1) * 16 + 3];
		expandedKey[ii * 16 + 4] = expandedKey[(ii - 1) * 16 + 4] ^ expandedKey[ii * 16 + 0];
		expandedKey[ii * 16 + 5] = expandedKey[(ii - 1) * 16 + 5] ^ expandedKey[ii * 16 + 1];
		expandedKey[ii * 16 + 6] = expandedKey[(ii - 1) * 16 + 6] ^ expandedKey[ii * 16 + 2];
		expandedKey[ii * 16 + 7] = expandedKey[(ii - 1) * 16 + 7] ^ expandedKey[ii * 16 + 3];
		expandedKey[ii * 16 + 8] = expandedKey[(ii - 1) * 16 + 8] ^ expandedKey[ii * 16 + 4];
		expandedKey[ii * 16 + 9] = expandedKey[(ii - 1) * 16 + 9] ^ expandedKey[ii * 16 + 5];
		expandedKey[ii * 16 + 10] = expandedKey[(ii - 1) * 16 + 10] ^ expandedKey[ii * 16 + 6];
		expandedKey[ii * 16 + 11] = expandedKey[(ii - 1) * 16 + 11] ^ expandedKey[ii * 16 + 7];
		expandedKey[ii * 16 + 12] = expandedKey[(ii - 1) * 16 + 12] ^ expandedKey[ii * 16 + 8];
		expandedKey[ii * 16 + 13] = expandedKey[(ii - 1) * 16 + 13] ^ expandedKey[ii * 16 + 9];
		expandedKey[ii * 16 + 14] = expandedKey[(ii - 1) * 16 + 14] ^ expandedKey[ii * 16 + 10];
		expandedKey[ii * 16 + 15] = expandedKey[(ii - 1) * 16 + 15] ^ expandedKey[ii * 16 + 11];
	}


}

// multiply by 2 in the galois field
unsigned char galois_mul2(unsigned char value)
{
	if (value >> 7)
	{
		value = value << 1;
		return (value ^ 0x1b);
	}
	else
		return value << 1;
}

// straight foreward aes encryption implementation
//   first the group of operations
//     - addroundkey
//     - subbytes
//     - shiftrows
//     - mixcolums
//   is executed 9 times, after this addroundkey to finish the 9th round, 
//   after that the 10th round without mixcolums
//   no further subfunctions to save cycles for function calls
//   no structuring with "for (....)" to save cycles
void aes_encr(unsigned char *state, unsigned char *expandedKey)
{
	unsigned char buf1, buf2, buf3, round;


	for (round = 0; round < 9; round++) {
		// addroundkey, sbox and shiftrows
		// row 0
		state[0] = sbox[(state[0] ^ expandedKey[(round * 16)])];
		state[4] = sbox[(state[4] ^ expandedKey[(round * 16) + 4])];
		state[8] = sbox[(state[8] ^ expandedKey[(round * 16) + 8])];
		state[12] = sbox[(state[12] ^ expandedKey[(round * 16) + 12])];
		// row 1
		buf1 = state[1] ^ expandedKey[(round * 16) + 1];
		state[1] = sbox[(state[5] ^ expandedKey[(round * 16) + 5])];
		state[5] = sbox[(state[9] ^ expandedKey[(round * 16) + 9])];
		state[9] = sbox[(state[13] ^ expandedKey[(round * 16) + 13])];
		state[13] = sbox[buf1];
		// row 2
		buf1 = state[2] ^ expandedKey[(round * 16) + 2];
		buf2 = state[6] ^ expandedKey[(round * 16) + 6];
		state[2] = sbox[(state[10] ^ expandedKey[(round * 16) + 10])];
		state[6] = sbox[(state[14] ^ expandedKey[(round * 16) + 14])];
		state[10] = sbox[buf1];
		state[14] = sbox[buf2];
		// row 3
		buf1 = state[15] ^ expandedKey[(round * 16) + 15];
		state[15] = sbox[(state[11] ^ expandedKey[(round * 16) + 11])];
		state[11] = sbox[(state[7] ^ expandedKey[(round * 16) + 7])];
		state[7] = sbox[(state[3] ^ expandedKey[(round * 16) + 3])];
		state[3] = sbox[buf1];

		// mixcolums //////////
		// col1
		buf1 = state[0] ^ state[1] ^ state[2] ^ state[3];
		buf2 = state[0];
		buf3 = state[0] ^ state[1]; buf3 = galois_mul2(buf3); state[0] = state[0] ^ buf3 ^ buf1;
		buf3 = state[1] ^ state[2]; buf3 = galois_mul2(buf3); state[1] = state[1] ^ buf3 ^ buf1;
		buf3 = state[2] ^ state[3]; buf3 = galois_mul2(buf3); state[2] = state[2] ^ buf3 ^ buf1;
		buf3 = state[3] ^ buf2;     buf3 = galois_mul2(buf3); state[3] = state[3] ^ buf3 ^ buf1;
		// col2
		buf1 = state[4] ^ state[5] ^ state[6] ^ state[7];
		buf2 = state[4];
		buf3 = state[4] ^ state[5]; buf3 = galois_mul2(buf3); state[4] = state[4] ^ buf3 ^ buf1;
		buf3 = state[5] ^ state[6]; buf3 = galois_mul2(buf3); state[5] = state[5] ^ buf3 ^ buf1;
		buf3 = state[6] ^ state[7]; buf3 = galois_mul2(buf3); state[6] = state[6] ^ buf3 ^ buf1;
		buf3 = state[7] ^ buf2;     buf3 = galois_mul2(buf3); state[7] = state[7] ^ buf3 ^ buf1;
		// col3
		buf1 = state[8] ^ state[9] ^ state[10] ^ state[11];
		buf2 = state[8];
		buf3 = state[8] ^ state[9];   buf3 = galois_mul2(buf3); state[8] = state[8] ^ buf3 ^ buf1;
		buf3 = state[9] ^ state[10];  buf3 = galois_mul2(buf3); state[9] = state[9] ^ buf3 ^ buf1;
		buf3 = state[10] ^ state[11]; buf3 = galois_mul2(buf3); state[10] = state[10] ^ buf3 ^ buf1;
		buf3 = state[11] ^ buf2;      buf3 = galois_mul2(buf3); state[11] = state[11] ^ buf3 ^ buf1;
		// col4
		buf1 = state[12] ^ state[13] ^ state[14] ^ state[15];
		buf2 = state[12];
		buf3 = state[12] ^ state[13]; buf3 = galois_mul2(buf3); state[12] = state[12] ^ buf3 ^ buf1;
		buf3 = state[13] ^ state[14]; buf3 = galois_mul2(buf3); state[13] = state[13] ^ buf3 ^ buf1;
		buf3 = state[14] ^ state[15]; buf3 = galois_mul2(buf3); state[14] = state[14] ^ buf3 ^ buf1;
		buf3 = state[15] ^ buf2;      buf3 = galois_mul2(buf3); state[15] = state[15] ^ buf3 ^ buf1;

	}
	// 10th round without mixcols
	state[0] = sbox[(state[0] ^ expandedKey[(round * 16)])];
	state[4] = sbox[(state[4] ^ expandedKey[(round * 16) + 4])];
	state[8] = sbox[(state[8] ^ expandedKey[(round * 16) + 8])];
	state[12] = sbox[(state[12] ^ expandedKey[(round * 16) + 12])];
	// row 1
	buf1 = state[1] ^ expandedKey[(round * 16) + 1];
	state[1] = sbox[(state[5] ^ expandedKey[(round * 16) + 5])];
	state[5] = sbox[(state[9] ^ expandedKey[(round * 16) + 9])];
	state[9] = sbox[(state[13] ^ expandedKey[(round * 16) + 13])];
	state[13] = sbox[buf1];
	// row 2
	buf1 = state[2] ^ expandedKey[(round * 16) + 2];
	buf2 = state[6] ^ expandedKey[(round * 16) + 6];
	state[2] = sbox[(state[10] ^ expandedKey[(round * 16) + 10])];
	state[6] = sbox[(state[14] ^ expandedKey[(round * 16) + 14])];
	state[10] = sbox[buf1];
	state[14] = sbox[buf2];
	// row 3
	buf1 = state[15] ^ expandedKey[(round * 16) + 15];
	state[15] = sbox[(state[11] ^ expandedKey[(round * 16) + 11])];
	state[11] = sbox[(state[7] ^ expandedKey[(round * 16) + 7])];
	state[7] = sbox[(state[3] ^ expandedKey[(round * 16) + 3])];
	state[3] = sbox[buf1];
	// last addroundkey
	state[0] ^= expandedKey[160];
	state[1] ^= expandedKey[161];
	state[2] ^= expandedKey[162];
	state[3] ^= expandedKey[163];
	state[4] ^= expandedKey[164];
	state[5] ^= expandedKey[165];
	state[6] ^= expandedKey[166];
	state[7] ^= expandedKey[167];
	state[8] ^= expandedKey[168];
	state[9] ^= expandedKey[169];
	state[10] ^= expandedKey[170];
	state[11] ^= expandedKey[171];
	state[12] ^= expandedKey[172];
	state[13] ^= expandedKey[173];
	state[14] ^= expandedKey[174];
	state[15] ^= expandedKey[175];
}

// straight foreward aes decryption implementation
//   the order of substeps is the exact reverse of decryption
//   inverse functions:
//       - addRoundKey is its own inverse
//       - rsbox is inverse of sbox
//       - rightshift instead of leftshift
//       - invMixColumns = barreto + mixColumns
//   no further subfunctions to save cycles for function calls
//   no structuring with "for (....)" to save cycles
void aes_decr(unsigned char *state, unsigned char *expandedKey)
{
	unsigned char buf1, buf2, buf3;
	signed char round;
	round = 9;

	// initial addroundkey
	state[0] ^= expandedKey[160];
	state[1] ^= expandedKey[161];
	state[2] ^= expandedKey[162];
	state[3] ^= expandedKey[163];
	state[4] ^= expandedKey[164];
	state[5] ^= expandedKey[165];
	state[6] ^= expandedKey[166];
	state[7] ^= expandedKey[167];
	state[8] ^= expandedKey[168];
	state[9] ^= expandedKey[169];
	state[10] ^= expandedKey[170];
	state[11] ^= expandedKey[171];
	state[12] ^= expandedKey[172];
	state[13] ^= expandedKey[173];
	state[14] ^= expandedKey[174];
	state[15] ^= expandedKey[175];

	// 10th round without mixcols
	state[0] = rsbox[state[0]] ^ expandedKey[(round * 16)];
	state[4] = rsbox[state[4]] ^ expandedKey[(round * 16) + 4];
	state[8] = rsbox[state[8]] ^ expandedKey[(round * 16) + 8];
	state[12] = rsbox[state[12]] ^ expandedKey[(round * 16) + 12];
	// row 1
	buf1 = rsbox[state[13]] ^ expandedKey[(round * 16) + 1];
	state[13] = rsbox[state[9]] ^ expandedKey[(round * 16) + 13];
	state[9] = rsbox[state[5]] ^ expandedKey[(round * 16) + 9];
	state[5] = rsbox[state[1]] ^ expandedKey[(round * 16) + 5];
	state[1] = buf1;
	// row 2
	buf1 = rsbox[state[2]] ^ expandedKey[(round * 16) + 10];
	buf2 = rsbox[state[6]] ^ expandedKey[(round * 16) + 14];
	state[2] = rsbox[state[10]] ^ expandedKey[(round * 16) + 2];
	state[6] = rsbox[state[14]] ^ expandedKey[(round * 16) + 6];
	state[10] = buf1;
	state[14] = buf2;
	// row 3
	buf1 = rsbox[state[3]] ^ expandedKey[(round * 16) + 15];
	state[3] = rsbox[state[7]] ^ expandedKey[(round * 16) + 3];
	state[7] = rsbox[state[11]] ^ expandedKey[(round * 16) + 7];
	state[11] = rsbox[state[15]] ^ expandedKey[(round * 16) + 11];
	state[15] = buf1;

	for (round = 8; round >= 0; round--) {
		// barreto
		//col1
		buf1 = galois_mul2(galois_mul2(state[0] ^ state[2]));
		buf2 = galois_mul2(galois_mul2(state[1] ^ state[3]));
		state[0] ^= buf1;     state[1] ^= buf2;    state[2] ^= buf1;    state[3] ^= buf2;
		//col2
		buf1 = galois_mul2(galois_mul2(state[4] ^ state[6]));
		buf2 = galois_mul2(galois_mul2(state[5] ^ state[7]));
		state[4] ^= buf1;    state[5] ^= buf2;    state[6] ^= buf1;    state[7] ^= buf2;
		//col3
		buf1 = galois_mul2(galois_mul2(state[8] ^ state[10]));
		buf2 = galois_mul2(galois_mul2(state[9] ^ state[11]));
		state[8] ^= buf1;    state[9] ^= buf2;    state[10] ^= buf1;    state[11] ^= buf2;
		//col4
		buf1 = galois_mul2(galois_mul2(state[12] ^ state[14]));
		buf2 = galois_mul2(galois_mul2(state[13] ^ state[15]));
		state[12] ^= buf1;    state[13] ^= buf2;    state[14] ^= buf1;    state[15] ^= buf2;
		// mixcolums //////////
		// col1
		buf1 = state[0] ^ state[1] ^ state[2] ^ state[3];
		buf2 = state[0];
		buf3 = state[0] ^ state[1]; buf3 = galois_mul2(buf3); state[0] = state[0] ^ buf3 ^ buf1;
		buf3 = state[1] ^ state[2]; buf3 = galois_mul2(buf3); state[1] = state[1] ^ buf3 ^ buf1;
		buf3 = state[2] ^ state[3]; buf3 = galois_mul2(buf3); state[2] = state[2] ^ buf3 ^ buf1;
		buf3 = state[3] ^ buf2;     buf3 = galois_mul2(buf3); state[3] = state[3] ^ buf3 ^ buf1;
		// col2
		buf1 = state[4] ^ state[5] ^ state[6] ^ state[7];
		buf2 = state[4];
		buf3 = state[4] ^ state[5]; buf3 = galois_mul2(buf3); state[4] = state[4] ^ buf3 ^ buf1;
		buf3 = state[5] ^ state[6]; buf3 = galois_mul2(buf3); state[5] = state[5] ^ buf3 ^ buf1;
		buf3 = state[6] ^ state[7]; buf3 = galois_mul2(buf3); state[6] = state[6] ^ buf3 ^ buf1;
		buf3 = state[7] ^ buf2;     buf3 = galois_mul2(buf3); state[7] = state[7] ^ buf3 ^ buf1;
		// col3
		buf1 = state[8] ^ state[9] ^ state[10] ^ state[11];
		buf2 = state[8];
		buf3 = state[8] ^ state[9];   buf3 = galois_mul2(buf3); state[8] = state[8] ^ buf3 ^ buf1;
		buf3 = state[9] ^ state[10];  buf3 = galois_mul2(buf3); state[9] = state[9] ^ buf3 ^ buf1;
		buf3 = state[10] ^ state[11]; buf3 = galois_mul2(buf3); state[10] = state[10] ^ buf3 ^ buf1;
		buf3 = state[11] ^ buf2;      buf3 = galois_mul2(buf3); state[11] = state[11] ^ buf3 ^ buf1;
		// col4
		buf1 = state[12] ^ state[13] ^ state[14] ^ state[15];
		buf2 = state[12];
		buf3 = state[12] ^ state[13]; buf3 = galois_mul2(buf3); state[12] = state[12] ^ buf3 ^ buf1;
		buf3 = state[13] ^ state[14]; buf3 = galois_mul2(buf3); state[13] = state[13] ^ buf3 ^ buf1;
		buf3 = state[14] ^ state[15]; buf3 = galois_mul2(buf3); state[14] = state[14] ^ buf3 ^ buf1;
		buf3 = state[15] ^ buf2;      buf3 = galois_mul2(buf3); state[15] = state[15] ^ buf3 ^ buf1;

		// addroundkey, rsbox and shiftrows
		// row 0
		state[0] = rsbox[state[0]] ^ expandedKey[(round * 16)];
		state[4] = rsbox[state[4]] ^ expandedKey[(round * 16) + 4];
		state[8] = rsbox[state[8]] ^ expandedKey[(round * 16) + 8];
		state[12] = rsbox[state[12]] ^ expandedKey[(round * 16) + 12];
		// row 1
		buf1 = rsbox[state[13]] ^ expandedKey[(round * 16) + 1];
		state[13] = rsbox[state[9]] ^ expandedKey[(round * 16) + 13];
		state[9] = rsbox[state[5]] ^ expandedKey[(round * 16) + 9];
		state[5] = rsbox[state[1]] ^ expandedKey[(round * 16) + 5];
		state[1] = buf1;
		// row 2
		buf1 = rsbox[state[2]] ^ expandedKey[(round * 16) + 10];
		buf2 = rsbox[state[6]] ^ expandedKey[(round * 16) + 14];
		state[2] = rsbox[state[10]] ^ expandedKey[(round * 16) + 2];
		state[6] = rsbox[state[14]] ^ expandedKey[(round * 16) + 6];
		state[10] = buf1;
		state[14] = buf2;
		// row 3
		buf1 = rsbox[state[3]] ^ expandedKey[(round * 16) + 15];
		state[3] = rsbox[state[7]] ^ expandedKey[(round * 16) + 3];
		state[7] = rsbox[state[11]] ^ expandedKey[(round * 16) + 7];
		state[11] = rsbox[state[15]] ^ expandedKey[(round * 16) + 11];
		state[15] = buf1;
	}
}

int Base64decode_len(const char *bufcoded)
{
	int nbytesdecoded;
	register const unsigned char *bufin;
	register int nprbytes;

	bufin = (const unsigned char *)bufcoded;
	while (pr2six[*(bufin++)] <= 63);

	nprbytes = (bufin - (const unsigned char *)bufcoded) - 1;
	nbytesdecoded = ((nprbytes + 3) / 4) * 3;

	return nbytesdecoded + 1;
}

int Base64decode(char *bufplain, const char *bufcoded)
{
	int nbytesdecoded;
	register const unsigned char *bufin;
	register unsigned char *bufout;
	register int nprbytes;

	bufin = (const unsigned char *)bufcoded;
	while (pr2six[*(bufin++)] <= 63);
	nprbytes = (bufin - (const unsigned char *)bufcoded) - 1;
	nbytesdecoded = ((nprbytes + 3) / 4) * 3;

	bufout = (unsigned char *)bufplain;
	bufin = (const unsigned char *)bufcoded;

	while (nprbytes > 4) {
		*(bufout++) =
			(unsigned char)(pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
		*(bufout++) =
			(unsigned char)(pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
		*(bufout++) =
			(unsigned char)(pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
		bufin += 4;
		nprbytes -= 4;
	}

	if (nprbytes > 1) {
		*(bufout++) =
			(unsigned char)(pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
	}
	if (nprbytes > 2) {
		*(bufout++) =
			(unsigned char)(pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
	}
	if (nprbytes > 3) {
		*(bufout++) =
			(unsigned char)(pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
	}

	*(bufout++) = '\0';
	nbytesdecoded -= (4 - nprbytes) & 3;
	return nbytesdecoded;
}

int Base64encode_len(int len)
{
	return ((len + 2) / 3 * 4) + 1;
}

int Base64encode(char *encoded, const char *string, int len)
{
	int i;
	char *p;
	p = encoded;
	for (i = 0; i < len - 2; i += 3) {
		*p++ = basis_64[(string[i] >> 2) & 0x3F];
		*p++ = basis_64[((string[i] & 0x3) << 4) |
			((int)(string[i + 1] & 0xF0) >> 4)];
		*p++ = basis_64[((string[i + 1] & 0xF) << 2) |
			((int)(string[i + 2] & 0xC0) >> 6)];
		*p++ = basis_64[string[i + 2] & 0x3F];
	}
	if (i < len) {
		*p++ = basis_64[(string[i] >> 2) & 0x3F];
		if (i == (len - 1)) {
			*p++ = basis_64[((string[i] & 0x3) << 4)];
			*p++ = '=';
		}
		else {
			*p++ = basis_64[((string[i] & 0x3) << 4) |
				((int)(string[i + 1] & 0xF0) >> 4)];
			*p++ = basis_64[((string[i + 1] & 0xF) << 2)];
		}
		*p++ = '=';
	}

	*p++ = '\0';
	return p - encoded;
}

int main(int argc, char *argv[])
{
	double timecheck = 0;
	clock_t timestart, timeend;
	timestart = clock();

	if (argc != 9) {//프롬프트 입력개수 검사
		printf("옵션값 제대로 입력해 주세요. 옵션종류 순서는 상관 없습니다.\n");
		printf(" 옵션종류 : -in, -out, -key, -binary, -base64, -enc, -dec\n\
	사용예 : .\\Speed_Test_AES.exe -enc -binary -in 입력경로 -out 출력경로 -key 0123456789abcdef");
		exit(1);
	}
	char _in = False, _out = False, _key = False, _by = False, _bs64 = False, _enc = False, _dec = False;
	unsigned char keyk[16] = { 0, };//입력키
	unsigned char infile[256], outfile[256];//파일 경로
	for (int i = 0; i < argc; ++i) {
		if (strcmp(argv[i], "-enc") == 0)
			_enc = True;
		else if (strcmp(argv[i], "-dec") == 0)
			_dec = True;
		else if (strcmp(argv[i], "-base64") == 0)
			_bs64 = True;
		else if (strcmp(argv[i], "-binary") == 0)
			_by = True;
		else if (strcmp(argv[i], "-key") == 0) {
			if (argv[i + 1] == NULL) {
				printf("-key 옵션값을 입력해주세요.\n");
				exit(1);
			}
			else if (strchr(argv[i + 1], '-') != NULL) {
				printf("-key 옵션값이 비어있습니다.\n");
				exit(1);
			}
			else if (strlen(argv[i + 1]) > 16) {
				printf("-key 옵션값 길이는 최대 16자입니다.\n");
				exit(1);
			}
			strcpy(keyk, argv[i + 1]);
			_key = True;
		}
		else if (strcmp(argv[i], "-in") == 0) {
			if (argv[i + 1] == NULL) {
				printf("-in 옵션값을 입력해주세요.\n");
				exit(1);
			}
			else if (strchr(argv[i + 1], '-') != NULL) {
				printf("-in 옵션값이 비어있습니다.\n");
				exit(1);
			}
			else if (strlen(argv[i + 1]) > 255) {
				printf("-in 옵션값 길이는 최대 255자입니다.\n");
				exit(1);
			}
			else if (_access(argv[i + 1], 0) != 0) {
				printf("-in 옵션 파일이 존재하지 않습니다.\n");
				exit(1);
			}
			strcpy(infile, argv[i + 1]);
			_in = True;
		}
		else if (strcmp(argv[i], "-out") == 0) {
			if (argv[i + 1] == NULL) {
				printf("-out 옵션값을 입력해주세요.\n");
				exit(1);
			}
			else if (strchr(argv[i + 1], '-') != NULL) {
				printf("-out 옵션값이 비어있습니다.\n");
				exit(1);
			}
			else if (strlen(argv[i + 1]) > 255) {
				printf("-out 옵션값 길이는 최대 255자입니다.\n");
				exit(1);
			}
			else if (_access(argv[i + 1], 0) == 0) {
				printf("-out 옵션 같은파일 이름이 존재합니다.\n프로그램을 종료합니다.\n");
				exit(1);
			}
			strcpy(outfile, argv[i + 1]);
			_out = True;
		}
	}
	if (_enc + _dec != 1) {
		printf("_enc와 _dec 둘중 하나를 사용해 주세요.\n");
		exit(1);
	}
	if (_by - _bs64 == 0) {
		printf("base64와 binary를 같이 사용할 수 없습니다.\n");
		exit(1);
	}
	printf("입력된 파일경로 : %s\n", infile);
	printf("출력할 파일경로 : %s\n", outfile);
	printf("입력된 키 : %s\n", keyk);

	unsigned char intext[16] = { 0, };
	unsigned char expandedKey[176];
	expandKey(expandedKey, keyk);//키생성

	FILE *infp, *outfp;
	infp = fopen(infile, "rb");
	if (infp == NULL) {
		printf("%s 파일을 열수 없습니다.\n", infile);
		exit(EXIT_FAILURE);
	}
	outfp = fopen(outfile, "w+b");
	if (outfp == NULL) {
		printf("%s 파일을 열수 없습니다.\n", outfile);
		fclose(infp);
		exit(EXIT_FAILURE);
	}

	if (_by - _bs64 == -1) {//binary와 base64
		unsigned char *inbuf, *b64debuf, *crypt, *b64inbuf, *tempmem;
		int file_size = 0, tempsize = 0, encode_len = 0, decode_len = 0, tempd_len = 0, b64_pad = 0, count1 = 0, count2 = 0;
		unsigned char junkpad[2];
		fseek(infp, 0, SEEK_END);
		file_size = ftell(infp);//읽은 전체파일크기
		fseek(infp, -2, SEEK_CUR);
		fread(junkpad, 1, 2, infp);//junkpad에 인코딩된base64파일 패딩검사
		if (ferror(infp)) {
			perror("파일 읽기 에러");
			_fcloseall();
			exit(EXIT_FAILURE);
		}
		if (junkpad[0] == '=') ++b64_pad;
		if (junkpad[1] == '=') ++b64_pad;
		fseek(infp, 0, SEEK_SET);
		inbuf = malloc(file_size);
		fread(inbuf, file_size, 1, infp);
		if (ferror(infp)) {
			perror("파일 읽기 에러");
			_fcloseall();
			exit(EXIT_FAILURE);
		}
		decode_len = Base64decode_len(inbuf) - 1;
		tempmem = malloc(decode_len + 1);
		Base64decode(tempmem, inbuf);//디코딩
		tempd_len = decode_len - b64_pad;
		b64debuf = malloc(tempd_len);
		memcpy(b64debuf, tempmem, tempd_len);//base64패딩된 개수만큼 줄여서 복사해 옮김
		free(tempmem);
		free(inbuf);//b64debuf에 최종적으로 디코딩된 값이 있음.
		if (_enc) {//암호화 시작
			int paddingcheck1 = tempd_len % 16;
			int paddingcheck2 = tempd_len - paddingcheck1;
			if (paddingcheck1 == 0) {
				crypt = malloc(tempd_len);
				tempsize = tempd_len;
				while (count1 < tempd_len) {
					for (int i = 0; i < 16; ++i) {
						intext[i] = b64debuf[count1];
						++count1;
					}
					aes_encr(intext, expandedKey);
					for (int j = 0; j < 16; ++j) {
						crypt[count2] = intext[j];
						++count2;
					}
				}
			}
			else {
				tempsize = tempd_len + (16 - paddingcheck1);
				crypt = malloc(tempsize);
				while (count1 != paddingcheck2) {
					for (int i = 0; i < 16; ++i) {
						intext[i] = b64debuf[count1];
						++count1;
					}
					aes_encr(intext, expandedKey);
					for (int j = 0; j < 16; ++j) {
						crypt[count2] = intext[j];
						++count2;
					}
				}
				for (int i = 0; i < paddingcheck1; ++i) {
					intext[i] = b64debuf[count1];
					++count1;
				}
				for (int j = 15; j >= paddingcheck1; --j) {
					intext[j] = paddingcheck1;
				}
				aes_encr(intext, expandedKey);
				for (int k = 0; k < 16; ++k) {
					crypt[count2] = intext[k];
					++count2;
				}
			}//crypt에 암호문
			encode_len = Base64encode_len(tempsize) - 1;
			b64inbuf = malloc(encode_len);
			Base64encode(b64inbuf, crypt, tempsize);
			fwrite(b64inbuf, encode_len, 1, outfp);
			if (ferror(outfp)) {
				perror("파일 인코딩 에러");
				_fcloseall();
				exit(EXIT_FAILURE);
			}
			free(crypt);
		}
		else if (_dec) {//복호화 시작
			int paddingcheck1 = tempd_len - 16;
			int paddingcheck2 = 0;
			crypt = malloc(tempd_len);
			while (count1 < paddingcheck1) {
				for (int i = 0; i < 16; ++i) {
					intext[i] = b64debuf[count1];
					++count1;
				}
				aes_decr(intext, expandedKey);
				for (int j = 0; j < 16; ++j) {
					crypt[count2] = intext[j];
					++count2;
				}
			}
			for (int i = 0; i < 16; ++i) {
				intext[i] = b64debuf[count1];
				++count1;
			}
			aes_decr(intext, expandedKey);
			if (intext[15] < 16) {
				for (int i = 15; i >= intext[15]; --i) {
					if (intext[i] == intext[15])
						++paddingcheck2;
				}
				if (paddingcheck2 == 16 - intext[15]) {
					if (intext[15] == 0x0F || intext[15] == 0x0E) {
						for (int j = 0; j < 16; ++j) {
							crypt[count2] = intext[j];
							++count2;
						}
					}
					else {
						if (intext[15] != 0) {
							for (int j = 0; j < intext[15]; ++j) {
								crypt[count2] = intext[j];
								++count2;
							}
							tempsize = 16 - intext[15];
						}
						else {
							for (int j = 0; j < 16; ++j) {
								crypt[count2] = intext[j];
								++count2;
							}
						}
					}
				}
				else {
					for (int j = 0; j < 16; ++j) {
						crypt[count2] = intext[j];
						++count2;
					}
				}
			}
			else {
				for (int j = 0; j < 16; ++j) {
					crypt[count2] = intext[j];
					++count2;
				}
			}
			unsigned char *cryptr = malloc(tempd_len - tempsize);
			memcpy(cryptr, crypt, tempd_len - tempsize);
			free(crypt);
			encode_len = Base64encode_len(count2) - 1;
			b64inbuf = malloc(encode_len);
			Base64encode(b64inbuf, cryptr, count2);
			fwrite(b64inbuf, encode_len, 1, outfp);
			if (ferror(outfp)) {
				perror("파일 인코딩 에러");
				_fcloseall();
				exit(EXIT_FAILURE);
			}
			free(cryptr);
		}
		_fcloseall();
	}
	else if (_by - _bs64 == 1) {	//binary
		int flen;
		if (_enc) {//암호화 시작
			while (!feof(infp)) {
				flen = fread(&intext, 1, 16, infp);
				if (ferror(infp)) {
					perror("파일 읽기 에러");
					_fcloseall();
					exit(EXIT_FAILURE);
				}
				if (flen == 16) {
					aes_encr(intext, expandedKey);
					fwrite(&intext, 16, 1, outfp);
					if (ferror(outfp)) {
						perror("파일 암호화 에러");
						_fcloseall();
						exit(EXIT_FAILURE);
					}
				}
				else {
					if (flen == 0) {
						break;
					}
					for (int i = 15; i >= flen; --i) {
						intext[i] = flen;
					}
					aes_encr(intext, expandedKey);
					fwrite(&intext, 16, 1, outfp);
					if (ferror(outfp)) {
						perror("파일 암호화 에러");
						_fcloseall();
						exit(EXIT_FAILURE);
					}
				}
			}
			_fcloseall();
		}
		else if (_dec) {//복호화 시작
			while (1) {
				unsigned char junk = 0;
				flen = fread(&intext, 16, 1, infp);
				if (ferror(infp)) {
					perror("파일 읽기 에러");
					_fcloseall();
					exit(EXIT_FAILURE);
				}
				if (flen > 0)
					aes_decr(intext, expandedKey);
				else {
					break;
				}
				if (intext[15] < 16) {
					fread(&junk, 1, 1, infp);
					if (!feof(infp)) {
						fseek(infp, -1, SEEK_CUR);
						fwrite(&intext, 16, 1, outfp);
						if (ferror(outfp)) {
							perror("파일 복호화 에러");
							_fcloseall();
							exit(EXIT_FAILURE);
						}
					}
					else {
						int count = 0;
						for (int i = 15; i >= intext[15]; --i) {
							if (intext[i] == intext[15])
								++count;
						}
						if (count == 16 - intext[15]) {
							if (intext[15] == 0x0F || intext[15] == 0x0E) {
								fwrite(&intext, 16, 1, outfp);
								if (ferror(outfp)) {
									perror("파일 복호화 에러");
									_fcloseall();
									exit(EXIT_FAILURE);
								}
								break;
							}
							else {
								if (intext[15] != 0) {
									fwrite(&intext, 1, intext[15], outfp);
									if (ferror(outfp)) {
										perror("파일 복호화 에러");
										_fcloseall();
										exit(EXIT_FAILURE);
									}
								}
								else {
									fwrite(&intext, 1, 16, outfp);
									if (ferror(outfp)) {
										perror("파일 복호화 에러");
										_fcloseall();
										exit(EXIT_FAILURE);
									}
								}
								break;
							}
						}
						else {
							fwrite(&intext, 16, 1, outfp);
							if (ferror(outfp)) {
								perror("파일 복호화 에러");
								_fcloseall();
								exit(EXIT_FAILURE);
							}
							break;
						}
					}
				}
				else {
					fwrite(&intext, 16, 1, outfp);
					if (ferror(outfp)) {
						perror("파일 복호화 에러");
						_fcloseall();
						exit(EXIT_FAILURE);
					}
				}
			}
			_fcloseall();
		}
	}

	timeend = clock();
	timecheck = (double)(timeend - timestart);
	printf("측정시간 : %f ms\n", timecheck);
	return 0;
}