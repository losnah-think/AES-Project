#include "aes.h"

/**********************************************************************/
/*                                                                    */
/*                              AES알고리즘                           */
/*                                                                    */
/**********************************************************************/

/******************************다음은 암호화된 변환함수**********************/
/**
 *  S박스 변환 - 처음 4자리 숫자는 줄번호，마지막 4자리 숫자는 열번호
 */
void AES::SubBytes(byte mtx[4 * 4])
{
	for (int i = 0; i < 16; ++i)
	{
		int row = mtx[i][7] * 8 + mtx[i][6] * 4 + mtx[i][5] * 2 + mtx[i][4];
		int col = mtx[i][3] * 8 + mtx[i][2] * 4 + mtx[i][1] * 2 + mtx[i][0];
		mtx[i] = S_Box[row][col];
	}
}

/**
 *  행변환 - 좌측으로
 */
void AES::ShiftRows(byte mtx[4 * 4])
{
	// 2열 순환 좌측으로 1칸 이동
	byte temp = mtx[4];
	for (int i = 0; i < 3; ++i)
		mtx[i + 4] = mtx[i + 5];
	mtx[7] = temp;
	// 3열 순환 좌측으로 2칸 이동
	for (int i = 0; i < 2; ++i)
	{
		temp = mtx[i + 8];
		mtx[i + 8] = mtx[i + 10];
		mtx[i + 10] = temp;
	}
	// 4열 순환 좌측으로 3칸 이동
	temp = mtx[15];
	for (int i = 3; i > 0; --i)
		mtx[i + 12] = mtx[i + 11];
	mtx[12] = temp;
}

/**
 *  열변환
 */
void AES::MixColumns(byte mtx[4 * 4])
{
	byte arr[4];
	for (int i = 0; i < 4; ++i)
	{
		for (int j = 0; j < 4; ++j)
			arr[j] = mtx[i + j * 4];

		mtx[i] = Mul_02[arr[0].to_ulong()] ^ Mul_03[arr[1].to_ulong()] ^ arr[2] ^ arr[3];
		mtx[i + 4] = arr[0] ^ Mul_02[arr[1].to_ulong()] ^ Mul_03[arr[2].to_ulong()] ^ arr[3];
		mtx[i + 8] = arr[0] ^ arr[1] ^ Mul_02[arr[2].to_ulong()] ^ Mul_03[arr[3].to_ulong()];
		mtx[i + 12] = Mul_03[arr[0].to_ulong()] ^ arr[1] ^ arr[2] ^ Mul_02[arr[3].to_ulong()];
	}
}

/**
 *  라운드 키 암호 변환 - 각 열마다 암호키를 확장
 */
void AES::AddRoundKey(byte mtx[4 * 4], word k[4])
{
	for (int i = 0; i < 4; ++i)
	{
		word k1 = k[i] >> 24;
		word k2 = (k[i] << 8) >> 24;
		word k3 = (k[i] << 16) >> 24;
		word k4 = (k[i] << 24) >> 24;
		// 연산
		mtx[i] = mtx[i] ^ byte(k1.to_ulong());
		mtx[i + 4] = mtx[i + 4] ^ byte(k2.to_ulong());
		mtx[i + 8] = mtx[i + 8] ^ byte(k3.to_ulong());
		mtx[i + 12] = mtx[i + 12] ^ byte(k4.to_ulong());
	}
}

/**************************다음은 복호화 역변환 함수***********************/
/**
 *  역 S박스 변환
 */
void AES::InvSubBytes(byte mtx[4 * 4])
{
	for (int i = 0; i < 16; ++i)
	{
		int row = mtx[i][7] * 8 + mtx[i][6] * 4 + mtx[i][5] * 2 + mtx[i][4];
		int col = mtx[i][3] * 8 + mtx[i][2] * 4 + mtx[i][1] * 2 + mtx[i][0];
		mtx[i] = Inv_S_Box[row][col];
	}
}

/**
 *  역행변환 - 우측으로
 */
void AES::InvShiftRows(byte mtx[4 * 4])
{
	// 2열 순환 우측으로 1칸 이동
	byte temp = mtx[7];
	for (int i = 3; i > 0; --i)
		mtx[i + 4] = mtx[i + 3];
	mtx[4] = temp;
	// 3열 순환 우측으로 2칸 이동
	for (int i = 0; i < 2; ++i)
	{
		temp = mtx[i + 8];
		mtx[i + 8] = mtx[i + 10];
		mtx[i + 10] = temp;
	}
	// 4열 순환 우측으로 3칸 이동
	temp = mtx[12];
	for (int i = 0; i < 3; ++i)
		mtx[i + 12] = mtx[i + 13];
	mtx[15] = temp;
}

void AES::InvMixColumns(byte mtx[4 * 4])
{
	byte arr[4];
	for (int i = 0; i < 4; ++i)
	{
		for (int j = 0; j < 4; ++j)
			arr[j] = mtx[i + j * 4];

		mtx[i] = Mul_0e[arr[0].to_ulong()] ^ Mul_0b[arr[1].to_ulong()] ^ Mul_0d[arr[2].to_ulong()] ^ Mul_09[arr[3].to_ulong()];
		mtx[i + 4] = Mul_09[arr[0].to_ulong()] ^ Mul_0e[arr[1].to_ulong()] ^ Mul_0b[arr[2].to_ulong()] ^ Mul_0d[arr[3].to_ulong()];
		mtx[i + 8] = Mul_0d[arr[0].to_ulong()] ^ Mul_09[arr[1].to_ulong()] ^ Mul_0e[arr[2].to_ulong()] ^ Mul_0b[arr[3].to_ulong()];
		mtx[i + 12] = Mul_0b[arr[0].to_ulong()] ^ Mul_0d[arr[1].to_ulong()] ^ Mul_09[arr[2].to_ulong()] ^ Mul_0e[arr[3].to_ulong()];
	}
}

/******************************아래는 키의 암호 확장 부분이다***********************/
/**
 * 4개의 byte를 1개의 워드로 전환
 */
AES::word AES::Word(byte& k1, byte& k2, byte& k3, byte& k4)
{
	word result(0x00000000);
	word temp;
	temp = k1.to_ulong();  // K1
	temp <<= 24;
	result |= temp;
	temp = k2.to_ulong();  // K2
	temp <<= 16;
	result |= temp;
	temp = k3.to_ulong();  // K3
	temp <<= 8;
	result |= temp;
	temp = k4.to_ulong();  // K4
	result |= temp;
	return result;
}

/**
 *  자절에 따라 순환하여 좌측으로 이동
 *  즉, [a0, a1, a2, a3]은 [a1, a2, a3, a0]
 */
AES::word AES::RotWord(word& rw)
{
	word high = rw << 8;
	word low = rw >> 24;
	return high | low;
}

/**
 *  워드에 입력된 각 바이트마다 s-box 를 변환
 */
AES::word AES::SubWord(word& sw)
{
	word temp;
	for (int i = 0; i < 32; i += 8)
	{
		int row = sw[i + 7] * 8 + sw[i + 6] * 4 + sw[i + 5] * 2 + sw[i + 4];
		int col = sw[i + 3] * 8 + sw[i + 2] * 4 + sw[i + 1] * 2 + sw[i];
		byte val = S_Box[row][col];
		for (int j = 0; j < 8; ++j)
			temp[i + j] = val[j];
	}
	return temp;
}

/**
 *  암호확장함수 - 128비트 암호화 w[4*(Nr+1)]
 */
void AES::KeyExpansion(byte key[4 * 4], word w[4 * (10 + 1)])
{
	word temp;
	word *rot_temp;
	int i = 0;
	// w[] 처음 4 개는 입력 키입니다
	while (i < 4)
	{
		w[i] = Word(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
		++i;
	}

	i = 4;

	while (i < 4 * (10 + 1))
	{
		temp = w[i - 1]; // 기록하기전의 워드 값
		if (i % 4 == 0) {
			rot_temp = &RotWord(temp);
			w[i] = w[i - 4] ^ SubWord(*rot_temp) ^ Rcon[i / 4 - 1];
		}
		else
			w[i] = w[i - 4] ^ temp;
		++i;
	}
}

/******************************아래는 암호함수**************************/
/**
 *  보안성을 규정한다.
 */
void AES::encrypt(byte in[4 * 4], word w[4 * (10 + 1)])
{
	word key[4];
	for (int i = 0; i < 4; ++i)
		key[i] = w[i];
	AddRoundKey(in, key);

	for (int round = 1; round < 10; ++round)
	{
		SubBytes(in);
		ShiftRows(in);
		MixColumns(in);
		for (int i = 0; i < 4; ++i)
			key[i] = w[4 * round + i];
		AddRoundKey(in, key);
	}

	SubBytes(in);
	ShiftRows(in);
	for (int i = 0; i < 4; ++i)
		key[i] = w[4 * 10 + i];
	AddRoundKey(in, key);
}

/**
 *  복호화
 */
void AES::decrypt(byte in[4 * 4], word w[4 * (10 + 1)])
{
	word key[4];
	for (int i = 0; i < 4; ++i)
		key[i] = w[4 * 10 + i];
	AddRoundKey(in, key);

	for (int round = 10 - 1; round > 0; --round)
	{
		InvShiftRows(in);
		InvSubBytes(in);
		for (int i = 0; i < 4; ++i)
			key[i] = w[4 * round + i];
		AddRoundKey(in, key);
		InvMixColumns(in);
	}

	InvShiftRows(in);
	InvSubBytes(in);
	for (int i = 0; i < 4; ++i)
		key[i] = w[i];
	AddRoundKey(in, key);
}
