#include "aes.h"
#include "base64.h"

/**********************************************************************/
/*                                                                    */
/*                              메인                                  */
/*                                                                    */
/**********************************************************************/

//추가 제작 함수


int main(int argc, char **argv)
{
	time_t start, end;
	start = clock();
	AES aes;
	base64 base64;
	AES::byte key[16] = { 0, };
	std::ifstream in;
	std::ofstream out;
	std::string in_filepath;
	std::string out_filepath;
	// 옵션 값 검사
	bool is_key = false, is_enc = false, is_dec = false, is_binary = false, is_base64 = false, is_in = false, is_out = false;
	for (int op_check = 0; op_check < argc; op_check++) {
		if (strcmp(argv[op_check], "-key") == 0) {
			if (strlen(argv[op_check + 1]) > 16) {
				std::cout << "key 값 입력 범위를 초과했습니다. Key 값은 16자 이내로 작성해주세요" << std::endl;
				return 0;
			}
			else {
				std::string key_value;
				key_value = std::string(argv[op_check + 1]);
				if (key_value.length() > 16) {
					return 0;
				}
				const char *key_array = key_value.c_str();
				std::cout << "Key :" << key_value << std::endl;
				for (int i = 0; i < 16; i++) {
					key[i] = key_array[i];
				}
				is_key = true;
			}
		}
		if (strcmp(argv[op_check], "-enc") == 0) {
			is_enc = true;
		}
		if (strcmp(argv[op_check], "-dec") == 0) {
			is_dec = true;
		}
		if (strcmp(argv[op_check], "-binary") == 0) {
			is_binary = true;
		}
		if (strcmp(argv[op_check], "-base64") == 0) {
			is_base64 = true;
		}
		if (strcmp(argv[op_check], "-in") == 0) {
			in_filepath = std::string(argv[op_check + 1]);
			std::cout << "입력 된 경로 : " << in_filepath << std::endl;
			is_in = true;
		}
		if (strcmp(argv[op_check], "-out") == 0) {
			out_filepath = std::string(argv[op_check + 1]);
			std::cout << "출력 될 경로 : " << out_filepath << std::endl;
			is_out = true;
		}
	}

	if (is_key == false || (is_enc != is_dec) == false || (is_binary != is_base64) == false || is_in == false || is_out == false) {
		std::cout << std::endl << "옵션값을 확인해주세요." << std::endl;
		std::cout << "키 값 입력 옵션 : -key " << std::endl;
		std::cout << "암호화 기능 옵션 : -enc | -dec ( 둘 중 하나만 선택)" << std::endl;
		std::cout << "파일 타입 옵션 (입력해주는 파일의 형태) : -binary | -base64" << std::endl;
		std::cout << "-in 옵션 '입력할 파일(실행할 파일)' | -out 옵션 '저장할 파일(실행 결과 파일)' / 둘 다 필수 입력" << std::endl;
		std::cout << std::endl << "< 사용 예시 >" << std::endl << "-key 0123456789abcdef -enc -base64 -in \"C:\\user\\source\\repos\\aes\\test.txt\" -out \"C:\\user\\source\\repos\\aes\\encrypt.txt\" " << std::endl;
		return 0;
	}

	in.open(in_filepath, std::ios::binary);
	out.open(out_filepath, std::ios::binary);
	// 키 확장
	AES::word w[4 * (10 + 1)];
	aes.KeyExpansion(key, w);
	// 파일 입출력 버퍼 공간
	unsigned char *buffer = new unsigned char[16];
	// 암호화 진행 변수
	AES::byte input[16];
	// 파일 크기 측정에 사용되는 변수
	int file_start_point, file_end_point, file_total_size;
	file_start_point = in.tellg();
	in.seekg(0, std::ios::end);
	file_end_point = in.tellg();
	in.seekg(0, std::ios::beg);
	file_total_size = (file_end_point - file_start_point);
	//std::cout << "파일 사이즈 측정 결과 : " << (int)file_total_size << std::endl;
	std::string base64_data, base64_decode_data, base64_encode_data;
	unsigned char *file_read_buffer = new unsigned char[file_total_size];
	unsigned char *base64_buffer = NULL;
	unsigned char *base64_buffer_2 = NULL;
	// base64 디코딩
	if (is_base64 == true) {
		// 파일 읽기
		in.read((char *)file_read_buffer, file_total_size);
		// 파일 읽기 데이터
		base64_data = std::string((char *)file_read_buffer);
		// 디코드
		base64_decode_data = base64.base64_decode(base64_data);
		// 디코드 버퍼
		base64_buffer = new unsigned char[base64_decode_data.length()];
		// 메모리 카피
		memcpy(base64_buffer,base64_decode_data.c_str(), base64_decode_data.length());
	}
	else {
		delete file_read_buffer, base64_buffer;
	}
	// binary
	if (is_binary == true) {
		for (int file_read_size = 0, read_count = 16; file_read_size < file_total_size; file_read_size += 16) {
			// 파일 읽기
			in.read((char *)buffer, read_count);
			for (int i = 0; i < read_count; i++) {
				input[i] = buffer[i];
			}
			// 암호화
			if (is_enc == true) {
				aes.encrypt(input, w);
				for (int i = 0; i < read_count; i++) {
					buffer[i] = input[i].to_ulong();
				}
				out.write((char *)buffer, read_count);
			}
			// 복호화
			if (is_dec == true) {
				aes.decrypt(input, w);
				for (int i = 0; i < read_count; i++) {
					buffer[i] = input[i].to_ulong();
				}
				out.write((char *)buffer, read_count);
			}
			memset(buffer, 0, read_count);
		} 
	}// base64
	if (is_base64 == true) {
		base64_buffer_2 = new unsigned char[base64_decode_data.length()];
		for (int file_read_size = 0, read_count = 16; file_read_size < base64_decode_data.length(); file_read_size += 16) {
			// 파일 읽기
			for (int k = 0; k < read_count; k++) {
				input[k] = base64_buffer[file_read_size + k];
			}
			// 암호화
			if (is_enc == true) {
				aes.encrypt(input, w);
				for (int i = 0; i < read_count; i++) {
					base64_buffer_2[file_read_size +i] = input[i].to_ulong();
				}
			}
			// 복호화
			if (is_dec == true) {
				aes.decrypt(input, w);
				for (int i = 0; i < read_count; i++) {
					base64_buffer_2[i] = input[i].to_ulong();
				}
			}
		}
		// base 64 인코딩
		base64_encode_data = base64.base64_encode(base64_buffer_2, base64_decode_data.length());
		memcpy(file_read_buffer, base64_encode_data.c_str(), base64_encode_data.length());
		// 파일 쓰기
		out.write((char *)file_read_buffer, base64_encode_data.length());
	}
	end = clock();
	std::cout << "수행시간 :"<< end-start<< "ms " << std::endl;
	in.close();
	out.close();
	return 0;
}