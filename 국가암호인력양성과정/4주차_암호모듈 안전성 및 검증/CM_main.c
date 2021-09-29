#include "CM_main.h"

#define CM_Not_Initialized		0x00000000
#define CM_Approved				0x00000001
#define CM_SeriousError			0x00000002

static int CMStatus = CM_Not_Initialized;

void print_Hex(unsigned char *data, int len)
{
	int i;

	for (i = 0; i < len; i++)
	{
		fprintf(stderr, "%02x", data[i]);

		if ((i != 0) && ((i + 1) % 16 == 0))
			fprintf(stderr, "\n");
		else if ((i != 0) && ((i + 1) % 4 == 0))
			fprintf(stderr, " ");
	}
}

int CBC_Init(CipherManager *cm, int ALG, int encrypt, unsigned char *userkey, int key_len, unsigned char *iv)
{
	// 1. set informations in CipherManager
	// 2. key scheduling

	if (cm == NULL || userkey == NULL || iv == NULL)
		return 0;

	if (ALG == AES)
	{
		AES_KEY *aes = (AES_KEY *)malloc(sizeof(AES_KEY));

		if ((key_len != 128) && (key_len != 192) && (key_len != 256))
			return 0;

		cm->block_size = 128;
		cm->key_st = aes;
		cm->set_enc_key = AES_set_encrypt_key;
		cm->set_dec_key = AES_set_decrypt_key;
		cm->encrypt_block = AES_encrypt;
		cm->decrypt_block = AES_decrypt;
	}
	else
	{
		printf("Not Supported Yet...\n\n");
		return 0;
	}

	cm->encrypt = encrypt;
	cm->key_size = key_len;
	if(encrypt)
		cm->set_enc_key(userkey, key_len, cm->key_st);
	else
		cm->set_dec_key(userkey, key_len, cm->key_st);

	memcpy(cm->iv, iv, 16);
	memset(cm->buf, 0x00, MAX_BLOCK_SIZE);
	memset(cm->last_block, 0x00, MAX_BLOCK_SIZE);
	cm->buflen = cm->last_block_flag = 0;

	return 1;
}

static void internal_process_blocks(CipherManager *cm, int encrypt, unsigned char *ivec, unsigned char *in, unsigned int inl, unsigned char *out)
{
	unsigned int inlength = inl;
	const unsigned char *iv = ivec;

	if (encrypt)
	{
		while (inlength >= AES_BLOCK_SIZE)
		{
			out[0] = in[0] ^ iv[0];		out[1] = in[1] ^ iv[1];
			out[2] = in[2] ^ iv[2];		out[3] = in[3] ^ iv[3];
			out[4] = in[4] ^ iv[4];		out[5] = in[5] ^ iv[5];
			out[6] = in[6] ^ iv[6];		out[7] = in[7] ^ iv[7];
			out[8] = in[8] ^ iv[8];		out[9] = in[9] ^ iv[9];
			out[10] = in[10] ^ iv[10];	out[11] = in[11] ^ iv[11];
			out[12] = in[12] ^ iv[12];	out[13] = in[13] ^ iv[13];
			out[14] = in[14] ^ iv[14];	out[15] = in[15] ^ iv[15];

			cm->encrypt_block(out, out, cm->key_st);

			iv = out;
			inlength -= AES_BLOCK_SIZE;
			in += AES_BLOCK_SIZE;
			out += AES_BLOCK_SIZE;
		}

		memcpy(ivec, iv, AES_BLOCK_SIZE);
	}
	else
	{
		while (inlength >= AES_BLOCK_SIZE)
		{
			cm->decrypt_block(in, out, cm->key_st);

			out[0] ^= iv[0];	out[1] ^= iv[1];
			out[2] ^= iv[2];	out[3] ^= iv[3];
			out[4] ^= iv[4];	out[5] ^= iv[5];
			out[6] ^= iv[6];	out[7] ^= iv[7];
			out[8] ^= iv[8];	out[9] ^= iv[9];
			out[10] ^= iv[10];	out[11] ^= iv[11];
			out[12] ^= iv[12];	out[13] ^= iv[13];
			out[14] ^= iv[14];	out[15] ^= iv[15];

			iv = in;
			inlength -= AES_BLOCK_SIZE;
			in += AES_BLOCK_SIZE;
			out += AES_BLOCK_SIZE;
		}
		
		memcpy(ivec, iv, AES_BLOCK_SIZE);
	}
}

static int internal_cbc_process_enc(CipherManager *cm, unsigned char *in, int inLen, unsigned char *out, int *outLen)
{
	// 초기화 대상 없음
	unsigned int templen = inLen&(0x0F);

	if (cm->buflen == 0 && templen == 0)
	{
		internal_process_blocks(cm, cm->encrypt, cm->iv, in, inLen, out);
		*outLen = inLen;
		
		return 1;
	}

	if (cm->buflen != 0)
	{
		if (cm->buflen + inLen < AES_BLOCK_SIZE)
		{
			memcpy(&(cm->buf[cm->buflen]), in, inLen);
			cm->buflen += inLen;
			*outLen = 0;
			
			return 1;
		}
		else
		{
			int length;
			length = AES_BLOCK_SIZE - cm->buflen;
			memcpy(&(cm->buf[cm->buflen]), in, length);
			internal_process_blocks(cm, cm->encrypt, cm->iv, cm->buf, AES_BLOCK_SIZE, out);


			inLen -= length;
			in += length;
			out += AES_BLOCK_SIZE;
			*outLen = AES_BLOCK_SIZE;

			templen = inLen&(0x0F);
		}
	}
	else
		*outLen = 0;

	inLen -= templen;
	if (inLen > 0)
	{
		internal_process_blocks(cm, cm->encrypt, cm->iv, in, inLen, out);
		*outLen += inLen;
	}

	if (templen != 0)
		memcpy(cm->buf, &(in[inLen]), templen);

	cm->buflen = templen;

	return 1;
}

static int internal_cbc_process_dec(CipherManager *cm, unsigned char *in, int inLen, unsigned char *out, int *outLen)
{
	// 초기화 대상 없음
	int updated_len;

	if (cm->last_block_flag)
	{
		memcpy(out, cm->last_block, AES_BLOCK_SIZE);
		out += AES_BLOCK_SIZE;
		updated_len = 1;
	}
	else
		updated_len = 0;

	internal_cbc_process_enc(cm, in, inLen, out, outLen);

	if (!cm->buflen)
	{
		*outLen -= AES_BLOCK_SIZE;
		cm->last_block_flag = 1;
		memcpy(cm->last_block, &out[*outLen], AES_BLOCK_SIZE);
	}
	else
		cm->last_block_flag = 0;

	if (updated_len)
		*outLen += AES_BLOCK_SIZE;

	return 1;
}

// return (1) if it's success, o.w return (0)
int CBC_Update(CipherManager *cm, unsigned char *in, int inLen, unsigned char *out, int *outLen)
{
	// 1. note : refer only the CipherManager
	int i = 0;

	if (!cm || !in || (inLen <= 0) || !out || !outLen)
		return 0;

	if (cm->encrypt)
	{
		i = internal_cbc_process_enc(cm, in, inLen, out, outLen);
	}
	else
	{
		i = internal_cbc_process_dec(cm, in, inLen, out, outLen);
	}

	return i;
}

// PKCS pad
// return (1) if it's success, o.w return (0)
int CBC_Final(CipherManager *cm, unsigned char *out, int *outLen)
{
	// 1. note : refer only the CipherManager
	unsigned int i, padlen, padvalue;

	if (!cm || !out || !outLen)
		return -4;

	if (cm->encrypt)
	{
		padlen = AES_BLOCK_SIZE - (cm->buflen);

		for (i = (cm->buflen); i < AES_BLOCK_SIZE; ++i)
			cm->buf[i] = (unsigned char)padlen;

		internal_process_blocks(cm, cm->encrypt, cm->iv, cm->buf, AES_BLOCK_SIZE, out);

		*outLen = AES_BLOCK_SIZE;

		return 1;
	}
	else
	{
		*outLen = 0;

		padlen = AES_BLOCK_SIZE - (cm->last_block[AES_BLOCK_SIZE - 1]);

		if (padlen > AES_BLOCK_SIZE) {
			return 0;
		}

		if (padlen > 1)
		{
			i = padvalue = cm->last_block[AES_BLOCK_SIZE - 1];
			while (i > 0)
			{
				if (padvalue != cm->last_block[AES_BLOCK_SIZE - i]) {
					return 0;
				}
				i--;
			}
		}

		for (i = 0; i < padlen; ++i)
			out[i] = cm->last_block[i];

		*outLen = padlen;

		return 1;
	}
}

// clean CipherManager structure (memory, data)
void CipherManager_Clean(CipherManager *cm)
{
	if (!cm)
		return;

	memset(cm, 0x00, sizeof(CipherManager));

	return;
}



/* 과제 1 */
int HMAC(unsigned char *key, int keyLen, unsigned char *data, int dataLen, unsigned char *md)
{
	if (!key || (keyLen <= 0) || !data || !md)
		return 0;

	HMAC_CTX hmac;

	HMAC_Init(&hmac, key, keyLen);
	HMAC_Update(&hmac, data, dataLen);
	HMAC_Final(md, &hmac);

	return 1;
}
int HMAC_Init(HMAC_CTX* hmac, unsigned char* key, int keyLen) {
	memset(hmac, 0, sizeof(*hmac));

	// Store K_prime into hmac->buf.
	if (keyLen > 64)
	{
		SHA256_Init(&(hmac->sha));
		SHA256_Update(&(hmac->sha), key, keyLen);
		SHA256_Final(hmac->buf, &(hmac->sha));
	}
	else
		memcpy(hmac->buf, key, keyLen);

	// Xor key and pad.
	for (int i = 0; i < 64; i++)
		hmac->iPad[i] = IPAD ^ hmac->buf[i];

	for (int i = 0; i < 64; i++)
		hmac->oPad[i] = OPAD ^ hmac->buf[i];

	// Update i key pad into hmac->sha
	SHA256_Init(&(hmac->sha));
	SHA256_Update(&(hmac->sha), (hmac->iPad), 64);

	return 1;
}

int HMAC_Update(HMAC_CTX* hmac, unsigned char* data, int dataLen) {
	if (dataLen < 0)
		return 0;

	return SHA256_Update(&(hmac->sha), data, dataLen);
}

int HMAC_Final(unsigned char* md, HMAC_CTX* hmac) {
	// store hash sum 1 in hmac->buf
	SHA256_Final(hmac->buf, &(hmac->sha));

	// store hash sum 2 in md
	SHA256_Init(&(hmac->sha));
	SHA256_Update(&(hmac->sha), (hmac->oPad), 64);
	SHA256_Update(&(hmac->sha), (hmac->buf), 32);
	SHA256_Final(md, &(hmac->sha));

	// print MAC
	print_Hex(md, 32);

	return 1;
}

/* 과제 2 */
// 1. CM 암호 연산 서비스 상태를 나타낼 구조체
static CM_Service_Stat cm_service_stat;

#include <windows.h>
#include <share.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
static int Integrity_Check(unsigned char *md)
{
	char path[1024] = { 0x00, };
	int fd = -1, ret;
	struct stat statbuf;
	int length, readlen;
	unsigned char *buf;
	unsigned char key[64] = { 0xff, };
	
	GetModuleFileNameA(NULL, path, sizeof(path));

	_sopen_s(&fd, path, _O_RDONLY | _O_BINARY, _SH_DENYWR, _S_IREAD);

	if (fd == -1)
		return 0;

	ret = fstat(fd, &statbuf);
	if (ret != 0)
		return 0;

	length = statbuf.st_size;
	buf = (unsigned char *)calloc(length + 8, sizeof(unsigned char));
	readlen = _read(fd, buf, length);

	if (readlen != length)
	{
		free(buf);
		_close(fd);
		return 0;
	}

	HMAC(key, 64, buf, length, md);

	free(buf);
	_close(fd);

	return 1;
}

int CM_Init()
{
	// 2-1. CM 상태가 SeriousError 인지 체크
	if (CMStatus == CM_SeriousError)
	{
		SeriousErrorPrint;
		return 0;
	}

	unsigned char md[32] = { 0x00, };
	int success = 0;

	printf("Initialize CM...\n");

	// 2-2. Integrity_Check 전 HMAC의 KAT 실행
	// 실패시 무결성을 체크할 수 없으므로 심각한 오류 상태로 천이.
	printf("Checking HMAC-KAT...");
	if (HMAC_SHA_256_KAT() == Success) {
		printf("OK.\n");
	}
	else{
		printf("Fail.\n CM_Status become SeriousError.\n");
		CMStatus = CM_SeriousError;
		return 0;
	}

	printf("Checking Integrity...");
	success = Integrity_Check(md);
	if (success)
	{
		printf("OK.\n");
		print_Hex(md, 32);
	}
	else
	{
		printf("Fail.\n");
		return 0;
	}
	
	printf("Initialization...");
	// 유한상태모델에 따라 상태 설정 필요
	// 2-3. CM 상태와 암호 연산 서비스 상태 초기화
	CMStatus = CM_Approved;
	for (int i = 0; i < Service_Num; i++)
	{
		cm_service_stat.is_first[i] = True;
		cm_service_stat.is_kat_success[i] = Fail;
	}

	printf(" - All Done.\n\n");

	return 1;
}

// 3. 초기화 대기 상태로 돌아갈 함수
int CM_Init_Ready() {
	if (CMStatus != CM_Approved) { // 3-1. 상태가 Approved 인지 체크
		NotApprovedPrint;
		return Fail;
	}
	CMStatus = CM_Not_Initialized;
	return 1;
}

int GetCMStatus()
{
	return CMStatus;
}

int CM_KAT(enum Services service) {
	// 4-1. 상태가 Approved 인지 체크
	if (CMStatus != CM_Approved)
	{
		NotApprovedPrint;
		return Fail;
	}

	int success;

	// 4-2. 각 서비스 별로 KAT 실행. ( 서비스 별 KAT 함수는 기존 main에 있던 KAT를 그대로 활용하였습니다. )
	switch (service)
	{
	case AES_CBC:
		success = AES_CBC_KAT();
		break;
	case SHA_256:
		success = SHA_256_KAT();
		break;
	case HMAC_SHA_256:
		success = HMAC_SHA_256_KAT();
		break;
	default:
		printf("Not Supported Yet...\n\n");
		return 0;
	}
	
	return cm_service_stat.is_kat_success[service] = success;
}

int CM_Service(enum Services service) {
	// 5-1. CM_Approved 인지 체크
	if (CMStatus != CM_Approved)
	{
		NotApprovedPrint;
		return Fail;
	}

	// 5-2. 암호 서비스 최초 수행인 지 확인
	if (cm_service_stat.is_first[service] == True)
	{
		CM_KAT(service);
	}

	// 5-3. 조건부 자가시험에 실패했을 경우
	if (cm_service_stat.is_kat_success[service] == Fail)
	{
		return Fail;
	}

	// 5-4. 암호 서비스 실행
	// ...
	
	return 1;
}


#include "TestVectors.h"
// (HMAC_SHA_256_KAT()의 4번째 Test Case 추가), (실패시 return Fail) 외엔 변경사항 없음
// 기존 main 문에서 그대로 긁어옴.
int HMAC_SHA_256_KAT() {
	int success = Success;
	unsigned char key[131] = { 0x00, };
	unsigned char md[64] = { 0x00, };

	HMAC(hmackey, 64, hmacmsg, 34, md);
	if (!memcmp(md, hmacmd, 32))
	{
		printf(" - Test Case 1 : OK.\n");
	}
	else
	{
		printf(" - Test Case 1 : Fail.\n");
		success = Fail;
	}

	memset(key, 0xaa, 131);
	HMAC(key, 131, message5, 54, md);
	if (!memcmp(md, testVectorH5, 32))
	{
		printf(" - Test Case 2 : OK.\n");
	}
	else
	{
		printf(" - Test Case 2 : Fail.\n");
		success = Fail;
	}

	HMAC(key, 131, message6, 152, md);
	if (!memcmp(md, testVectorH6, 32))
	{
		printf(" - Test Case 3 : OK.\n");
	}
	else
	{
		printf(" - Test Case 3 : Fail.\n");
		success = Fail;
	}

	// 6. HMAC Update에 분할 메시지 가능한 지 테스트
	HMAC_CTX hmac;
	HMAC_Init(&hmac, key, 131);
	HMAC_Update(&hmac, message6, 31);
	HMAC_Update(&hmac, message6 + 31, 41);
	HMAC_Update(&hmac, message6 + (31 + 41), 152 - (31 + 41));
	HMAC_Final(md, &hmac);
	if (!memcmp(md, testVectorH6, 32))
	{
		printf(" - Test Case 4 (Message split Test) : OK.\n");
	}
	else
	{
		printf(" - Test Case 4 (Message split Test) : Fail.\n");
		success = Fail;
	}

	return success;
}

int AES_CBC_KAT() {
	int success = Success;
	unsigned char RCT1[180];
	unsigned char RPT1[180];
	int rctlen1_1, rctlen1_2, rctlen1_3, rptlen1_1, rptlen1_2, rptlen1_3, padlen1;

	CipherManager cm;

	CBC_Init(&cm, AES, ENCRYPT, TestKey128, 128, TestIV128);
	CBC_Update(&cm, TestPT128, 64, RCT1, &rctlen1_1);
	CBC_Final(&cm, RCT1 + rctlen1_1, &padlen1);
	if (!memcmp(RCT1, TestCT128, 64))
	{
		printf(" - Test Case 1(Enc 64 Once) : OK.\n");
	}
	else
	{
		printf(" - Test Case 1(Enc 64 Once) : Fail.\n");
		success = Fail;
	}
	//print_Hex(RCT1, rctlen1_1 + padlen1);

	CBC_Init(&cm, AES, DECRYPT, TestKey128, 128, TestIV128);
	CBC_Update(&cm, RCT1, rctlen1_1 + padlen1, RPT1, &rptlen1_1);
	CBC_Final(&cm, RPT1 + rptlen1_1, &padlen1);
	if (!memcmp(RPT1, TestPT128, 64))
	{
		printf(" - Test Case 1(Dec Once) : OK.\n\n");
	}
	else
	{
		printf(" - Test Case 1(Dec Once) : Fail.\n\n");
		success = Fail;
	}
	//print_Hex(RPT1, rptlen1_1 + padlen1);
	memset(RCT1, 0x00, 180);
	memset(RPT1, 0x00, 180);


	CBC_Init(&cm, AES, ENCRYPT, TestKey128, 128, TestIV128);
	CBC_Update(&cm, TestPT128, 59, RCT1, &rctlen1_1);
	CBC_Final(&cm, RCT1 + rctlen1_1, &padlen1);

	CBC_Init(&cm, AES, DECRYPT, TestKey128, 128, TestIV128);
	CBC_Update(&cm, RCT1, rctlen1_1 + padlen1, RPT1, &rptlen1_1);
	CBC_Final(&cm, RPT1 + rptlen1_1, &padlen1);
	if (!memcmp(RPT1, TestPT128, 59))
	{
		printf(" - Test Case 2(Enc/Dec 59 Once) : OK.\n\n");
	}
	else
	{
		printf(" - Test Case 2(Enc/Dec 59 Once) : Fail.\n\n");
		success = Fail;
	}
	memset(RCT1, 0x00, 180);
	memset(RPT1, 0x00, 180);


	CBC_Init(&cm, AES, ENCRYPT, TestKey128, 128, TestIV128);
	CBC_Update(&cm, TestPT128, 13, RCT1, &rctlen1_1);
	CBC_Update(&cm, TestPT128 + 13, 15, RCT1 + rctlen1_1, &rctlen1_2);
	CBC_Update(&cm, TestPT128 + 28, 36, RCT1 + rctlen1_1 + rctlen1_2, &rctlen1_3);
	CBC_Final(&cm, RCT1 + rctlen1_1 + rctlen1_2 + rctlen1_3, &padlen1);
	if (!memcmp(RCT1, TestCT128, 64))
	{
		printf(" - Test Case 3(Enc 13+15+36) : OK.\n");
	}
	else
	{
		printf(" - Test Case 3(Enc 13+15+36) : Fail.\n");
		success = Fail;
	}

	CBC_Init(&cm, AES, DECRYPT, TestKey128, 128, TestIV128);
	CBC_Update(&cm, RCT1, 13, RPT1, &rptlen1_1);
	CBC_Update(&cm, RCT1 + 13, 27, RPT1 + rptlen1_1, &rptlen1_2);
	CBC_Update(&cm, RCT1 + 40, 40, RPT1 + rptlen1_1 + rptlen1_2, &rptlen1_3);
	CBC_Final(&cm, RPT1 + rptlen1_1 + rptlen1_2 + rptlen1_3, &padlen1);
	if (!memcmp(RPT1, TestPT128, 64))
	{
		printf(" - Test Case 3(Dec 13+27+40) : OK.\n");
	}
	else
	{
		printf(" - Test Case 3(Dec 13+27+40) : Fail.\n");
		success = Fail;
	}

	return success;
}

int SHA_256_KAT() {
	int success = Success;
	SHA256_CTX c;
	unsigned char md[SHA256_DIGEST_LENGTH];

	SHA256_Init(&c);
	SHA256_Update(&c, message1, 3);
	SHA256_Final(md, &c);
	if (!memcmp(md, testVectorH1, 32))
	{
		printf(" - Test Case 1 : OK.\n");
	}
	else
	{
		printf(" - Test Case 1 : Fail.\n");
		success = Fail;
	}


	SHA256_Init(&c);
	SHA256_Update(&c, message2, 56);
	SHA256_Final(md, &c);
	if (!memcmp(md, testVectorH2, 32))
	{
		printf(" - Test Case 2 : OK.\n");
	}
	else
	{
		printf(" - Test Case 2 : Fail.\n");
		success = Fail;
	}


	SHA256_Init(&c);
	SHA256_Update(&c, message3, 112);
	SHA256_Final(md, &c);
	if (!memcmp(md, testVectorH3, 32))
	{
		printf(" - Test Case 3 : OK.\n");
	}
	else
	{
		printf(" - Test Case 3 : Fail.\n");
		success = Fail;
	}


	SHA256_Init(&c);
	SHA256_Update(&c, message4, 0);
	SHA256_Final(md, &c);
	if (!memcmp(md, testVectorH4, 32))
	{
		printf(" - Test Case 4 : OK.\n");
	}
	else
	{
		printf(" - Test Case 4 : Fail.\n");
		success = Fail;
	}

	return success;
}
