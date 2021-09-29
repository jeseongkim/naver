/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_AES_H
# define HEADER_AES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

# ifdef  __cplusplus
extern "C" {
# endif

# define AES_ENCRYPT     1
# define AES_DECRYPT     0

/*
 * Because array size can't be a const in C, the following two are macros.
 * Both sizes are in bytes.
 */
# define AES_MAXNR 14
# define AES_BLOCK_SIZE 16

typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

#define GETU32(pt) (((u32)(pt)[0] << 24) ^ ((u32)(pt)[1] << 16) ^ ((u32)(pt)[2] <<  8) ^ ((u32)(pt)[3]))
#define PUTU32(ct, st) { (ct)[0] = (u8)((st) >> 24); (ct)[1] = (u8)((st) >> 16); (ct)[2] = (u8)((st) >>  8); (ct)[3] = (u8)(st); }

#define FULL_UNROLL

/* This should be a hidden type, but EVP requires that the size be known */
struct aes_key_st {
    unsigned int rd_key[4 * (AES_MAXNR + 1)];
    int rounds;
};
typedef struct aes_key_st AES_KEY;

int AES_set_encrypt_key(unsigned char *userKey, int bits, AES_KEY *key);
int AES_set_decrypt_key(unsigned char *userKey, int bits, AES_KEY *key);

void AES_encrypt(unsigned char *in, unsigned char *out, AES_KEY *key);
void AES_decrypt(unsigned char *in, unsigned char *out, AES_KEY *key);

# ifdef  __cplusplus
}
# endif

#endif




/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_SHA_H
#define HEADER_SHA_H

#include <stddef.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*-
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! SHA_LONG has to be at least 32 bits wide.                    !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
#define SHA_LONG unsigned int
#define SHA_LBLOCK      16
#define SHA_CBLOCK      (SHA_LBLOCK*4)
#define SHA256_DIGEST_LENGTH    32

typedef struct SHA256state_st {
    SHA_LONG h[8];
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num, md_len;
} SHA256_CTX;

int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);

#ifdef  __cplusplus
}
#endif

#endif









#ifdef  __cplusplus
extern "C" {
#endif

void print_Hex(unsigned char *data, int len);


#define AES		0x00000001
#define ARIA	0x00000002
#define LEA		0x00000003
#define SEED	0x00000004

#define MAX_BLOCK_SIZE	16

#define ENCRYPT		1
#define DECRYPT		0

typedef struct cipher_manager_st{
	int		key_size;
	int     block_size;
	int     encrypt;
	void   *key_st;
	
	unsigned char   iv[MAX_BLOCK_SIZE];
	
	unsigned char   buf[MAX_BLOCK_SIZE];
	int buflen;
	
	unsigned char   last_block[MAX_BLOCK_SIZE];
	int last_block_flag;

	int  (*set_enc_key)(unsigned char *, int, void *);
	int  (*set_dec_key)(unsigned char *, int, void *);
	void  (*encrypt_block)(unsigned char*, unsigned char*, void *);
	void  (*decrypt_block)(unsigned char*, unsigned char*, void *);
} CipherManager;

int CBC_Init(CipherManager *cm, int ALG, int encrypt,unsigned char *userkey, int key_len, unsigned char *iv);
int CBC_Update(CipherManager *cm, unsigned char *in, int inLen, unsigned char *out, int *outLen);
int CBC_Final(CipherManager *cm, unsigned char *out, int *outLen);
void CipherManager_Clean(CipherManager *cm);

/* 과제 1 */
#define OPAD 0x5C
#define IPAD 0x36
int HMAC(unsigned char *key, int keyLen, unsigned char *data, int dataLen, unsigned char *md);

// 추가 부분 - 구조체 및 Init, Update, Final 함수
typedef struct hmac_ctx_st {
	SHA256_CTX sha;
	unsigned char iPad[64];
	unsigned char oPad[64];
	unsigned char buf[64];
} HMAC_CTX;
int HMAC_Init(HMAC_CTX* hmac, unsigned char* key, int keyLen);
int HMAC_Update(HMAC_CTX* hmac, unsigned char* data, int dataLen);
int HMAC_Final(unsigned char* md, HMAC_CTX* hmac);

/* 과제 2 */
int CM_Init();
int GetCMStatus();

// 추가 부분
// 1. 상태명
#define CM_Not_Initialized		0x00000000
#define CM_Approved				0x00000001
#define CM_SeriousError			0x00000002
#define Service_Num				3
#define SeriousErrorPrint		printf("CM Status : Serious Error. So service can't be provided.\n")
#define NotApprovedPrint		printf("CM Status is not Approved. So service can't be provided.\n")

// 2. CM의 암호 연산 서비스 상태 ( 첫 수행인가?, 조건부 자가시험에 성공하였나? )를 나타낼 구조체
typedef struct {
	unsigned char is_first[Service_Num];
	unsigned char is_kat_success[Service_Num];
}CM_Service_Stat;
#define True					0x00000001
#define False					0x00000000
#define Success					0x00000001
#define Fail					0x00000000

// 3. 일반천이 함수들
enum Services {
	AES_CBC = 0,
	SHA_256,
	HMAC_SHA_256
};
int CM_Init_Ready();
int CM_KAT(enum Services service);
int CM_Service(enum Services service);
int AES_CBC_KAT();
int SHA_256_KAT();
int HMAC_SHA_256_KAT();
#ifdef  __cplusplus
}
#endif




