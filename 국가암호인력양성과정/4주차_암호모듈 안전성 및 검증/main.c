#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "CM_main.h"
//#include "TestVectors.h"

void MenuDisp(void)
{
	fprintf(stderr, "====================================\n");
	fprintf(stderr, "=   1. Initialize CM               =\n");
	fprintf(stderr, "=   2. CM Service (AES-CBC)        =\n");
	fprintf(stderr, "=   3. CM Service (SHA-256)        =\n");
	fprintf(stderr, "=   4. CM Service (HMAC_SHA-256)   =\n");
	fprintf(stderr, "=   5. CM Service (SelfTest)       =\n");
	fprintf(stderr, "=   6. Check CM Status             =\n");
	fprintf(stderr, "=   7. QUIT                        =\n");
	fprintf(stderr, "=   8. CM_Init_Ready               =\n");
	fprintf(stderr, "====================================\n\n");
}

int main()
{
	char sel[6];

	for(;;)
	{
		system ("cls");
		memset(sel, 0x00, sizeof(sel));
		fflush(stdin);
		MenuDisp();
		printf("[Select ::] ");
		fgets(sel, sizeof(sel), stdin);
		sel[strlen(sel)-1] = '\0';
		if(strlen(sel) <= 0)
			continue;
		else if(!strncmp(sel, "1", strlen(sel)))
		{
			CM_Init();
		}
		else if(!strncmp(sel, "2", strlen(sel)))
		{
			CM_Service(AES_CBC);
			/*
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
			}
			*/
		}
		else if(!strncmp(sel, "3", strlen(sel)))
		{
			CM_Service(SHA_256);
			/*
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
			}
			*/
		}
		else if(!strncmp(sel, "4", strlen(sel)))
		{
			CM_Service(HMAC_SHA_256);
			/*
			unsigned char key[131] = {0x00, };
			unsigned char md[64] = {0x00, };
		
			HMAC(hmackey, 64, hmacmsg, 34, md);
			if (!memcmp(md, hmacmd, 32))
			{
				printf(" - Test Case 1 : OK.\n");
			}
			else
			{
				printf(" - Test Case 1 : Fail.\n");
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
			}

			HMAC(key, 131, message6, 152, md);
			if (!memcmp(md, testVectorH6, 32))
			{
				printf(" - Test Case 3 : OK.\n");
			}
			else
			{
				printf(" - Test Case 3 : Fail.\n");
			}
			*/
		}
		else if(!strncmp(sel, "5", strlen(sel)))
		{
			system("cls");
			memset(sel, 0x00, sizeof(sel));
			fflush(stdin);

			fprintf(stderr, "===== Choose KAT ===================\n");
			fprintf(stderr, "=   1. AES_CBC KAT                 =\n");
			fprintf(stderr, "=   2. SHA_256 KAT                 =\n");
			fprintf(stderr, "=   3. MAC_SHA_256 KAT             =\n");
			fprintf(stderr, "===== Quit : else ==================\n\n");

			printf("[Select ::] ");
			fgets(sel, sizeof(sel), stdin);
			sel[strlen(sel) - 1] = '\0';

			if (strlen(sel) <= 0)
				continue;
			else if (!strncmp(sel, "1", strlen(sel)))
			{
				CM_KAT(AES_CBC);
			}
			else if (!strncmp(sel, "2", strlen(sel)))
			{
				CM_KAT(SHA_256);
			}
			else if (!strncmp(sel, "3", strlen(sel)))
			{
				CM_KAT(HMAC_SHA_256);
			}
			else {
				continue;
			}
			printf("== Press Enter Key to Continue ==");
			getchar();
			continue;
		}
		else if(!strncmp(sel, "6", strlen(sel)))
		{
			printf("Status : 0x%08x\n", GetCMStatus());
		}
		else if (!strncmp(sel, "7", strlen(sel)))
		{
		printf("Bye!!!\n\n");
		exit(0);
		}
		else if (!strncmp(sel, "8", strlen(sel)))
		{
		CM_Init_Ready();
		}
		else
			continue;

		printf("== Press Enter Key to Continue ==");
		getchar();
	}
}