#include "sha2.h"
//#include <time.h>
#include <stdio.h>
#include <string.h>
#include "zwEcies529.h"
#ifdef WIN32
unsigned int RdtscRand()
{
	unsigned int iRand = 0;
	__asm
	{
		rdtsc;0
			mov iRand, eax;
	}
	return iRand;	
}
#else	//ARM
extern unsigned int RdtscRand();
//�����ARM����ʹ����Ӳ�������������дһ������ԭ�͵ĺ��������ڵ����ļ��У�
#endif // WIN32

void zwRandSeedGen603(char *randBuf,const int randBufLen)
{
	int rndCount=(randBufLen)/sizeof(unsigned int);
	unsigned int rnd;
	sha512_ctx shactx;
	sha512_init(&shactx);
	for (int i=0;i<rndCount;i++)
	{
		rnd = RdtscRand();
		sha512_update(&shactx,(unsigned char *)&rnd,sizeof(rnd));
	}
	unsigned char sha512out[SHA512_DIGEST_SIZE];
	sha512_final(&shactx,sha512out);
	//��������������ж�󣬷�������SHA512�Ľ�������������
	for (int i=0;i<randBufLen;i++)
	{
		randBuf[i]=sha512out[(i)%SHA512_DIGEST_SIZE];
	}

}

//�˴�static�������ܻ��ж��̰߳�ȫ���⣬�Ժ���˵��20140716.1600.��ΰ
char g_zwPskBuf[SHA256_DIGEST_SIZE];
char g_zwPskAsc[SHA256_DIGEST_SIZE*2+1];
ZWECIES_API const char * zwMergePsk(const char *pskInput)
{
	memset(g_zwPskBuf,0,sizeof(g_zwPskBuf));
	memset(g_zwPskAsc,0,sizeof(g_zwPskAsc));
	sha256_ctx shactx;
	memset(&shactx,0,sizeof(sha256_ctx));
	sha256_init(&shactx);

	sha256_update(&shactx,(unsigned char *)pskInput,strlen(pskInput));
	//�����صذ�rnd��ʼ��Ϊһ����ֵ֪��Ϊ���Ǹ����еİ汾���һ���̶������������Ժ���Ը��ĵĵ������أ�
	//��rnd��Ϊһ���ַ�����Ϊ���Ǳ���PC��ARM֮����ֽ���һ�����⡣20160425.1611.��ΰ
	int rnd=20141210;
	char bRnd[16];	//16�ֽڿ϶���������32λ����ת�����ַ��������ж����0�������Ŀռ�
	memset(bRnd,0,16);
	sprintf(bRnd,"%d",rnd);
	sha256_update(&shactx,(unsigned char *)bRnd,strlen(bRnd));
	sha256_final(&shactx,(unsigned char *)g_zwPskBuf);
	for (int i=0;i<SHA256_DIGEST_SIZE;i++)
	{
		sprintf(g_zwPskAsc+i*2,"%02X",(unsigned char)g_zwPskBuf[i]);
	}
	return g_zwPskAsc;
}