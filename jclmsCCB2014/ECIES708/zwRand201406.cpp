#include "sha2.h"
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
