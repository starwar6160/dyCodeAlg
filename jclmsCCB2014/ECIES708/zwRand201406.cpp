#include "sha2.h"
#undef WIN32
#ifdef WIN32
#include <Windows.h>
#endif	//end of WIN32
#include <ctime>

void zwRandSeedGen603(char *randBuf,const int randBufLen)
{
#ifdef WIN32
	int rndCount=(randBufLen)/sizeof(LARGE_INTEGER);
	LARGE_INTEGER rnd;
#else
	int rndCount=(randBufLen)/sizeof(int);
	int rnd;
#endif // WIN32
	sha512_ctx shactx;
	sha512_init(&shactx);
	for (int i=0;i<rndCount;i++)
	{
#ifdef WIN32
		QueryPerformanceCounter(&rnd);
		Sleep(1);	//���ý��̵��ȵĲ�ȷ�������������
#else	
		rnd=clock();
#endif // WIN32
		//*(LONGLONG *)(randBuf)=rnd.QuadPart;
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

