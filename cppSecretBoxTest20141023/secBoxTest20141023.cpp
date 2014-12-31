#include "stdafx.h"
#include <string>
#include <windows.h>
#include "jclmsCCB2014.h"
using std::string;
#define _DEBUG1212
#define _DEBUG_ZWHIDCOMM
void zwSecboxWDXtest20141023(void)
{
	char zwbuf[256];
	memset(zwbuf,0,256);
	const int ZWPAUSE = 1500;
	//����һ���ܺж���ʹ�øö����3����������֤����ȡ��д�룬����Open/Close�ɸö����ڲ��Զ���ɣ�            
	int i=0;
	for (int i = 0; i < 10; i++)
	//while(1)
	{
		i++;
		JcSecBox secBox;

		//sprintf(zwbuf,"Secret Box Open###############################################TestByCPP %04d\n",i);
		//printf(zwbuf);
		//OutputDebugStringA(zwbuf);
		//���ܺ�                
#ifdef _DEBUG1212
		printf("SecboxAuth:");
		int status =
			secBox.SecboxAuth();

		if (0==status)
		{
			OutputDebugStringA("SecboxAuth_PASS");
			printf("SecboxAuth_PASS\n");
		}
		else{
			OutputDebugStringA("SecboxAuth_FAIL");
			printf("SecboxAuth_FAIL\n");
			Sleep(500);
			continue;
		}
#endif // _DEBUG1212

		//////////////////////////////////////////////////////////
		//�����һ�αȽϳ������־���base64�����γɵ���������д�д���base64����
		//ʵ���У������ö��������ݱ���֮���Ϊbase64�ַ���д�룻
		//�ڶ��������������ţ���������0��10���ң����廹�ú��Թ�ȷ��
		//������������Ҳ�������ݣ������Ͽ��Դﵽ���400����ֽڣ�������ٻ��ú��Թ�ȷ��
		const char  *myLongB64Str1 = "emhvdXdlaXRlc3RPdXRwdXREZWJ1Z1N0cmluZ0FuZEppbkNodUVMb2NraW5kZXg9MFRvdGFsQmxvY2s9MkN1ckJsb2NrTGVuPTU4U2VkaW5nIERhdGEgQmxvY2sgIzBSZWNldmVkIERhdGEgRnJvbSBKQ0VMb2NrIGlzOg==";
		//ͨ������������ţ���ȡ�ܺ����ݣ����ص�Ҳ��Base64��������ַ����������������ı���Ҳ�����Ƕ���������
		//Console.Out.WriteLine("Secret Box WriteData");
		
		//Console.Out.WriteLine("Secret Box ReadData");
		std::string recvFromSecBox = secBox.SecboxReadData(2);
		secBox.SecboxWriteData(2, myLongB64Str1);
		//Console.Out.WriteLine("WAIT 4 SECONDS FOR PLUG OUT/IN SECRET BOX");
		//System.Threading.Thread.Sleep(ZWPAUSE*5);
		sprintf(zwbuf,"end of secBox test loop %d\n",i);
		//OutputDebugStringA(zwbuf);
		//printf(zwbuf);
	}
	printf("\n");
}

void zwSecboxReadonlyTest20141226(void)
{
	char zwbuf[256];	
	//����һ���ܺж���ʹ�øö����3����������֤����ȡ��д�룬����Open/Close�ɸö����ڲ��Զ���ɣ�            
	int i=0;
	for (int i = 0; i < 1024*64; i++)
		//while(1)
	{
		if (i>0 && i%64==0)
		{
			printf("%d\t",i);
		}
		JcSecBox secBox;

		//���ܺ�                
		//printf("SecboxAuth:");
		int status =
			secBox.SecboxAuth();

		if (0==status)
		{
			//OutputDebugStringA("SecboxAuth_PASS");
			printf(".");
		}
		else{
			memset(zwbuf,0,256);
			sprintf(zwbuf,"SECBOX AUTH FAIL.20141226.Count %d\n",i);
			OutputDebugStringA(zwbuf);
			printf("\n%s\n",zwbuf);
			Sleep(50);
			continue;
		}
		
		//std::string recvFromSecBox = secBox.SecboxReadData(2);
		//sprintf(zwbuf,"end of secBox test loop %d\n",i);
	}
	printf("\n");
}