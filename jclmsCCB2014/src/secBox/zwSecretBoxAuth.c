#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "sha1.h"
#include "zwSecretBoxAuth.h"
#include "zwHidComm.h"
#include "zwHidSplitMsg.h"
#ifdef WIN32
#include <windows.h>
#endif // WIN32


#define ZWDBGOUT_SECBOX1226	//�����ܺ���һ���ֵĵ������
//����λ������ʹ���Լ���PSK�������ݣ���֤�Է�����������ʱ��ʹ�öԷ���PSK����֤��
//ע�⣬������ֵ���ڻ��ܣ�
//���⣬������ֵ��ø���char���飬�����С������
//0x87,0x34,0xA1,0x5D,0x49,0x24,0x68,0xC9,0x7A,0xE0,0x00,0x00,0x30,0x32,0x00,0x4E,0x4C,0x21,0x72,0x6E,
//0x24,0x68,0xC9,0x7A,0xE0,0x00,0x00,0x30,0x32,0x00,0x4E,0x4C,0x21,0x72,0x6E,0x42,0x66,0x00,0x00,0x00,
const unsigned char SECBOXPSK2014D[SHA1DGSTLEN]=
{0x87,0x34,0xA1,0x5D,0x49,0x24,0x68,0xC9,0x7A,0xE0,0x00,0x00,0x30,0x32,0x00,0x4E,0x4C,0x21,0x72,0x6E};    
const unsigned char SECBOXPSK2014Z[SHA1DGSTLEN]=
{0x24,0x68,0xC9,0x7A,0xE0,0x00,0x00,0x30,0x32,0x00,0x4E,0x4C,0x21,0x72,0x6E,0x42,0x66,0x00,0x00,0x00};

void myDumpPsk1016(void)
{
	int i=0;
	for (i=0;i<20;i++)
	{
		printf("0x%02X,",SECBOXPSK2014D[i] & 0xFF);
	}
	printf("\n");
	for (i=0;i<20;i++)
	{
		printf("0x%02X,",SECBOXPSK2014Z[i] & 0xFF);
	}
	printf("\n");

}

#ifdef _DEBUG_1015
void zwSecretBoxAuthTest1015A(void)
{
	//void sha1(void *dest, const void* msg, uint32_t length_b);	
	const char *mystr="zhouwei test value and";
	int lenb=strlen(mystr)*sizeof(char)*8;
	char dest[20];
	memset(dest,0,20);
	//sha1(dest,mystr,lenb);
	sha1(dest,SECBOXPSK2014D,160);
	{
		int i=0;
		for (i=0;i<20;i++)
		{
			if (i>0 && i % 4 ==0)
			{
				printf(" ");
			}
			printf("%02X",dest[i] & 0xFF);
		}
		printf("\n");
	}
}
#endif // _DEBUG_1015

//����Ӳ�����SHA1�����20�ֽ�(160bit)���ֵ
//�뱣֤���������������20�ֽ�
void zwRandSeedWin32(char *randBuf)
{
	LARGE_INTEGER rnd;
	int pos=0;
	int i=0;
	assert(NULL!=randBuf);
	for (i=0;i<10;i++)
	{
		QueryPerformanceCounter(&rnd);
		sha1(randBuf,&rnd,sizeof(LARGE_INTEGER)*8);	
		Sleep(1);	//���ý��̵��ȵĲ�ȷ�������������
	}
}

void myHexDump1016( int  outReqLen, char * outReq )
{
	int i=0;
	assert(outReqLen>0);
	assert(NULL!=outReq);
//#ifdef _DEBUG
	printf("\n");
	for (i=0;i<(outReqLen);i++)
	{
		if (i>0 && i % 2 ==0)
		{
			printf(" ");
		}
		printf("%02X",outReq[i] & 0xFF);
	}
	printf("\n");
//#endif // _DEBUG
}

//�����������֤����,�Լ���֤�ظ��������SECBOX_AUTH�ṹ�壬�ΪHID֡����64�ֽ�
//ԭ�����ڣ�����λ��������һ�������+��ͬ���в����ܵ�PSK����һ��SHA1�����
//Ȼ����������SHA1��������Է���Ϊ��֤�ķ�ʽ
void zwSecboxAuthDataGen(SECBOX_AUTH *req)
{
	char tmpBuf[JCHID_FRAME_LENGTH];
	char sha1dgst[SHA1DGSTLEN];
	char tmpRand[SHA1DGSTLEN];
	
	time_t now=0;
	assert(NULL!=req);
	if (NULL==req)
	{
		return;
	}

	
//////////////////////////////////////////////////////////////////////////
	memset(tmpBuf,0,JCHID_FRAME_LENGTH);
	memset(sha1dgst,0,SHA1DGSTLEN);
	memset(req,0,sizeof(SECBOX_AUTH));

	zwRandSeedWin32(tmpRand);
	memcpy(tmpBuf,tmpRand,SHA1DGSTLEN);	//��ǰʱ��rdtsc��Դ���ɵ�HASH��������Ƶ�������
	memcpy(tmpBuf+SHA1DGSTLEN,SECBOXPSK2014D,SHA1DGSTLEN);	//PSK�Ķ�������ʽ���Ƶ�������
	sha1(sha1dgst,tmpBuf,(2*SHA1DGSTLEN)*8);	//ʱ���PSK��������SHA1�ó����sha1dgst,��Ϊ���������
	memcpy(req->rand_data,sha1dgst,SHA1DGSTLEN);	//�����ɵġ���������ŵ��ṹ�������Ӧ�ֶΣ�
//////////////////////////////////////////////////////////////////////////
	memset(tmpBuf,0,JCHID_FRAME_LENGTH);
	memset(sha1dgst,0,SHA1DGSTLEN);

	memcpy(tmpBuf,req->rand_data,SHA1DGSTLEN);	//ǰһ����������ġ�����������Ƶ�������
	memcpy(tmpBuf+SHA1DGSTLEN,SECBOXPSK2014D,SHA1DGSTLEN);	//PSK�Ķ�������ʽ���Ƶ�������
	sha1(sha1dgst,tmpBuf,(2*SHA1DGSTLEN)*8);	//"���������PSK��������SHA1�ó����sha1dgst,��Ϊ�����е�SHA1����ֶ�
	memcpy(req->sha1_dgst,sha1dgst,SHA1DGSTLEN);	//�����ɵ�SHA1����ֶηŵ��ṹ�������Ӧ�ֶΣ�
}

//���ɰ���ǰ����2�ֽڡ������͡�+2�ֽڡ������ȡ����ڵ��ܺ���Ȩ�����Ӧ���ֽڴ�
void zwSecboxAuthByteGen(char *outReq,int *outLen,JC_SECBOX_TYPE type)
{
	SECBOX_AUTH req;	
	short int msgType=type;
	int outReqLen=0;
	SECBOX_DATA_INFO info;	
	assert(NULL!=outReq);
	assert(type>=0 && type <=256*128);
//////////////////////////////////////////////////////////////////////////	
	info.msg_type=(unsigned char)msgType;
	info.data_index=0;
	info.data_len=HtoNs(sizeof(SECBOX_AUTH));	
	memcpy(outReq,&info,sizeof(SECBOX_DATA_INFO));
	zwSecboxAuthDataGen(&req);
	memcpy(outReq+sizeof(SECBOX_DATA_INFO),&req,sizeof(SECBOX_AUTH));
	outReqLen=sizeof(SECBOX_DATA_INFO)+sizeof(SECBOX_AUTH);
	*outLen=outReqLen;
	//myHexDump1016(outReqLen, outReq);
}


//////////////////////////////////////////////////////////////////////////

//��������Ļظ���֤Ӧ��,�����SECBOX_AUTH�ṹ�壬�ΪHID֡����64�ֽ�
//����0������֤�ɹ�������ֵ����ʧ�ܣ�
//�����Ӧ��ͨ��ͬһ���ṹ��req�������
int zwSecboxAuthVerify(SECBOX_AUTH *req)
{
	char tmpBuf[JCHID_FRAME_LENGTH];
	char sha1dgst[SHA1DGSTLEN];
	int rcmp=0;	//����memcpy�ȽϽ��
	time_t now=0;
	//////////////////////////////////////////////////////////////////////////
	assert(NULL!=req);
	if (NULL==req)
	{
		return 2;
	}
	
	//////////////////////////////////////////////////////////////////////////
	memset(tmpBuf,0,JCHID_FRAME_LENGTH);
	memset(sha1dgst,0,SHA1DGSTLEN);

	memcpy(tmpBuf,req->rand_data,SHA1DGSTLEN);	//��������������(20�ֽڵ�SHA1�������)���Ƶ�������
	memcpy(tmpBuf+SHA1DGSTLEN,SECBOXPSK2014Z,SHA1DGSTLEN);	//PSK�Ķ�������ʽ���Ƶ�������
	sha1(sha1dgst,tmpBuf,(2*SHA1DGSTLEN)*8);	//ʱ���PSK��������SHA1�ó����sha1dgst,��Ϊ���������
	rcmp=memcmp(sha1dgst,req->sha1_dgst,SHA1DGSTLEN);
	if (0!=rcmp)
	{
		//////////////////////////////////////////////////////////////////////////
		printf("req->randata is ");
		myHexDump1016(SHA1DGSTLEN,req->rand_data);
		printf("req->sha1_dgst is");
		myHexDump1016(SHA1DGSTLEN,req->sha1_dgst);
		printf("Expect SHA1DGST IS ");
		myHexDump1016(SHA1DGSTLEN,sha1dgst);
		myDumpPsk1016();
		//////////////////////////////////////////////////////////////////////////
		return rcmp;	//�������HASHֵ���ȣ�Ҳ������֤ʧ�ܣ�����memcpy�Ľ��
	}
	//////////////////////////////////////////////////////////////////////////
	//�����֤ͨ���ˣ�������λ��ͬ�����㷨�������Ӧ��

	return rcmp;
}

//////////////////////////////////���ݶ�д����////////////////////////////////////////

//��ȡ��Ϣ�����Լ����ȣ�
void zwGetDataMsgTypeLen(const char *msg,JC_SECBOX_TYPE *type,int *msgLen)
{
	SECBOX_DATA_INFO *pInfo=(SECBOX_DATA_INFO *)msg;
	assert(NULL!=msg);
	assert(NULL!=type);
	assert(NULL!=msgLen);

	*type=pInfo->msg_type;
	*msgLen=NtoHs(pInfo->data_len);
}

//����PC���ܺе����ݶ�ȡ�����뱣֤���������������SECBOX_DATA_INFO��ô��
//indexָ����ȡ���ٺ�����
void pc2BoxDataReadRequest(const unsigned char index, char *outBuf,int *outLen)
{
	SECBOX_DATA_INFO info;	
	assert(NULL!=outBuf);
	assert(NULL!=outLen);
	info.msg_type=JC_SECBOX_DATA_READ_REQUEST;
	info.data_index=index;	//ָ��Ҫ��ȡ�����ݵ�������
	info.data_len=HtoNs(0);	//���ݲ������κ����ݣ����Գ���Ϊ0
	memcpy(outBuf,&info,sizeof(SECBOX_DATA_INFO));
	*outLen=sizeof(SECBOX_DATA_INFO);
};

//�����ܺз��صĶ�ȡ���ݣ�������������ݺͳ���
void box2PcDataParse(const char *inData,const int inLen,
						char *outBuf,int *outLen)
{
	SECBOX_DATA_INFO *info=(SECBOX_DATA_INFO *)inData;
	int inRealLen=NtoHs(info->data_len);
	assert(NULL!=inData && inLen>=sizeof(SECBOX_DATA_INFO));
	assert(NULL!=outBuf && NULL!=outLen);

	memcpy(outBuf,inData+sizeof(SECBOX_DATA_INFO),inRealLen);
	*outLen=inRealLen;
}

//����PC���ܺе�����д�������뱣֤���������������"SECBOX_DATA_INFO+ʵ�����ݳ���"��ô��
void pc2BoxDataWriteRequest(const unsigned char index,const char *inData,const int inLen,
						char *outBuf,int *outLen)
{
	SECBOX_DATA_INFO info;	
	assert(NULL!=inData && inLen>0);
	assert(NULL!=outBuf && NULL!=outLen);

	info.msg_type=JC_SECBOX_DATA_WRITE;
	info.data_index=index;
	info.data_len=HtoNs(inLen);	
	memcpy(outBuf,&info,sizeof(SECBOX_DATA_INFO));
	memcpy(outBuf+sizeof(SECBOX_DATA_INFO),inData,inLen);
	*outLen=sizeof(SECBOX_DATA_INFO)+inLen;
};

