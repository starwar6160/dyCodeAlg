#include "stdafx.h"
#include "zwHidComm.h"
#include "zwSecretBoxAuth.h"
#include <windows.h>
#include "zwBaseLib.h"
#include "zwTest201407.h"
#pragma comment(lib,"zwBaseLib.lib")

void myMallocTest1(int argc, _TCHAR** argv)
{
	int a=333;
	int b=555;
	cout<<argc<<" "<<argv[0]<<endl;
	cout<<a<<"+"<<b<<"="<<zwTest717::zwAddTest717(a,b)<<endl;
	zwTest717::zwMemAllocTest01();
}


void myDesEDE2EncTest1(void)
{
	//���Ŀ��������ⳤ��
	string plain="zw20140718.0905";
	string encoded;	//���ܽ������
	//key������64bit����������Ҳ����16��HEX�ַ���������
	string key="446FA6E22A22F0A2";
	cout<<"plain text is \t"<<plain<<endl;
	//���ܲ���
	encoded= zwCrypt::zwDesEDE2EcbEncCCBv1(plain,key);
	cout<<__FUNCTION__<<" "<<encoded<<endl;
	//���ܲ���
	string dePlain=zwCrypt::zwDesEDE2EcbDecCCBv1(encoded,key);
	cout<<__FUNCTION__<<" "<<dePlain<<endl;
}



void zw901StaticLibTest1(void)
{
	cout<<"Result from zw Static Lib is "<<zwsTest1::zwsTestAdd(11,22)<<endl;
}


void zwTimeTest1008(void)
{
	std::string outDate,outTime;
	time_t now=time(NULL);
	time_t tail=now % 300;
	now=now-tail;
	zwTimeFunc::zwGetLocalDateTimeString(now,outDate,outTime);
	time_t outTimeSec=0;
	zwTimeFunc::zwCCBDateTime2UTC(outDate.c_str(),outTime.c_str(),&outTimeSec);
	std::string oDate2,oTime2;
	zwTimeFunc::zwGetLocalDateTimeString(outTimeSec,oDate2,oTime2);
	cout<<"now=\t\t\t\t"<<now<<endl;
	cout<<"Date=\t"<<outDate<<"\tTime=\t"<<outTime<<endl;
	cout<<"zwCCBDateTime2UTC Result=\t"<<outTimeSec<<endl;
	cout<<"zwCCBDateTime2UTC out\n";
	cout<<"Date=\t"<<oDate2<<"\tTime=\t"<<oTime2<<endl;

}

#ifdef _DEBUG_0120
//20141009.��򵥵Ĵ�HIDͨ�ŷ�ʽ���ԣ�
JCHID_STATUS zwHidTest1009Simple(void)
{
	JCHID hidHandle;
	JCHID_STATUS sts=JCHID_STATUS_OK;
	memset(&hidHandle,0,sizeof(JCHID));
	hidHandle.vid=JCHID_VID_2014;
	hidHandle.pid=JCHID_PID_SECBOX;		
	sts=jcHidOpen(&hidHandle);
	if (JCHID_STATUS_OK!=sts)
	{
		//cout<<"VID=\t"<<hidHandle.vid<<"\t"<<"PID="<<hidHandle.pid<<endl;
		//printf("VID=%04X\tPID=%04X\n",hidHandle.vid,hidHandle.pid);
		return sts;
	}
	//////////////////////////////////////////////////////////////////////////
	const char *str="ZhouWeiTestHidSimple20141009.1507"
		"ZhouWeiTestHidSimple20141010.1637ZhouWeiTestHidSimple20141010.1647"
		;
	jcHidSendData(&hidHandle,str,strlen(str));
	Sleep(500);
	unsigned char recvData[JC_HIDMSG_PAYLOAD_LEN];
	memset(recvData,0,JC_HIDMSG_PAYLOAD_LEN);
	int recvLen=0;
	jcHidRecvData(&hidHandle,(char *)recvData,JC_HIDMSG_PAYLOAD_LEN,&recvLen,JCHID_RECV_TIMEOUT);
	printf("Read Payload Data From JcLock is:\n");
	for (int i=0;i<JC_HIDMSG_PAYLOAD_LEN;i++)
	{
		if (i>0 && i % 16 ==0)
		{
			printf("\n");
		}
		printf("%02X ",recvData[i]);
	}
	printf("\n");


	//////////////////////////////////////////////////////////////////////////
	if (NULL!=hidHandle.vid && NULL!=hidHandle.pid)
	{
		jcHidClose(&hidHandle);
	}

	return sts;
};
#endif // _DEBUG_0120

void mySecBoxAuthTest1016()
{
	assert(sizeof(SECBOX_AUTH)<=(JCHID_FRAME_LENGTH-8));
	char secReq[JCHID_FRAME_LENGTH];
	memset(secReq,0,JCHID_FRAME_LENGTH);
	//printf("zwSecboxAuthRequest is\n");
	//////////////////////////////////��λ����ʼ������֤����////////////////////////////////////////
	//��λ��������֤��������ֽڴ���������������ΪHID����Ч�غɷ�����
	printf("PC Send to SecBox AuthRequest is\n");
	int seqLen1=0;
	zwSecboxAuthByteGen(secReq,&seqLen1,JC_SECBOX_AUTH_REQUEST);
	//////////////////////////////////��λ������������֤����////////////////////////////////////////

	//////////////////////////////��λ����ʼ��֤��λ�����////////////////////////////////////////////
	//��λ�������յ�����֤���������֤������0Ϊ�ɹ�������ֵΪʧ��
	int verf=zwSecboxAuthVerify((SECBOX_AUTH *)(secReq+sizeof(SECBOX_DATA_INFO)));
	//�����֤�ɹ������������Ӧ��Ȼ��ͨ��HID���͸���λ��
	//��������ȡ��������Ϊ��������ӣ����Բ��������������Ҫ��1�����ϣ�����ʹ����λ��Ӧ��ͬ������Ҫ�����������Դ
	//Sleep(1200);	
	if (0==verf)
	{	
		printf("Good PC!\n");
		printf("SecBox Recv from PC Data is\n");
		int seqLen2=0;
		zwSecboxAuthByteGen(secReq,&seqLen2,JC_SECBOX_AUTH_RESPONE);
	}
	else
	{
		printf("FAKE PC!\n");
	}
	//////////////////////////////��λ��������֤��λ�����////////////////////////////////////////////
	//////////////////////////////��λ����ʼ��֤�ܺ����////////////////////////////////////////////
	//��λ�������յ����ܺ�Ӧ�������֤������0Ϊ�ɹ�������ֵΪʧ��
	verf=zwSecboxAuthVerify((SECBOX_AUTH *)(secReq+sizeof(SECBOX_DATA_INFO)));
#ifdef _DEBUG_ZWHIDCOMM
	if (0==verf)
	{	
		printf("Good Secbox !\n");
	}
	else
	{
		printf("FAKE Seedbox Found!\n");
	}
#endif // _DEBUG_ZWHIDCOMM

	//////////////////////////////��λ��������֤�ܺ����////////////////////////////////////////////

}

#ifdef _DEBUG_0120
void mySecBoxAuthCSTest1017()
{
	int hnd=zwSecboxHidOpen();
	zwSendAuthReq2SecBox(hnd);
	zwVerifyAuthRspFromSecBox(hnd);
	zwSecboxHidClose(hnd);
}

void mySecBoxWriteTest1017()
{
	int hnd=zwSecboxHidOpen();
	//mySecBoxAuthCSTest1017();

	const char *myLongB64Str1="emhvdXdlaXRlc3RPdXRwdXREZWJ1Z1N0cmluZ0FuZEppbkNodUVMb2NraW5kZXg9MFRvdGFsQmxvY2s9MkN1ckJsb2NrTGVuPTU4U2VkaW5nIERhdGEgQmxvY2sgIzBSZWNldmVkIERhdGEgRnJvbSBKQ0VMb2NrIGlzOg==";
	const char *myShortB64Str2="emhvdXdlaQ==";
	zwWriteData2SecretBox(hnd,1,myLongB64Str1);
	//zwReadDataFromSecretBox(33,1);
	exit(111);

	const char *data1="ZhouWeiTestWrite2SecretBoxDataJinChuElock20141017.1403.zwHidTest1009Simple.zwSecretBoxAuthTest";
	const int BUFLEN=JCHID_FRAME_LENGTH*2;
	char outBufW[BUFLEN];
	memset(outBufW,0,BUFLEN);
	int outLen=0;
	pc2BoxDataWriteRequest(1,data1,strlen(data1),outBufW,&outLen);
	jcHidSendData((JCHID *)hnd,outBufW,outLen);
	char recvBuf[BUFLEN];
	memset(recvBuf,0,BUFLEN);
	jcHidRecvData((JCHID *)hnd,recvBuf,BUFLEN,&outLen,JCHID_RECV_TIMEOUT);
	zwSecboxHidClose(hnd);
}

void mySecBoxReadTest1018()
{
	int hnd=zwSecboxHidOpen();
	zwReadDataFromSecretBox(hnd,1);
	zwSecboxHidClose(hnd);
}
#endif // _DEBUG_0120