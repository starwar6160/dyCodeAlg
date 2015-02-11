//#include "CCBelock.h"
//#include "stdafx.h"
//#include "zwSecretBoxCCBcsWrap.h"
#include "jclmsCCB2014.h"
#include "zwSecBoxCSHdr.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <windows.h>
//extern Poco::LogStream * pocoLog;
//#define ZWTRC	zwTrace1027 zwtrace(__FUNCTION__);
#define ZWTRC
//printf("%s\n",__FUNCTION__);



class zwTrace1027 {
	char *m_strClass;
	char m_buf[64];
	LARGE_INTEGER nStart, nEnd;
      public:
	zwTrace1027(const char *strClassName);
	~zwTrace1027();
};

static int g_hidHandle;		//����ģʽ�ܺ�HID�����new���ٸ��඼�����ȫ�ֱ�������HIDͨ�ž��������һ���ࣻ

typedef enum jc_secret_box_status_t {
	JC_SECBOX_SUCCESS = 0,
	JC_SECBOX_FAIL = 1
} JC_SECBOX_STATUS;

#ifdef _DEBUG_1018
////////////////////////////////C#��װ����//////////////////////////////////////////
//���ܺ�HIDͨ��,����0����ʧ�ܣ���������ɹ�
int zwSecboxHidOpen(void);
//�ر��ܺ�HIDͨ��������ΪsecboxHidOpen�ķ���ֵ���
void zwSecboxHidClose(int handleHid);
//ͨ��HID������Ȩ��֤�����ܺ�
void zwSendAuthReq2SecBox(int handleHid);
//ͨ��HID�����ܺз�Ӧ����֤���ɹ�����0������ֵ����ʧ��
int zwVerifyAuthRspFromSecBox(int handleHid);

//д�����ݵ��ܺУ����400���ֽڣ������ʽΪbase64������ַ�������Ҫָ��zwSecboxHidOpen�����ľ�����Լ�������
//�����Ŵ�ԼΪ1-8���ң����廹��Ҫ���Թ�ȷ����
void zwWriteData2SecretBox(int handleHid, const int index, const char *dataB64);
//ָ���ܺ�HID������Լ������ţ���ȡ�ܺе����ݣ�����base64����������ַ���
const char *zwReadDataFromSecretBox(int handleHid, const int index);
#endif // _DEBUG_1018

JCLMSCCB2014_API JcSecBox::JcSecBox()
{
	ZWTRC if (NULL == g_hidHandle) {
#ifdef _DEBUG_USEPOCOLOG1027
		pocoLog->information("jcSecBox OpenFirst");
#endif // _DEBUG_USEPOCOLOG1027
		g_hidHandle = zwSecboxHidOpen();
	}
	if (NULL == g_hidHandle) {
		OutputDebugStringA("JcSecBox open FAIL");
		printf("%s OPEN HID JINCHU SECRET BOX FAIL!\n", __FUNCTION__);
#ifdef _DEBUG_USEPOCOLOG1027
		pocoLog->error("jcSecBox OpenNULL");
#endif // _DEBUG_USEPOCOLOG1027
	}
}

JCLMSCCB2014_API JcSecBox::~JcSecBox()
{
	ZWTRC 
	CloseHid();
}

//20141222.0941.��ΰ.JcSecBox���һ����ȷ��CloseHid�ӿ��Ժ󣬽�������ܺ���֤��д
//֮���ٷ���lms�ܺ�����ͻ�򲻿��豸�����⡣��Դ����C#�޷����ƶ���������ʱ����
//����JcSecBoxû�м�ʱ�����ͷ�HID�豸��
JCLMSCCB2014_API void JcSecBox::CloseHid()
{
	if (NULL != g_hidHandle) {
		//pocoLog->information()<<"jcSecBox Closed handle="<<g_hidHandle<<endl;
		zwSecboxHidClose(g_hidHandle);
		g_hidHandle=NULL;
	}
}

JCLMSCCB2014_API int JcSecBox::SecboxAuth(void)
{
	ZWTRC if (0 == g_hidHandle) {
#ifdef _DEBUG_USEPOCOLOG1027
		pocoLog->error("jcSecbox Error HandleZero");
#endif // _DEBUG_USEPOCOLOG1027
		return JC_SECBOX_FAIL;
	}
	int AuthRes=0;

	for (int i=0;i<3;i++)
	{
		//printf("*****************************SecretBox zwSendAuthReq2SecBox\n");
#ifdef _DEBUG_USEPOCOLOG1027
		pocoLog->information() << "zwSendAuthReq2SecBox" << g_hidHandle << endl;
#endif // _DEBUG_USEPOCOLOG1027
		zwSendAuthReq2SecBox(g_hidHandle);
		//printf("*****************************SecretBox zwVerifyAuthRspFromSecBox\n");
#ifdef _DEBUG_USEPOCOLOG1027
		pocoLog->
			information() << "zwVerifyAuthRspFromSecBox g_hidHandle=" <<
			g_hidHandle << endl;
#endif // _DEBUG_USEPOCOLOG1027
		AuthRes = zwVerifyAuthRspFromSecBox(g_hidHandle);
		if (0 == AuthRes) {
#ifdef _DEBUG_USEPOCOLOG1027
			pocoLog->information() << "SecboxAuth SUCCESSJC" << endl;
#endif // _DEBUG_USEPOCOLOG1027
			//printf("1021.1355.****************************************** *SecretBox Auth SUCCESS\n");
			//�ɹ��Ļ���ֱ�ӷ��سɹ�
			return JC_SECBOX_SUCCESS;
		} 
		else{
			printf("SECBOX AUTH TEMP FAIL,WAIT 1 SEC FOR RETRY\n");
			Sleep(1000);	//�ȴ�1����������֤
		}
	}

//����N���Ժ�����֤ʧ��
#ifdef _DEBUG_USEPOCOLOG1027
		pocoLog->error() << "SecboxAuth FAILJC" << endl;
#endif // _DEBUG_USEPOCOLOG1027
		OutputDebugStringA
		    ("JcSecBox AUTH FAIL###########################");
		printf
		    ("************************************************** ***SecretBox Auth FAIL\n");
		return JC_SECBOX_FAIL;
}

JCLMSCCB2014_API int JcSecBox::SecboxWriteData(const int index, const char *dataB64)
{
	ZWTRC if (0 == g_hidHandle) {
#ifdef _DEBUG_USEPOCOLOG1027
		pocoLog->error("jcSecbox Error HandleZero");
#endif // _DEBUG_USEPOCOLOG1027
		//return 1;
	}
	assert(index >= 0 && index <= 16);
	assert(NULL != dataB64 && strlen(dataB64) > 0);
	if (index < 0 || index > 16) {
#ifdef _DEBUG_USEPOCOLOG1027
		pocoLog->error("jcSecbox Error IndexOutofRange");
#endif // _DEBUG_USEPOCOLOG1027
		printf("Data Index out of range! must in 0 to 16\n");
		return 1;
	}
	if (NULL == dataB64 || strlen(dataB64) == 0) {
#ifdef _DEBUG_USEPOCOLOG1027
		pocoLog->error("jcSecbox Error InputDataZero");
#endif // _DEBUG_USEPOCOLOG1027
		printf("input must base64 encoded string!\n");
		return 1;
	}
#ifdef _DEBUG_USEPOCOLOG1027
	pocoLog->
	    information() << __FUNCTION__ << "index=" << index << " input Data="
	    << dataB64 << endl;
#endif // _DEBUG_USEPOCOLOG1027
	//pocoLog->information("WriteData Auth Start");
	int status = SecboxAuth();
	//pocoLog->information("WriteData Auth End");
	if (JC_SECBOX_SUCCESS == status) {
		//pocoLog->information()<<"WriteData Authed,start write"<<endl;
		zwWriteData2SecretBox(g_hidHandle, index, dataB64);
		//pocoLog->information()<<"WriteData end"<<endl;
	}
	return 0;
}

JCLMSCCB2014_API const char *JcSecBox::SecboxReadData(const int index)
{
	ZWTRC const char *retStr = "";
	if (0 == g_hidHandle) {
#ifdef _DEBUG_USEPOCOLOG1027
		pocoLog->error("jcSecbox Error HandleZero");
#endif // _DEBUG_USEPOCOLOG1027
		return retStr;
	}
	assert(index >= 0 && index <= 16);
	if (index < 0 || index > 16) {
#ifdef _DEBUG_USEPOCOLOG1027
		pocoLog->error("jcSecbox Error IndexOutofRange");
#endif // _DEBUG_USEPOCOLOG1027
		printf("Data Index out of range! must in 0 to 16\n");
		return retStr;
	}
#ifdef _DEBUG_USEPOCOLOG1027
	pocoLog->information() << __FUNCTION__ << " index=" << index << endl;
#endif // _DEBUG_USEPOCOLOG1027
	//pocoLog->information("ReadData Auth Start");
	int status = SecboxAuth();
	//pocoLog->information("ReadData Auth End");
	if (JC_SECBOX_SUCCESS == status) {
		//pocoLog->information()<<"ReadData Authed,start read"<<endl;
		retStr = zwReadDataFromSecretBox(g_hidHandle, index);
		//pocoLog->information()<<"ReadData end"<<endl;
	}
#ifdef _DEBUG_USEPOCOLOG1027
	pocoLog->information() << __FUNCTION__ << "Return " << retStr << endl;
#endif // _DEBUG_USEPOCOLOG1027
	return retStr;
}
