#ifndef zwSecretBoxCCBcsWrap_h__
#define zwSecretBoxCCBcsWrap_h__

//#ifdef _ZWUSE_AS_JNI
//#define JCLMSCCB2014_API
//#else
//#ifdef CCBELOCK_EXPORTS
//#define JCLMSCCB2014_API __declspec(dllexport)
//#else
//#define JCLMSCCB2014_API __declspec(dllimport)
//#endif
//#endif
#include "jclmsCCB2014.h"

#ifdef __cplusplus
extern "C" {
#endif

	////////////////////////////////C#��װ����//////////////////////////////////////////
	////���ܺз�����֤���󣬷��سɹ����߽��
	//JCLMSCCB2014_API JC_SECBOX_STATUS SecboxAuth(void);
	////д�����ݵ��ܺУ����400���ֽڣ������ʽΪbase64������ַ�������Ҫָ��zwSecboxHidOpen�����ľ�����Լ�������
	////�����Ŵ�ԼΪ1-8���ң����廹��Ҫ���Թ�ȷ����
	//JCLMSCCB2014_API void SecboxWriteData(const int index,const char *dataB64);
	////ָ���ܺ�HID������Լ������ţ���ȡ�ܺе����ݣ�����base64����������ַ���
	//JCLMSCCB2014_API const char * SecboxReadData(const int index);

#ifdef __cplusplus
}
#endif
#endif				// zwSecretBoxCCBcsWrap_h__
