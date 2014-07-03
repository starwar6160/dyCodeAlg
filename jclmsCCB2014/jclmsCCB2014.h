#ifndef jclmsCCB2014_h__
#define jclmsCCB2014_h__
#include "stdafx.h"

// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� JCLMSCCB2014_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// JCLMSCCB2014_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
#ifdef _ZWUSE_AS_JNI
#define JCLMSCCB2014_API
#else
#ifdef JCLMSCCB2014_EXPORTS
#define JCLMSCCB2014_API __declspec(dllexport)
#else
#define JCLMSCCB2014_API __declspec(dllimport)
#endif
#endif	//_ZWUSE_AS_JNI

//////////////////////////////////////////////////////////////////////////
namespace jclms{
//////////////////////////////////////////////////////////////////////////
typedef enum jc_error_code{
	EJC_SUSSESS,	//�ɹ�
	EJC_FAIL,		//ʧ��
	EJC_INPUT_NULL	//��������ȱ��
} JCERROR;

typedef enum jc_cmd_type{
	JCCMD_INVALID,			//��Ч����
	JCCMD_INIT_CLOSECODE,	//��ʼ������
	JCCMD_CCB_DYPASS1,		//��λ����һ��������
	JCCMD_CCB_LOCK_VERCODE,	//��λ����֤��
	JCCMD_CCB_DYPASS2,		//��λ���ڶ���������
	JCCMD_RESET_KEY		//����Կ��
} JCCMD;


	class JCLMSCCB2014_API JcLockInput
	{
	public:
		//�̶����ز���
		string m_atmno;			//ATM��
		string m_lockno;		//����
		string m_psk;			//PSK������λ����ͬ���е�Ψһ��������
		//�ɱ����ز���
		int m_datetime;		//����ʱ��
		int m_validity;		//��Ч��
		int m_closecode;	//������		
		JCCMD m_cmdtype;		//ģʽ���룬���翪��ģʽ��Զ������ģʽ�����е�����Ҫ��ĸ���ģʽ�ȵ�
	private:		
		JCERROR m_status;
	public:
		JcLockInput(void);
		void DebugPrint(void);	//
		JCERROR CheckInput(void);
	};
	int JCLMSCCB2014_API zwGetDynaCode(const JcLockInput &lock);
	//�Ӱ������������ݵ��ַ������룬���һ��8λ���������
	unsigned int JCLMSCCB2014_API zwBinString2Int32By8(const char *data,const int len);

}	//end of namespace jclms

namespace zwTools{
	//////////////////////////////////////////////////////////////////////////

	//ʵ���ϲ�����AES,ֻ����Ϊһ�������Ŀ������С��λ���㴦��
#define ZW_AES_BLOCK_SIZE	(128/8)	
#define ZW_SM3_DGST_SIZE	(256/8)
	class JCLMSCCB2014_API zwHexTool
	{
		char *m_bin;
		int m_binLen;
		int m_padLen;
		string m_CArrayStr;
	public:
		zwHexTool(const char *HexInput);
		zwHexTool(const void *msg,const int msgLen);
		~zwHexTool();
		//���θ����ڲ�bin��������ַ,�Լ�����
		char * getBin(void);
		int getBinLen(void);
		int getPadedLen(void);
		int getXXTEABlockNum(void);
		void PrintBin(void);
		const char * getCArrayStr(void);
	protected:

	private:
	};
	//////////////////////////////////////////////////////////////////////////
	//��Կ����Ϣ�������ժҪ,���Ƕ����Ƹ�ʽ
	int32_t JCLMSCCB2014_API zwSm3Hmac7(zwHexTool &inPsk,
		zwHexTool &inMessage,
		zwHexTool &outHmac);
}

#endif // jclmsCCB2014_h__
