#ifndef jclmsCCB2014_h__
#define jclmsCCB2014_h__
#include "zwstdafx.h"

// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� JCLMSCCB2014_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// JCLMSCCB2014_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
//��ARM��ʹ����򿪸ú궨���Ա�����windows��DLL��ض���ı������
//#define _USEON_NONWIN32
#ifdef _USEON_NONWIN32
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
	EJC_INPUT_NULL,	//��������ȱ��
	EJC_DATETIME_INVALID,	//����ʱ��Ƿ�
	EJC_VALIDRANGE_INVALID,	//��Ч�ڷǷ�
	EJC_CLOSECODE_INVALID,	//������Ƿ�
	EJC_CMDTYPE_INVALID		//�������ͷǷ�
} JCERROR;

typedef enum jc_cmd_type{
	JCCMD_INVALID_START,			//��Ч����
	//��ʼ�����룬��ʱ����ATM��ţ�����ţ�PSK���߾���������ɱ�����Ϊ��ֵ
	JCCMD_INIT_CLOSECODE,	
	JCCMD_CCB_DYPASS1,		//��λ����һ��������.��ʱ�������롱�ֶ���д�����ı�����
	JCCMD_CCB_LOCK_VERCODE,	//��λ����֤��.������֤��ʱ���������롱�ֶα�����д��һ��������
	JCCMD_CCB_DYPASS2,		//��λ���ڶ���������.�����ڶ���������ʱ���������롱�ֶ���д��֤��
	JCCMD_RESET_NFCKEY,		//����NFCԿ��
	JCCMD_RESET_LOCKTIME,	//��������ʱ��
	JCCMD_RESET_LOCKSYSTEM,	//��ϵͳ����
	JCCMD_GET_LOCKLOG,		//��ȡ������־	
	JCCMD_INVALID_END
} JCCMD;

//����ƥ��ķ���ֵ
typedef struct jcOfflineResult{
	int s_datetime;
	int s_validity;
}JCOFFLINE;

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
	//lock�ṹ���ڲ�m_cmdtype������������һ�ද̬�룻
	int JCLMSCCB2014_API zwGetDynaCode(const JcLockInput &lock);

//��֤��̬�룬�ɹ�����EJC_SUSSESS��ʧ�ܷ���EJC_FAIL
	JCERROR zwVerifyDynaCode(const JcLockInput &lock,const int dstDyCode);

	JCOFFLINE JCLMSCCB2014_API zwOfflineVerifyDynaCode( const JcLockInput &lock,const int dstCode );
	int JCLMSCCB2014_API getVersion(void);

	JCERROR CheckInputValid( const JcLockInput &lock );

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
#ifdef _DEBUG_USE_OLD_SM3HMAC20140703
	//��Կ����Ϣ�������ժҪ,���Ƕ����Ƹ�ʽ
	int32_t JCLMSCCB2014_API zwSm3Hmac7(zwHexTool &inPsk,
		zwHexTool &inMessage,
		zwHexTool &outHmac);
#endif // _DEBUG_USE_OLD_SM3HMAC20140703
	
}

#endif // jclmsCCB2014_h__
