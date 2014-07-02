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
//namespace jclms{
//////////////////////////////////////////////////////////////////////////
typedef enum jc_error_code{
	EJC_SUSSESS,	//�ɹ�
	EJC_FAIL,		//ʧ��
	EJC_INPUT_NULL	//��������ȱ��
} JCERROR;

typedef enum jc_cmd_type{
	JCCMD_GEN_DYNACODE,		//�������ɶ�̬��
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
		int m_cmdtype;		//ģʽ���룬���翪��ģʽ��Զ������ģʽ�����е�����Ҫ��ĸ���ģʽ�ȵ�
		//////////////////////////////////////////////////////////////////////////
#ifdef JC_USEKEYINFO_201407
		string m_keyno;
		string m_keypin;
#endif // JC_USEKEYINFO_201407
	private:
		JCERROR m_status;
	public:
		JcLockInput(void);
		void DebugPrint(void);	//
		JCERROR CheckInput(void);
	};
//////////////////////////////////////////////////////////////////////////
//}	//end of namespace jclms

#endif // jclmsCCB2014_h__
