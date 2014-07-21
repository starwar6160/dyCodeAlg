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
	extern const int ZW_AES_BLOCK_SIZE;
	extern const int ZW_SM3_DGST_SIZE;

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
typedef struct jcLockReverseMatchResult{
	int s_datetime;		//ƥ��������
	int s_validity;		//ƥ������Ч�ڷ�����
	int s_matchTimes;	//ƥ�����ü������
}JCMATCH;

//��Ч�������С�����Ĵ˴��Ժ����Ӧ����Դ������JcLockInput���ʼ��������
//Ϊ��Ч������m_validity_array�����ֵ����Ӧ���
const int NUM_VALIDITY=8;

	struct JCLMSCCB2014_API JcLockInput
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
	///////////////////////////////////����Ϊ�����㷨����ģʽ������///////////////////////////////////////
		//����ʱ�䲽��������Ĭ��Ϊ����ģʽ������1���ӣ�ֵΪ60������ģʽ���Լ�����Ϊ3600�����������ֵ
		int m_stepoftime;	
		//��ǰ���Ƶ�ʱ�䳤��������Ĭ��Ϊ����ģʽ��10���ӣ�ֵΪ600������ֵ��������24Сʱ���Լ�����
		int m_reverse_time_length;					
		//��Ч�ڣ�����NUM_VALIDITY��,Ĭ��ֵ�Ǵ�5���ӵ�24Сʱ��һϵ�У���λ�Ƿ��ӣ������Լ��趨
		//���԰���õ���Ч�������ڸ�������ʼ���ӿ�ƥ���ٶ�
		int m_validity_array[NUM_VALIDITY];
	public:
		JcLockInput(void);
		void DebugPrint(void);	//
		JCERROR CheckInput(void);
		void SetValidity(const int index,const int val);	//����m_validity_array������ĳ��ֵ
	private:				
		JCERROR m_status;
	};
	//lock�ṹ���ڲ�m_cmdtype������������һ�ද̬�룻
	int JCLMSCCB2014_API zwGetDynaCode(const JcLockInput &lock);
	//��֤��̬�룬���ط��Ƴ�����ʱ�����Ч�ڽ����ʧ�ܵĻ������߾�Ϊ0��
	JCMATCH JCLMSCCB2014_API zwReverseVerifyDynaCode( const JcLockInput &lock,const int dstCode );
	//ָ�����㷨����һ����ģ����㷨���������ϵı��ʱ����汾�ı䣬һ�����ֻ��һ���汾��
	int JCLMSCCB2014_API getVersion(void);

	JCERROR CheckInputValid( const JcLockInput &lock );

//}	//end of namespace jclms


#endif // jclmsCCB2014_h__
