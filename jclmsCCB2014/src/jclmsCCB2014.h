#ifndef jclmsCCB2014_h__
#define jclmsCCB2014_h__
//#include "zwstdafx.h"

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
	EJC_CMDTYPE_TIMESTEP_INVALID,	//ʱ�����������Ƿ�
	EJC_CMDTYPE_TIMELEN_INVALID,	//ʱ���������ȷǷ�
	EJC_CMDTYPE_INVALID		//�������ͷǷ�
} JCERROR;

typedef enum jc_cmd_type{
	JCCMD_START,			//��Ч����
	//��ʼ�����룬��ʱ����ATM��ţ�����ţ�PSK���߾���������ɱ�����Ϊ��ֵ
	//ע�⣬��ʼ����������ɣ�����ÿ�����߽��г�ʼ��ʱ����һ�Σ������������
	//���߳�ʼ��ʱ����һ�γ�ʼ������
	JCCMD_INIT_CLOSECODE,		
	JCCMD_CCB_DYPASS1,		//��λ����һ��������.��ʱ�������롱�ֶ���д�����ı�����
	JCCMD_CCB_LOCK_VERCODE,	//��λ����֤��.������֤��ʱ���������롱�ֶα�����д��һ��������
	JCCMD_CCB_DYPASS2,		//��λ���ڶ���������.�����ڶ���������ʱ���������롱�ֶ���д��֤��
	JCCMD_CCB_CLOSECODE,	//���������ı�����
	JCCMD_RESET_NFCKEY,		//����NFCԿ��
	JCCMD_RESET_LOCKTIME,	//��������ʱ��
	JCCMD_RESET_LOCKSYSTEM,	//��ϵͳ����
	JCCMD_GET_LOCKLOG,		//��ȡ������־	
	JCCMD_END
} JCCMD;

typedef enum jc_input_type{
	JCI_START,		//��Чֵ�����ڽ綨���·�Χ
	JCI_ATMNO,		//ATM��ţ���ʼ��ʱ�趨
	JCI_LOCKNO,		//���ţ���ʼ��ʱ�趨
	JCI_PSK,		//PSK����ʼ��ʱ�趨
	JCI_DATETIME,	//ʱ�����ڣ���λ���룬Ӧ����GMT����
	JCI_VALIDITY,	//��Ч�ڣ���λ�Ƿ���
	JCI_CLOSECODE,	//������
	JCI_CMDTYPE,	//Ҫ����ʲô���͵Ķ�̬��
	JCI_TIMESTEP,	//ʱ����ǰ����ļ������λΪ��
	JCI_END			//��Чֵ�����ڽ綨���·�Χ
}JCITYPE;

//����ƥ��ķ���ֵ
typedef struct jcLockReverseMatchResult{
	int s_datetime;		//ƥ��������
	int s_validity;		//ƥ������Ч�ڷ�����
	//int s_matchTimes;	//ƥ�����ü������
}JCMATCH;

//��Ч�������С�����Ĵ˴��Ժ����Ӧ����Դ������JcLockInput���ʼ��������
//Ϊ��Ч������m_validity_array�����ֵ����Ӧ���
#define NUM_VALIDITY (8)
#define JC_ATMNO_MAXLEN (16)	//ATM��ų������ֵ
#define JC_LOCKNO_MAXLEN (16)	//LOCK��ų������ֵ
#define JC_PSK_LEN (256/4)	//256bit HEX+NULL,���Ƕ���ֵ
#define JC_INVALID_VALUE	(-1)

//����һ���ڲ����ݽṹ�����ؾ�����Ժ����в������Ըþ��Ϊ����
int		JCLMSCCB2014_API JcLockNew(void);
//ɾ���ڲ����ݽṹ���ͷ��ڴ�ռ䣬��������JCLMS��ش������ǰ����
int		JCLMSCCB2014_API JcLockDelete(const int handle);
//�����������͵�ֵ
JCERROR JCLMSCCB2014_API JcLockSetInt(const int handle,const JCITYPE mtype,int num);
//�����ַ������͵�ֵ
JCERROR	JCLMSCCB2014_API JcLockSetString(const int handle,const JCITYPE mtype,const char *str);
//������������(��һ�����룬��ʼ������ȵ�)
JCERROR	JCLMSCCB2014_API JcLockSetCmdType(const int handle,const JCITYPE mtype,const JCCMD cmd);
//�����������Ϸ���
JCERROR JCLMSCCB2014_API JcLockCheckInput(const int handle);
//lock�ṹ���ڲ�m_cmdtype������������һ�ද̬�룻
int		JCLMSCCB2014_API JcLockGetDynaCode(const int handle);
//��֤��̬�룬���ط��Ƴ�����ʱ�����Ч�ڽ����ʧ�ܵĻ������߾�Ϊ0��
JCMATCH	JCLMSCCB2014_API JcLockReverseVerifyDynaCode( const int handle,const int dstCode );
//ָ�����㷨����һ����ģ����㷨���������ϵı��ʱ����汾�ı䣬һ�����ֻ��һ���汾��
int		JCLMSCCB2014_API JcLockGetVersion(void);
//��������ַ���
void	JCLMSCCB2014_API JcLockDebugPrint(const int handle);

const int ZWMEGA=1000000;	//һ����

//}	//end of namespace jclms
//////////////////////////////����Ƶ�C�ӿ�////////////////////////////////////////////

#endif // jclmsCCB2014_h__