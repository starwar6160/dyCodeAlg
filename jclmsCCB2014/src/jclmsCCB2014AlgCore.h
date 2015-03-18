#ifndef jclmsCCB2014AlgCore_h__
#define jclmsCCB2014AlgCore_h__
#include <time.h>
//�˴��������������ʹ��JCLMSCCB2014_API�ڵ���ʹ��ʱ����Ϊ�ޣ�����ARM��ʹ�ã�
//���ڱ�Ƕ����һ�������jclmsCCB2014.h��ʹ��ʱʹ����DLL��������Ķ���
#ifndef jclmsCCB2014_h__
#define JCLMSCCB2014_API
#endif

#ifdef  __cplusplus
extern "C" {
#endif


	typedef enum jc_error_code {
		EJC_SUSSESS,		//�ɹ�
		EJC_FAIL,		//ʧ��
		EJC_INPUT_NULL,		//��������ȱ��
		EJC_DATETIME_INVALID,	//����ʱ��Ƿ�
		EJC_VALIDRANGE_INVALID,	//��Ч�ڷǷ�
		EJC_CLOSECODE_INVALID,	//������Ƿ�
		EJC_CMDTYPE_TIMESTEP_INVALID,	//ʱ�����������Ƿ�
		EJC_CMDTYPE_TIMELEN_INVALID,	//ʱ���������ȷǷ�
		EJC_CMDTYPE_INVALID	//�������ͷǷ�
	} JCERROR;


	typedef enum jc_cmd_type {
		JCCMD_START,		//��Ч����
		//��ʼ�����룬��ʱ����ATM��ţ�����ţ�PSK���߾���������ɱ�����Ϊ��ֵ
		//ע�⣬��ʼ����������ɣ�����ÿ�����߽��г�ʼ��ʱ����һ�Σ������������
		//���߳�ʼ��ʱ����һ�γ�ʼ������
		JCCMD_INIT_CLOSECODE,
		JCCMD_CCB_DYPASS1,	//��λ����һ��������.��ʱ�������롱�ֶ���д�����ı�����
		JCCMD_CCB_LOCK_VERCODE,	//��λ����֤��.������֤��ʱ���������롱�ֶα�����д��һ��������
		JCCMD_CCB_DYPASS2,	//��λ���ڶ���������.�����ڶ���������ʱ���������롱�ֶ���д��֤��
		JCCMD_CCB_CLOSECODE,	//���������ı�����
		JCCMD_RESET_NFCKEY,	//����NFCԿ��
		JCCMD_RESET_LOCKTIME,	//��������ʱ��
		JCCMD_RESET_LOCKSYSTEM,	//��ϵͳ����
		JCCMD_GET_LOCKLOG,	//��ȡ������־    
		JCCMD_END
	} JCCMD;

	typedef enum jc_input_type {
		JCI_START,		//��Чֵ�����ڽ綨���·�Χ
		JCI_ATMNO,		//ATM��ţ���ʼ��ʱ�趨
		JCI_LOCKNO,		//���ţ���ʼ��ʱ�趨
		JCI_PSK,		//PSK����ʼ��ʱ�趨
		JCI_DATETIME,		//ʱ�����ڣ���λ���룬Ӧ����GMT����
		JCI_VALIDITY,		//��Ч�ڣ���λ�Ƿ���
		JCI_CLOSECODE,		//������
		JCI_CMDTYPE,		//Ҫ����ʲô���͵Ķ�̬��
		JCI_TIMESTEP,		//ʱ����ǰ����ļ������λΪ��
		JCI_SEARCH_TIME_LENGTH,	//����ʱ�䳤�ȣ���λΪ�룬Ĭ��ֵ��9����(�ӵ�ǰʱ��Ĺ�ȥ6���ӵ�����3���ӣ���Ӧ���ܵ�ʱ������������
		JCI_SEARCH_TIME_START,		//����ʱ����ʼֵ��Ĭ��Ϊ��ǰʱ�䣬һ�㲻�����ã���ҪΪ�˵��Ժ͵�Ԫ����Ŀ�����á�20141118������
		JCI_END			//��Чֵ�����ڽ綨���·�Χ
	} JCITYPE;

	//����ƥ��ķ���ֵ
	typedef struct jcLockReverseMatchResult {
		int s_datetime;		//ƥ��������
		int s_validity;		//ƥ������Ч�ڷ�����
	} JCMATCH;

	typedef enum jclmsd_request{
		JCLMS_CCB_INVALID,		//��Чֵ
		JCLMS_CCB_CODEGEN,		//��̬������
		JCLMS_CCB_CODEVERIFY	//��̬�뷴��
	}JCLMSOP;

	//��Ч�������С�����Ĵ˴��Ժ����Ӧ����Դ������JcLockInput���ʼ��������
	//Ϊ��Ч������m_validity_array�����ֵ����Ӧ���
#define NUM_VALIDITY (8)
#define JC_ATMNO_MAXLEN (16)	//ATM��ų������ֵ
#define JC_LOCKNO_MAXLEN (16)	//LOCK��ų������ֵ
#define JC_PSK_LEN (256/4)	//256bit HEX+NULL,���Ƕ���ֵ
#define JC_INVALID_VALUE	(-1)

	//#pragma pack(1)
	typedef struct JcLockInput {
		//�̶����ز���
		char AtmNo[JC_ATMNO_MAXLEN + 1];	//ATM��
		char LockNo[JC_LOCKNO_MAXLEN + 1];	//����
		char PSK[JC_PSK_LEN + 1];	//PSK������λ����ͬ���е�Ψһ��������
		//�ɱ����ز���
		int CodeGenDateTime;		//����ʱ��
		int Validity;		//��Ч��
		int CloseCode;	//������             	
		JCCMD CmdType;	//ģʽ���룬���翪��ģʽ��Զ������ģʽ�����е�����Ҫ��ĸ���ģʽ�ȵ�
		///////////////////////////////////����Ϊ�����㷨����ģʽ������///////////////////////////////////////
		int SearchTimeStart;	//����ʱ����ʼ�㣬Ĭ��ֵӦ���ǵ�ǰʱ�䣬���Ǳ������ʱ���Զ����趨��20141118����,��Ҫ�����Ժ͵�Ԫ����ʹ��
		//����ʱ�䲽��������Ĭ��Ϊ����ģʽ������1���ӣ�ֵΪ60������ģʽ���Լ�����Ϊ3600�����������ֵ
		int SearchTimeStep;
		//��ǰ���Ƶ�ʱ�䳤��������Ĭ��Ϊ����ģʽ��10���ӣ�ֵΪ600������ֵ��������24Сʱ���Լ�����
		int SearchTimeLength;
		//��Ч�ڣ�����NUM_VALIDITY��,Ĭ��ֵ�Ǵ�5���ӵ�24Сʱ��һϵ�У���λ�Ƿ��ӣ������Լ��趨
		//���԰���õ���Ч�������ڸ�������ʼ���ӿ�ƥ���ٶ�
		int ValidityArray[NUM_VALIDITY];
	} JCINPUT;


	//����һ���ڲ����ݽṹ�����ؾ�����Ժ����в������Ըþ��Ϊ����
	int JCLMSCCB2014_API JcLockNew(void);
	//ɾ���ڲ����ݽṹ���ͷ��ڴ�ռ䣬��������JCLMS��ش������ǰ����
	int JCLMSCCB2014_API JcLockDelete(const int handle);
	//�����������͵�ֵ
	JCERROR JCLMSCCB2014_API JcLockSetInt(const int handle, const JCITYPE mtype,
		int num);
	//�����ַ������͵�ֵ
	JCERROR JCLMSCCB2014_API JcLockSetString(const int handle, const JCITYPE mtype,
		const char *str);
	//������������(��һ�����룬��ʼ������ȵ�)
	JCERROR JCLMSCCB2014_API JcLockSetCmdType(const int handle, const JCITYPE mtype,
		const JCCMD cmd);
	//�����������Ϸ���
	JCERROR JCLMSCCB2014_API JcLockCheckInput(const int handle);
	//lock�ṹ���ڲ�m_cmdtype������������һ�ද̬�룻
	int JCLMSCCB2014_API JcLockGetDynaCode(const int handle);
	//��֤��̬�룬���ط��Ƴ�����ʱ�����Ч�ڽ����ʧ�ܵĻ������߾�Ϊ0��
	JCMATCH JCLMSCCB2014_API JcLockReverseVerifyDynaCode(const int handle,
		const int dstCode);
	//ָ�����㷨����һ����ģ����㷨���������ϵı��ʱ����汾�ı䣬һ�����ֻ��һ���汾��
	int JCLMSCCB2014_API JcLockGetVersion(void);
	//��������ַ���
	void JCLMSCCB2014_API JcLockDebugPrint(const int handle);
	void JCLMSCCB2014_API zwJcLockDumpJCINPUT(const int handle);
	int JCLMSCCB2014_API zwSM3StandardTestVector(void);

//////////////////////////////////////////////////////////////////////////
//���ɵ�һ���ڶ�������,��֤�룬�����룬��ʼ������Ĺ�ͬ����������ֻ����CloseCode�Ǹ�λ�ã�
//�����ɵ�һ������ʱ��д����ǰһ�εı����룬������֤��ʱ��д���ǵ�һ�����룬���ɵڶ�������ʱ��д������֤��
//atm��ţ�����Ŷ��ǲ�����һ�������޶ȵ�������ַ�����PSK�Ƕ���64�ֽ�HEX�ַ�����س����������ͷ�ļ�
//DyCodeUTCTimeΪָ����̬���ʱ��UTC������һ�㶼�ǵ�ǰʱ�䣬��Ҳ����Ϊ������ǰ���ɶ�̬���ָ��������ʱ��
	int embSrvGenDyCode(const JCCMD Pass,const time_t DyCodeUTCTime,const int CloseCode,
		const char *AtmNo,const char *LockNo,const char *PSK);

//У�鶯̬�룬����ƥ���UTCʱ������,��Ҫ�������У�
//JCI_ATMNO,JCI_LOCKNO,JCI_PSK��3����������
//�Լ�CloseCode(�˴�ָ�������ɸö�̬��ʱ��д���Ǹ�ǰһ���ڵ���������)
//JCCMDָʾУ�������һ��Ķ�̬��
//SearchStartTimeָ��������ʼʱ�䣬һ������¾��ǵ�ǰʱ���UTC����
int embSrvReverseDyCode(const JCCMD Pass,const int dyCode, const int CloseCode,const time_t SearchStartTime,
		const char *AtmNo,const char *LockNo,const char *PSK);
//�ӽ��е�2��������������PSK�������64�ֽ�HEX�ַ�����
const char * zwGenPSKFromCCB(const char * ccbFact1, const char * ccbFact2);

////////////////////////////////ECIES//////////////////////////////////////////
//�ӹ�Կ�����е�2�����������ַ��������������Ϣ�ַ��������������������ͷ�ļ�����ָ�����㹻��С
void zwGenActiveInfo(const char *pubkey,const char *ccbFact1,const char *ccbFact2,char *ccbActiveInfo);
//���ɹ�Կ˽Կ��,���뻺����������ͷ�ļ�����궨��ֵ��ָ�����㹻��С
void zwGenKeyPair(char *pubKey,char *priKey);
//��˽Կ��������Ϣ����ȡPSK�����������������ͷ�ļ�����ָ�����㹻��С
void zwGetPSK(const char *priKey,const char *ccbActiveInfo,char *PSK);


#ifdef WIN32
#ifdef _DEBUG
//#define ZWDEBUG(format,...) printf(" "__FILE__","__FUNCTION__",LINE:%d:"format"", __LINE__,##__VA_ARGS__)
//ע�������format�����˫������һ��Ҫ
#define ZWDBG_INFO(format,...) printf(""format"", ##__VA_ARGS__)
#define ZWDBG_NOTICE(format,...) printf(""format"", ##__VA_ARGS__)
#define ZWDBG_WARN(format,...) printf(""format"", ##__VA_ARGS__)
#define ZWDBG_ERROR(format,...) printf(""format"", ##__VA_ARGS__)
#else
#define ZWDBG_INFO(format,...) 
//#define ZWDBG_NOTICE(format,...) 
//#define ZWDBG_WARN(format,...) 
//#define ZWDBG_ERROR(format,...) 
#define ZWDBG_NOTICE(format,...) printf(""format"", ##__VA_ARGS__)
#define ZWDBG_WARN(format,...) printf(""format"", ##__VA_ARGS__)
#define ZWDBG_ERROR(format,...) printf(""format"", ##__VA_ARGS__)

#endif // _DEBUG
#endif // WIN32


#ifdef  __cplusplus
}	//extern "C" {
#endif
#endif // jclmsCCB2014AlgCore_h__
