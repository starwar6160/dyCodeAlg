// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� JCLMSCCB2014_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// JCLMSCCB2014_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
#ifdef JCLMSCCB2014_EXPORTS
#define JCLMSCCB2014_API __declspec(dllexport)
#else
#define JCLMSCCB2014_API __declspec(dllimport)
#endif

// �����Ǵ� jclmsCCB2014.dll ������
class JCLMSCCB2014_API CjclmsCCB2014 {
public:
	CjclmsCCB2014(void);
	// TODO: �ڴ�������ķ�����
};

extern JCLMSCCB2014_API int njclmsCCB2014;

JCLMSCCB2014_API int fnjclmsCCB2014(void);


//////////////////////////////////////////////////////////////////////////
namespace jclms{
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
		int64_t m_datetime;		//����ʱ��
		int32_t m_validity;		//��Ч��
		int32_t m_closecode;	//������
		int32_t m_cmdtype;		//ģʽ���룬���翪��ģʽ��Զ������ģʽ�����е�����Ҫ��ĸ���ģʽ�ȵ�
		//////////////////////////////////////////////////////////////////////////
#ifdef JC_USEKEYINFO_201407
		string m_keyno;
		string m_keypin;
#endif // JC_USEKEYINFO_201407
	public:
		JcLockInput(void);
		void print(void);
		JCERROR check(void);
	};
//////////////////////////////////////////////////////////////////////////
}	//end of namespace jclms

