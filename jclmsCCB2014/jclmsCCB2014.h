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
