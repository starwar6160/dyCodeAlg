// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� YINBAO15_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// YINBAO15_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
#ifdef YINBAO15_EXPORTS
#define YINBAO15_API __declspec(dllexport)
#else
#define YINBAO15_API __declspec(dllimport)
#endif

#include <cstdint>
// �����Ǵ� YinBao15.dll ������
class YINBAO15_API CYinBao15 {
public:
	CYinBao15(void);
	// TODO: �ڴ�������ķ�����
};


#ifdef  __cplusplus
extern "C" {
#endif

extern YINBAO15_API int nYinBao15;

YINBAO15_API int fnYinBao15(void);


#ifdef _DEBUG_20150715
YINBAO15_API void __stdcall zwYinBaoGetHash(const char *inData,const int inLength,char* outHash256);
//zwYinBaoHash2Code
YINBAO15_API int __stdcall zwYinBaoHash2Code(const char *inData);
YINBAO15_API const char * __stdcall zwYinBaoGetHashSM3(const char *inData,const int inLength);
#endif // _DEBUG_20150715

//Ĭ�����256bit��HASH��������SM3����SHA256���������ǵ���;�϶�������
YINBAO15_API int __stdcall zwYinBaoGetHashSM3(const char *inData,const int inLength,char* &outHash256);
//����HEX�ַ�����������˫�����ȣ��Լ�Ҫ���λ��,������6��8��10��12λ���������λ������Ĭ��8λ
YINBAO15_API int64_t __stdcall zwYinBaoHash2Code( const char *inHexStr,int CodeLen );


#ifdef  __cplusplus
}	//extern "C" {
#endif
