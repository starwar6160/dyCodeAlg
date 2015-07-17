// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 YINBAO15_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何其他项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// YINBAO15_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。
#ifdef YINBAO15_EXPORTS
#define YINBAO15_API __declspec(dllexport)
#else
#define YINBAO15_API __declspec(dllimport)
#endif

#include <cstdint>
// 此类是从 YinBao15.dll 导出的
class YINBAO15_API CYinBao15 {
public:
	CYinBao15(void);
	// TODO: 在此添加您的方法。
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

//默认输出256bit的HASH，无论是SM3还是SHA256，对于我们的用途肯定够用了
YINBAO15_API int __stdcall zwYinBaoGetHashSM3(const char *inData,const int inLength,char* &outHash256);
//输入HEX字符串，必须是双数长度，以及要求的位数,可以用6，8，10，12位，如果输入位数错误，默认8位
YINBAO15_API int64_t __stdcall zwYinBaoHash2Code( const char *inHexStr,int CodeLen );


#ifdef  __cplusplus
}	//extern "C" {
#endif
