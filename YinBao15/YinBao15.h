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


YINBAO15_API void __stdcall zwYinBaoGetHash(const char *inData,const int inLength,char* outHash256);
//zwYinBaoHash2Code
YINBAO15_API int __stdcall zwYinBaoHash2Code(const char *inData);

#ifdef  __cplusplus
}	//extern "C" {
#endif
