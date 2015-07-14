#include "stdafx.h"
#include "jclmsCCB2014.h"
//从包含二进制数据的字符串输入，获得一个8位整数的输出
unsigned int zwBinString2Int32(const char *data, const int len);

JCLMSCCB2014_API void __stdcall myYinBaoTest714(void)
{
	const char *ybinput="YinBaoMsg714";
	const int ybLen=strlen(ybinput);
	uint32_t ybn=zwBinString2Int32(ybinput,ybLen);
	printf("%s RESULT IS %u\n",__FUNCTION__,ybn);
};