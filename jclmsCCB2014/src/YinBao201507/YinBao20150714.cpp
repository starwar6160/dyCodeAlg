#include "stdafx.h"
#include "jclmsCCB2014.h"
#include "sm3.h"
//从包含二进制数据的字符串输入，获得一个8位整数的输出
unsigned int zwBinString2Int32(const char *data, const int len);
void mySM3Update(SM3 * ctx, const char *data, const int len);

namespace myYinBao201507{
	const int ZWHASHLEN=256/8;	//256 bit Hash结果
}	//namespace myYinBao201507{

using myYinBao201507::ZWHASHLEN;

//默认输出256bit的HASH，无论是SM3还是SHA256，对于我们的用途肯定够用了
JCLMSCCB2014_API void __stdcall zwYinBaoGetHash(const char *inData,const int inLength,char* outHash256)
{
	assert(NULL!=inData && strlen(inData)>0);
	assert(inLength>0);
	assert(NULL!=outHash256);
	memset(outHash256,0,ZWHASHLEN);
	printf("%s\n",__FUNCTION__);
	SM3 sm3;
	SM3_Init(&sm3);
	mySM3Update(&sm3, inData,inLength);
	SM3_Final(&sm3, outHash256);
}

JCLMSCCB2014_API int __stdcall zwYinBaoHash2Code( const char *inData )
{	
	int ybn=zwBinString2Int32(inData,ZWHASHLEN);
	return ybn;
};