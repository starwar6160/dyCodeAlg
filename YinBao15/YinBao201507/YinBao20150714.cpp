#include "stdafx.h"
#include "YinBao15.h"
#include "sm3.h"
//从包含二进制数据的字符串输入，获得一个8位整数的输出
unsigned int zwBinString2Int32(const char *data, const int len);
void mySM3Update(SM3 * ctx, const char *data, const int len);

namespace myYinBao201507{
	const int ZWHASHLEN=256/8;	//256 bit Hash结果
}	//namespace myYinBao201507{

using myYinBao201507::ZWHASHLEN;

///////////////////////////////COPY FROM JCLMSCCB2014///////////////////////////////////////////
void mySM3Update(SM3 * ctx, const char *data, const int len)
{
	assert(ctx != NULL);
	assert(data != NULL);
	if (NULL==ctx || NULL==data)
	{
		return;
	}
	assert(ctx->length > 0);
	assert(len > 0);
	for (int i = 0; i < len; i++) {
		SM3_Update(ctx, *(data + i));
		int ch=*(data + i);
#ifdef _DEBUG_20150309
		//我和孙玉龙，又是遇到ARM编译器优化级别0导致SM3算法结果错误的问题.20150309.1546
		//调试过程中用的代码
		if (1==G_SM3DATA_TRACK)
		{
			printf("%02X ",ch);
		}	
#endif // _DEBUG_20150309

	}
}

//从包含二进制数据的字符串输入，获得一个8位整数的输出
unsigned int zwBinString2Int32(const char *data, const int len)
{
	//比1开头的8位数稍微大一些的质数
	const int dyLow = 10000019;
	//比9开头的8位数稍微小一些的质数
	const int dyMod = 89999969;
	const int dyMul = 257;	//随便找的一个质数作为相乘的因子

	unsigned __int64 sum = 0;
	for (int i = 0; i < len; i++) {
		unsigned char t = *(data + i);
		sum *= dyMul;
		sum += t;
	}
	//这两个数字结合使用，产生肯定是8位数的动态码
	sum %= dyMod;
	sum += dyLow;
	return static_cast<unsigned int>(sum);
}

//////////////////////////////////////////////////////////////////////////



//改回去出参方式，这些代码留着备用
#ifdef _DEBUG_20150715
//默认输出256bit的HASH，无论是SM3还是SHA256，对于我们的用途肯定够用了
YINBAO15_API void __stdcall zwYinBaoGetHash(const char *inData,const int inLength,char* outHash256)
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


YINBAO15_API const char * __stdcall zwYinBaoGetHashSM3( const char *inData,const int inLength )
{
	//在这里，static的智能指针本身，应该不是什么问题。20150715.1453，周伟
	static shared_ptr<string> rtn(new string);
	assert(NULL!=inData && strlen(inData)>0);
	assert(inLength>0);	
	(*rtn).clear();
	char outHash256[ZWHASHLEN];
	memset(outHash256,0,ZWHASHLEN);
	SM3 sm3;
	SM3_Init(&sm3);
	mySM3Update(&sm3, inData,inLength);
	SM3_Final(&sm3, outHash256);
	
	for (int i=0;i<ZWHASHLEN;i++)
	{
		uint8_t ch=outHash256[i];
		char st[3];
		memset(st,0,3);
		sprintf(st,"%02X",ch);
		(*rtn)+=st;
	}
	return (*rtn).c_str();
}


YINBAO15_API int __stdcall zwYinBaoHash2Code( const char *inHexStr )
{	
	assert(NULL!=inHexStr && strlen(inHexStr)>0);
	char inHashBin256[ZWHASHLEN];
	memset(inHashBin256,0,ZWHASHLEN);
	for (int i=0;i<ZWHASHLEN;i++)
	{
		int32_t ch=0;
		sscanf(inHexStr+i*2,"%02X",&ch);
		assert(ch>=0 && ch<=255);
		inHashBin256[i]=ch;
	}
	int ybn=zwBinString2Int32(inHashBin256,ZWHASHLEN);
	return ybn;
};
#endif // _DEBUG_20150715


//默认输出256bit的HASH，无论是SM3还是SHA256，对于我们的用途肯定够用了
YINBAO15_API int __stdcall zwYinBaoGetHashSM3(const char *inData,const int inLength,char* &outHash256)
{
	assert(NULL!=inData && strlen(inData)>0);
	assert(inLength>0);
	assert(NULL!=(*outHash256));	
	if (NULL==inData || strlen(inData)==0 ||inLength<=0)
	{
		return -1706;
	}
	if (NULL==outHash256)
	{
		return -1707;
	}
	char outHashTmp[ZWHASHLEN];
	memset(outHashTmp,0,ZWHASHLEN);
	printf("%s\n",__FUNCTION__);
	SM3 sm3;
	SM3_Init(&sm3);
	mySM3Update(&sm3, inData,inLength);
	SM3_Final(&sm3, outHashTmp);

	//在这里，static的智能指针本身，应该不是什么问题。20150715.1453，周伟
	//static shared_ptr<string> rtn(new string);
	memset(outHash256,0,ZWHASHLEN*2+1);
	string hexHashStr;
	for (int i=0;i<ZWHASHLEN;i++)
	{
		uint8_t ch=outHashTmp[i];
		char st[3];
		memset(st,0,3);
		sprintf(st,"%02X",ch);
		hexHashStr+=st;
	}
	strcpy(outHash256,hexHashStr.c_str());
	return 0;
}

YINBAO15_API int __stdcall zwYinBaoHash2Code( const char *inHexStr )
{	
	assert(NULL!=inHexStr && strlen(inHexStr)>0);
	if (NULL==inHexStr || strlen(inHexStr)==0)
	{
		return -1708;
	}
	char inHashBin256[ZWHASHLEN];
	memset(inHashBin256,0,ZWHASHLEN);
	for (int i=0;i<ZWHASHLEN;i++)
	{
		int32_t ch=0;
		sscanf(inHexStr+i*2,"%02X",&ch);
		assert(ch>=0 && ch<=255);
		inHashBin256[i]=ch;
	}
	int ybn=zwBinString2Int32(inHashBin256,ZWHASHLEN);
	return ybn;
};