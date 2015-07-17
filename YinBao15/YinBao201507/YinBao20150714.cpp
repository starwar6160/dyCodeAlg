#include "stdafx.h"
#include "YinBao15.h"
#include "sm3.h"

namespace myYinBao201507{
	const int ZWHASHLEN=256/8;	//256 bit Hash结果
	int myBin2Hex(const char *inData,int inLength,char *outHex,int outLength)
	{
		assert(NULL!=inData && inLength>0);
		assert(NULL!=outHex && outLength>0);
		if (NULL==inData || inLength<=0)
		{
			return -1148;
		}
		if (NULL==outHex || outLength<=0)
		{
			return -1149;
		}
		//在这里，static的智能指针本身，应该不是什么问题。20150715.1453，周伟
		//static shared_ptr<string> rtn(new string);
		// ZWHASHLEN*2+1	
		string hexHashStr;
		for (int i=0;i<inLength;i++)
		{
			uint8_t ch=inData[i];
			char st[3];
			memset(st,0,3);
			sprintf(st,"%02X",ch);
			hexHashStr+=st;
		}
		memset(outHex,0,outLength);
		assert(outLength>=hexHashStr.length());
		strncpy(outHex,hexHashStr.c_str(),outLength);
		return 0;
	}
	void myybSM3Update(SM3 * ctx, const char *data, const int len)
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
	uint64_t zwBinString2NumHL(const char *data, const int len, int64_t lowBound,int64_t highBound)
	{
		assert(NULL!=data && len>0);
		assert(lowBound>0 && highBound>0 && lowBound<highBound && lowBound!=highBound);
		if (NULL==data || len<=0)
		{
			return 1746;
		}
		if (lowBound<=0 || highBound<=0 || lowBound>highBound || lowBound==highBound) 
		{
			return 1748;
		}
		//比1开头的8位数稍微大一些的质数
		
		//比9开头的8位数稍微小一些的质数
		//const int dyMod = 89999969;
		const int dyMul = 257;	//随便找的一个质数作为相乘的因子

		uint64_t sum = 0;
		for (int i = 0; i < len; i++) {
			unsigned char t = *(data + i);
			sum *= dyMul;
			sum += t;
		}
		//这两个数字结合使用，产生肯定是8位数的动态码
		sum %= highBound;
		sum += lowBound;
		return sum;
	}

	//根据输入生成不同位数的动态码
	uint64_t zwBinString2Num(const char *data, const int len,const int numLen)
	{
		assert(NULL!=data && len>0);
		assert(numLen>=4 && numLen<=12);
		if (NULL==data || len<=0)
		{
			return 1746;
		}
		if (numLen<4 || numLen>12)
		{
			return 1747;
		}
		if (8==numLen)
		{
			return zwBinString2NumHL(data,len,10000019L,89999969L);
		}
		if (6==numLen)
		{
			//primes([100000,100100])
			//[100003, 100019, 100043, 100049, 100057, 100069]
			//primes([899900,899999])
			//[899903, 899917, 899939, 899971, 899981]
			return zwBinString2NumHL(data,len,100003L,899981L);
		}
		if (10==numLen)
		{
			//primes([1000000000,1000000100])
			//[1000000007, 1000000009, 1000000021, 1000000033, 1000000087, 1000000093, 1000000097]
			//[8999999909, 8999999929, 8999999993]
			return zwBinString2NumHL(data,len,1000000007L,8999999929L);
		}
		if (12==numLen)
		{
			//primes([100000000000,100000000100])
			// [100000000003, 100000000019, 100000000057, 100000000063, 100000000069, 100000000073, 100000000091]
			//primes([899999999900,899999999999])
			//[899999999903, 899999999929, 899999999947, 899999999959, 899999999981]
			return zwBinString2NumHL(data,len,100000000003L,899999999981L);
		}
		return -1744;
	}
	int myybHex2Bin(const char *inHexStr,char *outBin,int outLen)
	{	
		assert(NULL!=inHexStr);
		assert(NULL!=outBin &&outLen>0);
		if (NULL==inHexStr || NULL==outBin || outLen<=0)
		{
			return -1429;
		}
		int inLen=strlen(inHexStr);
		assert(inLen>0 && (inLen % 2 ==0));
		if (inLen<=0 || (inLen % 2==1))
		{
			return -1430;
		}	
		assert((inLen/2)<=outLen);
		if ((inLen/2)>outLen)
		{
			return -1441;
		}
		memset(outBin,0,outLen);
		for (int i=0;i<inLen/2;i++)
		{
			int32_t ch=0;
			sscanf(inHexStr+i*2,"%02X",&ch);
			assert(ch>=0 && ch<=255);
			outBin[i]=ch;
		}
		return 0;
	}
}	//namespace myYinBao201507{


using myYinBao201507::ZWHASHLEN;
namespace yb=myYinBao201507;

///////////////////////////////COPY FROM JCLMSCCB2014///////////////////////////////////////////







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
	myybSM3Update(&sm3, inData,inLength);
	SM3_Final(&sm3, outHash256);
}


YINBAO15_API const char * __stdcall jcGetHashSM3( const char *inData,const int inLength )
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
	myybSM3Update(&sm3, inData,inLength);
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


YINBAO15_API int __stdcall jcHash2Code8( const char *inHexStr )
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
	int ybn=zwBinString2Num8(inHashBin256,ZWHASHLEN);
	return ybn;
};
#endif // _DEBUG_20150715



//默认输出256bit的HASH，无论是SM3还是SHA256，对于我们的用途肯定够用了
YINBAO15_API int __stdcall jcGetHashSM3(const char *inData,const int inLength,char* &outHash256)
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
	yb::myybSM3Update(&sm3, inData,inLength);
	SM3_Final(&sm3, outHashTmp);

	yb::myBin2Hex(outHashTmp,ZWHASHLEN,outHash256,ZWHASHLEN*2+1);

	return 0;
}



YINBAO15_API int __stdcall jcHash2Code8( const char *inHexStr,char * &outCodeStr )
{	
	assert(NULL!=inHexStr && strlen(inHexStr)>0);
	assert(NULL!=outCodeStr);
	if (NULL==inHexStr || strlen(inHexStr)==0)
	{
		return -1708;
	}
	char inHashBin256[ZWHASHLEN];
	yb::myybHex2Bin(inHexStr,inHashBin256,ZWHASHLEN);
	int64_t ybn=yb::zwBinString2Num(inHashBin256,ZWHASHLEN,8);
	static shared_ptr<string> rtn(new string);
	(*rtn)=lexical_cast<string>(ybn);
	strcpy(outCodeStr,(*rtn).c_str());
	return 0;
};