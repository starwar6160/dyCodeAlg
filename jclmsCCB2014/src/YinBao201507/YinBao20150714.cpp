#include "stdafx.h"
#include "jclmsCCB2014.h"
#include "sm3.h"
//�Ӱ������������ݵ��ַ������룬���һ��8λ���������
unsigned int zwBinString2Int32(const char *data, const int len);
void mySM3Update(SM3 * ctx, const char *data, const int len);

namespace myYinBao201507{
	const int ZWHASHLEN=256/8;	//256 bit Hash���
}	//namespace myYinBao201507{

using myYinBao201507::ZWHASHLEN;

//Ĭ�����256bit��HASH��������SM3����SHA256���������ǵ���;�϶�������
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