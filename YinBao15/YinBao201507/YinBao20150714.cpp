#include "stdafx.h"
#include "YinBao15.h"
#include "sm3.h"
//�Ӱ������������ݵ��ַ������룬���һ��8λ���������
unsigned int zwBinString2Int32(const char *data, const int len);
void mySM3Update(SM3 * ctx, const char *data, const int len);

namespace myYinBao201507{
	const int ZWHASHLEN=256/8;	//256 bit Hash���
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
		//�Һ�����������������ARM�������Ż�����0����SM3�㷨������������.20150309.1546
		//���Թ������õĴ���
		if (1==G_SM3DATA_TRACK)
		{
			printf("%02X ",ch);
		}	
#endif // _DEBUG_20150309

	}
}

//�Ӱ������������ݵ��ַ������룬���һ��8λ���������
unsigned int zwBinString2Int32(const char *data, const int len)
{
	//��1��ͷ��8λ����΢��һЩ������
	const int dyLow = 10000019;
	//��9��ͷ��8λ����΢СһЩ������
	const int dyMod = 89999969;
	const int dyMul = 257;	//����ҵ�һ��������Ϊ��˵�����

	unsigned __int64 sum = 0;
	for (int i = 0; i < len; i++) {
		unsigned char t = *(data + i);
		sum *= dyMul;
		sum += t;
	}
	//���������ֽ��ʹ�ã������϶���8λ���Ķ�̬��
	sum %= dyMod;
	sum += dyLow;
	return static_cast<unsigned int>(sum);
}

//////////////////////////////////////////////////////////////////////////


//Ĭ�����256bit��HASH��������SM3����SHA256���������ǵ���;�϶�������
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

YINBAO15_API int __stdcall zwYinBaoHash2Code( const char *inData )
{	
	int ybn=zwBinString2Int32(inData,ZWHASHLEN);
	return ybn;
};