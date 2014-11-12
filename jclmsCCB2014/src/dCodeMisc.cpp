#include "stdafx.h"
#include "jclmsCCB2014.h"
#include "dCodeHdr.h"

//只是作为一个基本的块规整大小单位方便处理
const int ZW_SYNCALG_BLOCK_SIZE = (128 / 8);

int myGetDynaCodeImplCCB201407a(const int handle);
//从包含二进制数据的字符串输入，获得一个8位整数的输出
unsigned int zwBinString2Int32(const char *data, const int len);

int JcLockGetVersion(void)
{
	//含义是是日期
	return 20140901;
}

//获得规格化的时间，也就是按照某个值取整的时间
int myGetNormalTime(int gmtTime, const int TIMEMOD)
{
	int tail = gmtTime % TIMEMOD;
	return gmtTime - tail;
}

void mySm3Process(SM3 * ctx, const char *data, const int len)
{
	assert(ctx != NULL);
	assert(ctx->length > 0);
	assert(data != NULL);
	assert(len > 0);
	for (int i = 0; i < len; i++) {
		SM3_process(ctx, *(data + i));
	}
}

void mySm3Process(SM3 * ctx, const int data)
{
	assert(ctx != NULL);
	assert(ctx->length > 0);
	assert(data >= 0);	//几个整数参数，都是0或者正整数
	int td = data;
	for (int i = 0; i < sizeof(data); i++) {
		unsigned char t = td & 0xff;
		SM3_process(ctx, t);
		td = td >> 8;
	}
	assert(td == 0);
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
	return sum;
}

//获取初始闭锁码的3个可变条件的“固定值”
void myGetInitCloseCodeVarItem(int *mdatetime, int *mvalidity, int *mclosecode)
{
	assert(NULL != mdatetime && NULL != mvalidity && NULL != mclosecode);
	if (NULL == mdatetime || NULL == mvalidity || NULL == mclosecode) {
		return;
	}
	*mdatetime = myGetNormalTime(time(NULL), ZWMEGA);
	*mvalidity = 1000;
	*mclosecode = 10000000;
}

//获取闭锁码的3个可变条件的“固定值”
void myGetCloseCodeVarItem(int *mdatetime, int *mvalidity, int *mclosecode)
{
	const int ZW_CLOSECODE_BASEINPUT = 20000000;	//计算正常的闭锁码时，m_closecode字段的固定值
	assert(NULL != mdatetime && NULL != mvalidity && NULL != mclosecode);
	if (NULL == mdatetime || NULL == mvalidity || NULL == mclosecode) {
		return;
	}
	*mdatetime = myGetNormalTime(time(NULL), ZW_CLOSECODE_STEP);
	*mvalidity = 1440;
	*mclosecode = ZW_CLOSECODE_BASEINPUT;
}
