#include "stdafx.h"
#include "jclmsCCB2014.h"
#include "dCodeHdr.h"

const int ZW_CLOSECODE_BASEINPUT=20000000;	//���������ı�����ʱ��m_closecode�ֶεĹ̶�ֵ
const int ZW_LOWEST_DATE=1400*ZWMEGA-24*3600;	//���ǵ�ȡ���������ʹ��ʱ��ֵ����1400M�����԰���͵�ʱ����ǰһ������㹻��
const int ZW_DIGI8_LOW=10*ZWMEGA;
const int ZW_DIGI8_HIGH=100*ZWMEGA;
const int ZW_MAXDATA32=2048*ZWMEGA-3;	//32λ�з����������ܱ�ʾ�����ʱ��ֵ

//namespace jclms{
const int G_TIMEMOD=60;	//Ĭ�ϰ���60��ȡ����������ݣ����ڷ�ֹһЩ1-3���ӵĴ���
//ʵ���ϲ�����AES,ֻ����Ϊһ�������Ŀ������С��λ���㴦��
//#define ZW_AES_BLOCK_SIZE	(128/8)	
//#define ZW_SM3_DGST_SIZE	(256/8)
const int ZW_AES_BLOCK_SIZE=(128/8)	;
	

int myGetDynaCodeImplCCB201407a( const int handle );
//�Ӱ������������ݵ��ַ������룬���һ��8λ���������
unsigned int zwBinString2Int32(const char *data,const int len);

int JcLockGetVersion(void)
{
	//������������
	return 20140804;	
}

//��ù�񻯵�ʱ�䣬Ҳ���ǰ���ĳ��ֵȡ����ʱ��
int myGetNormalTime(int gmtTime,const int TIMEMOD) 
{
	int tail=gmtTime % TIMEMOD;
	return gmtTime-tail;
}

void mySm3Process(SM3 *ctx,const char *data,const int len)
{
	assert(ctx!=NULL);
	assert(ctx->length>0);
	assert(data!=NULL);
	assert(len>0);
	for (int i=0;i<len;i++)
	{
		SM3_process(ctx,*(data+i));
	}
}

void mySm3Process(SM3 *ctx,const int data)
{
	assert(ctx!=NULL);
	assert(ctx->length>0);
	assert(data>=0);	//������������������0����������
	int td=data;
	for (int i=0;i<sizeof(data);i++)
	{
		unsigned char t=td & 0xff;
		SM3_process(ctx,t);
		td=td>>8;
	}
	assert(td==0);
}


//�Ӱ������������ݵ��ַ������룬���һ��8λ���������
unsigned int zwBinString2Int32(const char *data,const int len)
{
	//��1��ͷ��8λ����΢��һЩ������
	const int dyLow=10000019;
	//��9��ͷ��8λ����΢СһЩ������
	const int dyMod=89999969;	
	const int dyMul=257;	//����ҵ�һ��������Ϊ��˵�����

	unsigned __int64 sum=0;
	for (int i=0;i<len;i++)
	{
		unsigned char t=*(data+i);
		sum*=dyMul;
		sum+=t;		
	}
	//���������ֽ��ʹ�ã������϶���8λ���Ķ�̬��
	sum %=dyMod;
	sum +=dyLow;
	return sum;
}

//��ȡ��ʼ�������3���ɱ������ġ��̶�ֵ��
void myGetInitCloseCodeVarItem(int *mdatetime,int *mvalidity,int *mclosecode)
{
	assert(NULL!=mdatetime && NULL!=mvalidity && NULL!=mclosecode);
	if (NULL==mdatetime || NULL==mvalidity || NULL==mclosecode)
	{
		return;
	}
	*mdatetime=myGetNormalTime(time(NULL),ZWMEGA);
	*mvalidity=1000;
	*mclosecode=10000000;
}

//��ȡ�������3���ɱ������ġ��̶�ֵ��
void myGetCloseCodeVarItem(int *mdatetime,int *mvalidity,int *mclosecode)
{		
	assert(NULL!=mdatetime && NULL!=mvalidity && NULL!=mclosecode);
	if (NULL==mdatetime || NULL==mvalidity || NULL==mclosecode)
	{
		return;
	}
	*mdatetime=myGetNormalTime(time(NULL),ZW_CLOSECODE_STEP);
	*mvalidity=1440;
	*mclosecode=ZW_CLOSECODE_BASEINPUT;
}
