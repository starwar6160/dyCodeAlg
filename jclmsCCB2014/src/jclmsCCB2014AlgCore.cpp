#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <time.h>
#include "jclmsCCB2014AlgCore.h"
#include "zwEcies529.h"
#include "sm3.h"
//ARM����ȥ��assert�����������Ҳ�������
#ifndef _WIN32
#define assert
#endif // _WIN32

#include <string>
using std::string;


void mySM3Update(SM3 * ctx, const char *data, const int len);
void mySM3Update(SM3 * ctx, const int data);

#ifdef  __cplusplus
extern "C" {
#endif
const int ZWMEGA = 1000000;	//һ����
const int ZW_LOWEST_DATE = 1400 * ZWMEGA - 24 * 3600;	//���ǵ�ȡ���������ʹ��ʱ��ֵ����1400M�����԰���͵�ʱ����ǰһ������㹻��
const int ZW_MAXDATA32 = 2048 * ZWMEGA - 3;	//32λ�з����������ܱ�ʾ�����ʱ��ֵ
extern const int ZW_ONE_DAY = 24 * 60 * 60;
int G_SM3DATA_TRACK=1;	//�Ƿ�����͵�SM3�㷨��
//���CRC8,��һ��ʹ��ʱ,crc8Input�����������Ϊ0
unsigned char crc8(const unsigned char crc8Input,const void *inputData, const int inputLen );
#ifdef  __cplusplus
}	//extern "C" {
#endif


const int ZW_SM3_DGST_SIZE = (256 / 8);
const int ZW_CLOSECODE_STEP = 12;	//������ļ��㲽��ʱ�侫��
//�ӵ�ǰʱ��ƫ�Ƶ�����������ô���룬�Է�ֹ��������ļ��ܷ�����ʱ��ȽϿ죬�����λ��ƥ��
//��ʱ�򣬴ӵ�ǰʱ�俪ʼƥ�䣬ʼ���޷�ƥ�䵽��Ӧ�ڡ�������ĳ��ʱ���Ķ�̬�룻
//����20140821�ڽ��й㿪���ķ��ֵ����⣻
const int JC_DCODE_MATCH_FUTURE_SEC = 60 * 3;

//�Ӱ������������ݵ��ַ������룬���һ��8λ���������
unsigned int zwBinString2Int32(const char *data, const int len);
//��ȡ�������3���ɱ������ġ��̶�ֵ��
void myGetCloseCodeVarItem(int *mdatetime, int *mvalidity, int *mclosecode);

//////////////////////////////////////////////////////////////////////////

//������������(��һ�����룬��ʼ������ȵ�)
JCERROR JCLMSCCB2014_API JcLockSetCmdType(const int handle, const JCITYPE mtype,
	const JCCMD cmd)
{
	assert(handle > 0);
	assert(mtype > JCI_START && mtype < JCI_END);
	assert(cmd > JCCMD_START && cmd < JCCMD_END);
	if (handle <= 0 || mtype <= JCI_START || mtype >= JCI_END
		|| cmd <= JCCMD_START || cmd >= JCCMD_END) {
			return EJC_INPUT_NULL;
	}
	JCINPUT *jcp = (JCINPUT *) handle;

	jcp->CmdType = cmd;

	return EJC_SUSSESS;
}

//��ù�񻯵�ʱ�䣬Ҳ���ǰ���ĳ��ֵȡ����ʱ��
int myGetNormalTime(int gmtTime, const int TIMEMOD)
{
	int tail = gmtTime % TIMEMOD;
	return gmtTime - tail;
}

//�����ַ������͵�ֵ
JCERROR JCLMSCCB2014_API JcLockSetString(const int handle, const JCITYPE mtype,
	const char *str)
{
	assert(handle > 0);
	assert(mtype > JCI_START && mtype < JCI_END);
	assert(str != NULL && strlen(str) > 0);
	if (handle <= 0 || mtype <= JCI_START || mtype >= JCI_END
		|| str == NULL || strlen(str) == 0) {
			return EJC_INPUT_NULL;
	}
	JCINPUT *jcp = (JCINPUT *) handle;
	//zwJcLockDumpJCINPUT(handle);
	switch (mtype) {
	case JCI_ATMNO:
		strncpy(jcp->AtmNo, str, sizeof(jcp->AtmNo));
		break;
	case JCI_LOCKNO:
		strncpy(jcp->LockNo, str, sizeof(jcp->LockNo));
		break;
	case JCI_PSK:
		strncpy(jcp->PSK, str, sizeof(jcp->PSK));
		break;
	}
	return EJC_SUSSESS;

}

//�����������͵�ֵ
JCERROR JCLMSCCB2014_API JcLockSetInt(const int handle, const JCITYPE mtype,
	int num)
{
	assert(handle > 0);
	assert(mtype > JCI_START && mtype < JCI_END);
	assert(num > JC_INVALID_VALUE);
	if (handle <= 0 || mtype <= JCI_START || mtype >= JCI_END
		|| num <= JC_INVALID_VALUE) {
			return EJC_INPUT_NULL;
	}
	JCINPUT *jcp = (JCINPUT *) handle;
	assert(jcp->SearchTimeStep >= 6 && jcp->SearchTimeStep <= ZW_ONE_DAY);
	//zwJcLockDumpJCINPUT(handle);
	switch (mtype) {
	case JCI_DATETIME:
		//ʱ����뾭�����
		if (num < (1400 * 1000 * 1000)) {
			return EJC_DATETIME_INVALID;
		}
		jcp->CodeGenDateTime = myGetNormalTime(num, jcp->SearchTimeStep);
		//jcp->dbgSearchTimeStart=jcp->CodeGenDateTime;	//20141128.���ⲿ����ʱ��,��������time����
		break;
	case JCI_VALIDITY:
		assert(num > 0 && num <= 1440 * 7);
		if (num <= 0 || num > (1440 * 7)) {
			return EJC_VALIDRANGE_INVALID;
		}
		jcp->Validity = num;
		break;
	case JCI_CLOSECODE:
		//assert(num>=10000000 && num<=99999999);
		//if (num<10000000 || num>99999999)
		//{
		//      return EJC_CLOSECODE_INVALID;
		//}
		jcp->CloseCode = num;
		break;
	case JCI_TIMESTEP:	//����ʱ�䲽��
		assert(num >= 3 && num <= 3600);
		if (num < 0 || num > 3600) {
			return EJC_CMDTYPE_TIMESTEP_INVALID;
		}
		jcp->SearchTimeStep = num;
		break;
	case JCI_SEARCH_TIME_START:	//����ʱ����ʼֵ
		//ʱ����뾭�����
		if (num < (1400 * 1000 * 1000)) {
			return EJC_DATETIME_INVALID;
		}
		jcp->SearchTimeStart = myGetNormalTime(num, jcp->SearchTimeStep);
		break;
	case JCI_SEARCH_TIME_LENGTH:	//����ʱ�䳤��
		if (num<=0 || num >(25*3600))	//һ����Է�����಻����һ��
		{
			return EJC_CMDTYPE_TIMELEN_INVALID;
		}
		jcp->SearchTimeLength=num;
	}
	return EJC_SUSSESS;
}

//ʱ��GMT����תΪ�ַ���
char * zwTimeSecond2String(const time_t sec)
{
	static char strTime[32];
	memset(strTime, 0, 32);
	struct tm *p;
	time_t tsec = sec;
	p = localtime(&tsec);
	sprintf(strTime, "%04d.%02d%02d:%02d:%02d:%02d",
		(1900 + p->tm_year), (1 + p->tm_mon), p->tm_mday,
		p->tm_hour, p->tm_min, p->tm_sec);
	return strTime;
}

//��ȡ��ʼ�������3���ɱ������ġ��̶�ֵ��
void myGetInitCloseCodeVarItem(int *mdatetime, int *mvalidity, int *mclosecode)
{
	assert(NULL != mdatetime && NULL != mvalidity && NULL != mclosecode);
	if (NULL == mdatetime || NULL == mvalidity || NULL == mclosecode) {
		return;
	}
	//20141113.1748.����ǰ��������ۣ����߳�ʼ�����벻����Ϊʱ��仯���仯
	//����ʱ��ֵ����Ϊ1400M�룬������ʵ�ĸ���ȥ�ķ�����ʶ���ʱ��㶼���ԣ�
	//��Щ��������Ҫ��Ϊ�������õģ�����Ҫ����ͨ���������������ã������
	//ʹ�������ļ�������
	*mdatetime = 1400*ZWMEGA;
	*mvalidity = 1000;
	*mclosecode = 10000000;
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
	return sum;
}


//��ȡ�������3���ɱ������ġ��̶�ֵ��
void myGetCloseCodeVarItem(int *mdatetime, int *mvalidity, int *mclosecode)
{
	const int ZW_CLOSECODE_BASEINPUT = 20000000;	//���������ı�����ʱ��m_closecode�ֶεĹ̶�ֵ
	assert(NULL != mdatetime && NULL != mvalidity && NULL != mclosecode);
	if (NULL == mdatetime || NULL == mvalidity || NULL == mclosecode) {
		return;
	}
	*mdatetime = myGetNormalTime(*mdatetime, ZW_CLOSECODE_STEP);
	*mvalidity = 1440;
	*mclosecode = ZW_CLOSECODE_BASEINPUT;
}

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

void mySM3Update(SM3 * ctx, const int data)
{
	assert(ctx != NULL);
	if (NULL==ctx)
	{
		return;
	}
	assert(ctx->length > 0);
	assert(data >= 0);	//������������������0����������
	int td = data;
	for (int i = 0; i < sizeof(data); i++) {
		unsigned char t = td & 0xff;
		SM3_Update(ctx, t);
		td = td >> 8;
	}
	assert(td == 0);
}

JCERROR JCLMSCCB2014_API JcLockCheckInput(const int handle)
{
	//zwJcLockDumpJCINPUT(handle);
	const int ZW_DIGI8_LOW = 10 * ZWMEGA;
	const int ZW_DIGI8_HIGH = 100 * ZWMEGA;
	JCINPUT *jcp = (JCINPUT *) handle;
	//�ٶ���Щ�����ֶ��ڶ����Ʋ��涼�ǵ�ͬ��int�ĳ��ȵģ��Ա�ͨ��һ��ͳһ�ĺ�������HASH����
	assert(sizeof(jcp->CodeGenDateTime) == sizeof(int));
	assert(sizeof(jcp->Validity) == sizeof(int));
	assert(sizeof(jcp->CloseCode) == sizeof(int));
#ifdef _WIN32
	//�ƺ�ARM��ö�ٴ�С�����ʹ�С��һ��������ֻ��PC�˼����һ�㡣20141203.1108
	//����������������HASHʱ����ʹ�ø��ֶε�����ֵ��Ϊ��������ģ������������
	//��û�в���ʵ����Ӱ�죻
	assert(sizeof(jcp->CmdType) == sizeof(int));
#endif // _WIN32

	assert(jcp->CodeGenDateTime >= (ZW_LOWEST_DATE)
		&& jcp->CodeGenDateTime < ZW_MAXDATA32);
	assert(jcp->CmdType > JCCMD_START && jcp->CmdType < JCCMD_END);
	if (JCCMD_INIT_CLOSECODE != jcp->CmdType && JCCMD_CCB_CLOSECODE != jcp->CmdType) {	//���ɳ�ʼ������,�Լ�����������ʱ���������Ч�ںͱ������ֵ
		assert(jcp->Validity >= 0 && jcp->Validity <= (24 * 60));
		//10,000,000 8λ����Ҳ����10-100M֮��
		assert(jcp->CloseCode >= ZW_DIGI8_LOW
			&& jcp->CloseCode <= ZW_DIGI8_HIGH);
	}

	//�޶���С��14��ͷ��ʱ��(1.4G��)���߿�Ҫ����ZW_MAXDATA32��Ļ����ǷǷ���
	if (jcp->CodeGenDateTime < (ZW_LOWEST_DATE) || jcp->CodeGenDateTime > ZW_MAXDATA32) {	//����ʱ��������2014���ĳ��1.4G��֮ǰ�����ӣ����߳���2038��(32λ�з����������ֵ)����Ч
		return EJC_DATETIME_INVALID;
	}
	if (JCCMD_INIT_CLOSECODE != jcp->CmdType && JCCMD_CCB_CLOSECODE != jcp->CmdType) {	//���ɳ�ʼ������,�Լ�����������ʱ���������Ч�ںͱ������ֵ
		if (jcp->Validity < 0 || jcp->Validity > (24 * 60)) {	//��Ч�ڷ�����Ϊ�������ߴ���һ��������Ч
			return EJC_VALIDRANGE_INVALID;
		}
		if (jcp->CloseCode < ZW_DIGI8_LOW || jcp->CloseCode > ZW_DIGI8_HIGH) {	//������С��8λ���ߴ���8λ����Ч
			return EJC_CLOSECODE_INVALID;
		}
	}			//if (JCCMD_INIT_CLOSECODE!=jcp->m_cmdtype)
	if (jcp->SearchTimeStep <= 0 || jcp->SearchTimeStep >= ZW_ONE_DAY) {	//��������Ϊ�������ߴ���һ��������Ч
		return EJC_CMDTYPE_TIMESTEP_INVALID;
	}
	if (jcp->SearchTimeLength <= 0 || jcp->SearchTimeLength >= (365 * ZW_ONE_DAY)) {	//��ǰ����ʱ��Ϊ�������ߴ���һ��������Ч
		return EJC_CMDTYPE_TIMELEN_INVALID;
	}

	if (jcp->CmdType <= JCCMD_START || jcp->CmdType >= JCCMD_END) {
		return EJC_CMDTYPE_INVALID;
	}
	return EJC_SUSSESS;
}

void JCLMSCCB2014_API JcLockDebugPrint(const int handle)
{
	JCINPUT *jcp = (JCINPUT *) handle;
	//zwJcLockDumpJCINPUT(handle);
	if (EJC_SUSSESS != JcLockCheckInput((const int)jcp)) {
		ZWDBG_ERROR("JcLock Input Para Error!\n");
	}
	//�����̶����������һ��,��ҪΪNULL�����ӷ�����������
	char mainstr[JC_ATMNO_MAXLEN + JC_LOCKNO_MAXLEN + JC_PSK_LEN + 5];
	memset(mainstr, 0, sizeof(mainstr));
	sprintf(mainstr, "%s.%s.%s.", jcp->AtmNo, jcp->LockNo, jcp->PSK);
	//�ɱ����������Ϊ�ַ�������ϵ�һ��
	char vstr[40];		//���°Ѹ����ɱ��ֶε�λ������һ��
	int mdatetime = jcp->CodeGenDateTime;
	int mvalidity = jcp->Validity;
	int mclosecode = jcp->CloseCode;
	if (JCCMD_INIT_CLOSECODE == jcp->CmdType) {	//��������ɳ�ʼ�����룬������ʱ�����ֵ���֮
		myGetInitCloseCodeVarItem(&mdatetime, &mvalidity, &mclosecode);
	}
	sprintf(vstr, "%d.%d.%d.%d", mdatetime, mvalidity,
		mclosecode, jcp->CmdType
		//,jcp->m_stepoftime,jcp->m_reverse_time_length
		);
	//allItems=allItems+buf;
	char allStr[128];
	memset(allStr, 0, 128);
	strncpy(allStr, mainstr, 128);
	strcat(allStr, vstr);
	ZWDBG_NOTICE("All Items = %s \n", allStr);
}

void JCLMSCCB2014_API zwJcLockDumpJCINPUT(const int handle)
{
	unsigned char crc=0;
	JCINPUT *jcp = (JCINPUT *) handle;
	assert(NULL != jcp);
	if (NULL == jcp) {
		ZWDBG_ERROR("%s input is NULL", __FUNCTION__);
		return;
	}
	static int dedupTime;
	//��ֹ�ظ����ͬһ�����ݽṹ
	if (dedupTime==jcp->CodeGenDateTime)
	{
		//return;
	}

	//ZWPRINTF("########JCINPUT DUMP START############\n");
	ZWDBG_INFO("[");
	ZWDBG_INFO("ATMNO:%s\t", jcp->AtmNo);
	crc=crc8(crc,(void *)&jcp->AtmNo,sizeof(jcp->AtmNo));
	ZWDBG_INFO("LOCKNO:%s\t", jcp->LockNo);
	crc=crc8(crc,(void *)&jcp->LockNo,sizeof(jcp->LockNo));
	ZWDBG_INFO("PSK:%s\n", jcp->PSK);
	crc=crc8(crc,(void *)&jcp->PSK,sizeof(jcp->PSK));
	ZWDBG_NOTICE("DATETIME:%d\t%s\t", jcp->CodeGenDateTime,
		zwTimeSecond2String(jcp->CodeGenDateTime));
	crc=crc8(crc,(void *)&jcp->CodeGenDateTime,sizeof(jcp->CodeGenDateTime));
	ZWDBG_INFO("STEP:%d\t", jcp->SearchTimeStep);
	crc=crc8(crc,(void *)&jcp->SearchTimeStep,sizeof(jcp->SearchTimeStep));
	ZWDBG_INFO("RTIME:%d\n", jcp->SearchTimeLength);
	crc=crc8(crc,(void *)&jcp->SearchTimeLength,sizeof(jcp->SearchTimeLength));
	ZWDBG_INFO("VAL:%d\tCloseCode:%d\t", jcp->Validity,
		jcp->CloseCode);
	crc=crc8(crc,(void *)&jcp->Validity,sizeof(jcp->Validity));
	crc=crc8(crc,(void *)&jcp->CloseCode,sizeof(jcp->CloseCode));
	ZWDBG_INFO("CMDTYPE:");
	crc=crc8(crc,(void *)&jcp->CmdType,sizeof(jcp->CmdType));
	ZWDBG_INFO("CRC8=%u\n",crc);
	switch (jcp->CmdType) {
	case JCI_ATMNO:
		ZWDBG_INFO("JCI_ATMNO");
		break;
	case JCI_LOCKNO:
		ZWDBG_INFO("JCI_LOCKNO");
		break;
	case JCI_PSK:
		ZWDBG_INFO("JCI_PSK");
		break;
	case JCI_DATETIME:
		ZWDBG_INFO("JCI_DATETIME");
		break;
	case JCI_VALIDITY:
		ZWDBG_INFO("JCI_VALIDITY");
		break;
	case JCI_CLOSECODE:
		ZWDBG_INFO("JCI_CLOSECODE");
		break;
	case JCI_CMDTYPE:
		ZWDBG_INFO("JCI_CMDTYPE");
		break;
	case JCI_TIMESTEP:
		ZWDBG_INFO("JCI_TIMESTEP");
		break;
	}
	//ZWPRINTF("\n");
	//ZWPRINTF("M_VALIDITY_ARRAY:\n");
	//for (int i = 0; i < NUM_VALIDITY; i++) {
	//	ZWPRINTF("%d\t", jcp->m_validity_array[i]);
	//}
	ZWDBG_INFO("]\n");
	dedupTime=jcp->CodeGenDateTime;
}

//////////////////////////////////////////////////////////////////////////
int JCLMSCCB2014_API JcLockNew(void)
{
	//myCjsonTest1();
	JCINPUT *pjc = new JCINPUT;
	assert(pjc != NULL);
	memset(pjc, 0, sizeof(JCINPUT));
	memset(pjc->AtmNo, 0, JC_ATMNO_MAXLEN + 1);
	memset(pjc->LockNo, 0, JC_LOCKNO_MAXLEN + 1);
	memset(pjc->PSK, 0, JC_PSK_LEN + 1);
	//#ifdef _DEBUG
	//	ZWPRINTF("sizeof JCINPUT=%d\n",sizeof(JCINPUT));
	//#endif // _DEBUG
	//Ϊû�пɱ�����ĳ�ʼ������ָ��3������
	pjc->CodeGenDateTime = 1400 * 1000 * 1000;
	pjc->Validity = 5;	//�õ�������5������Ч�ڣ�����ֱ�ӳ�ʼ��Ϊ5
	pjc->CloseCode = 0;	//������ʼ���������ɵ�ʱ��˴�δ��ʼ��
	pjc->CmdType = JCCMD_INIT_CLOSECODE;
	//pjc->dbgSearchTimeStart=time(NULL);
	pjc->SearchTimeStep = 6;
	//Ĭ������ģʽ������ʱ�䲽��60��.
	//20140805.0903.���������ž��ڵ�Ҫ����ʱ��Ϊ5����Ĭ��ֵ
	// 20140820.2329.���ս���Ҫ�������ʱ��㿪ʼ5������Ч�ڵ�Ҫ��
	// ������Ϊ6�� �Ա㾡���ӽ���Ҫ��
	//Ĭ������ģʽ(������ʼֵ������������ƫ��3����������)����6���ӣ���Ҫ���5���Ӷ�һ�㣬����һ��
	pjc->SearchTimeLength = 9 * 60;
	////��5���ӣ�4Сʱ������õ�����Ч��������ǰ�棬���Ч��
	//int valarr[]={5,MIN_OF_HOUR*4,MIN_OF_HOUR*8,MIN_OF_HOUR*12,15,30,60,MIN_OF_HOUR*24};
	pjc->ValidityArray[0] = 5;
	pjc->ValidityArray[1] = 60 * 4;
	pjc->ValidityArray[2] = 60 * 8;
	pjc->ValidityArray[3] = 60 * 12;
	pjc->ValidityArray[4] = 15;
	pjc->ValidityArray[5] = 30;
	pjc->ValidityArray[6] = 60;
	pjc->ValidityArray[7] = 60 * 24;
	return (int)pjc;
}

int JCLMSCCB2014_API JcLockDelete(const int handle)
{
	JCINPUT *jcp = (JCINPUT *) handle;
	assert(NULL != jcp);
	if (NULL == jcp) {
		return EJC_INPUT_NULL;
	}
	memset(jcp, 0xCC, sizeof(JCINPUT));
	delete jcp;
	return EJC_SUSSESS;
}

//���ɸ������͵Ķ�̬��
int zwJcLockGetDynaCode(const int handle)
{
	//zwTrace1027 tmr(__FUNCTION__"1");
	ZWDBG_INFO("%s\n",__FUNCTION__);
	JcLockDebugPrint(handle);
	zwJcLockDumpJCINPUT(handle);
	const JCINPUT *lock = (const JCINPUT *)handle;
	SM3 sm3;
	char outHmac[ZW_SM3_DGST_SIZE];

	//���ʱ�䵽G_TIMEMOD��ô����
	int l_datetime = myGetNormalTime(lock->CodeGenDateTime,
		lock->SearchTimeStep);
	//60*5);        //20140804.1717.Ӧ�ž��ڵĲ���������ʱ��Ϊ5����ȡ��
	//��Ч�ںͱ�������Ҫ���ݲ�ͬ����ֱ���
	int l_validity = lock->Validity;
	int l_closecode = lock->CloseCode;
	//�����ʼ������ʱ������ʮ����´��¹̶���ʱ�䣬��Ч�ڣ��������ֵ
	//�Ա�����ض������ߺ�PSK��˵����ʼ��������һ��ʮ������ڵĺ㶨ֵ
	if (JCCMD_INIT_CLOSECODE == lock->CmdType) {
		//l_datetime=myGetNormalTime(time(NULL),ZWMEGA);        //��ʼ���������1M��(��Լ12��)��ȡ��ʱ��
		//l_validity=1000;      //��ʼ��Ч��ȡһ����Ч��Χ�ڵĹ���ֵ
		//l_closecode=1000000;  //��ʼ��������ѡһ����Ч��Χ�ڵĹ���ֵ
		myGetInitCloseCodeVarItem(&l_datetime, &l_validity,
			&l_closecode);
	}
	if (JCCMD_CCB_CLOSECODE == lock->CmdType) {	//���������ı����룬����3���̶�����������ض���ȡ��������ʱ�䣬�Լ��̶�����Ч�ں͡������롱��Ϊ����
		myGetCloseCodeVarItem(&l_datetime, &l_validity, &l_closecode);
	}
	JCERROR err = JcLockCheckInput((const int)lock);
	if (EJC_SUSSESS != err) {
		return err;
	}

	G_SM3DATA_TRACK=1;
	SM3_Init(&sm3);

	//�޶���С��14��ͷ��ʱ��(1.4G��)���߿�Ҫ����2048M��Ļ����ǷǷ���
	/////////////////////////////���Ԫ�ؽ���HASH����/////////////////////////////////////////////
	//���ȴ���̶��ֶε�HASHֵ����
	mySM3Update(&sm3, lock->AtmNo, sizeof(lock->AtmNo));
	mySM3Update(&sm3, lock->LockNo, sizeof(lock->LockNo));
	mySM3Update(&sm3, lock->PSK, sizeof(lock->PSK));

	//������������ɱ��ֶε�HASHֵ
	mySM3Update(&sm3, l_datetime);
	mySM3Update(&sm3, l_validity);
	mySM3Update(&sm3, l_closecode);
	mySM3Update(&sm3, lock->CmdType);
	//////////////////////////////HASH�������////////////////////////////////////////////
	memset(outHmac, 0, ZWSM3_DGST_LEN);
	SM3_Final(&sm3, (char *)(outHmac));

#ifdef _DEBUG_20150309
	//�Һ�����������������ARM�������Ż�����0����SM3�㷨������������.20150309.1546
	printf("outHmac=\n");
	for (int i=0;i<ZWSM3_DGST_LEN;i++)
	{
		printf("%02X ",outHmac[i] & 0xFF);
	}
	printf("\n");
#endif // _DEBUG_20150309
	//��HASH���ת��Ϊ8λ�������
	unsigned int res = zwBinString2Int32(outHmac, ZWSM3_DGST_LEN);
	ZWDBG_WARN("%s:dyCode=%d\n",__FUNCTION__,res);
	G_SM3DATA_TRACK=0;
	return res;
}

//����ģʽƥ�䣬ʱ��㾫��Ϊȡ����һ��Сʱ����㣬��Ч�ھ���Ϊ1Сʱ��
//����ҵ��ˣ�����JCOFFLINE����ƥ���ʱ�����Ч�ڣ��������е�ֵ����0
JCMATCH JCLMSCCB2014_API JcLockReverseVerifyDynaCode(const int handle,
	const int dstCode)
{
	//zwTrace1027 tmr(__FUNCTION__"1");
	ZWDBG_WARN("%s dstCode=%d\n",__FUNCTION__,dstCode);
	JcLockDebugPrint(handle);
	zwJcLockDumpJCINPUT(handle);
	JCINPUT *jcp = (JCINPUT *) handle;
	const int MIN_OF_HOUR = 60;	//һСʱ�ķ�����
	JCMATCH jcoff;
	//����Ĭ�ϵ�ʧ�ܷ���ֵ
	jcoff.s_datetime = 0;
	jcoff.s_validity = 0;

	//���ݽ��й㿪���ķ��ֵ����⣬�ӡ������������ӵ�ʱ�俪ʼ����ȥ����
	//ƥ�䣬�Է����������������֮����ʱ����
	int l_datetime = jcp->SearchTimeStart + JC_DCODE_MATCH_FUTURE_SEC;
	int l_closecode = jcp->CloseCode;
	int l_timestep = jcp->SearchTimeStep;
	if (JCCMD_CCB_CLOSECODE == jcp->CmdType) {
		int l_validity = jcp->Validity;	//�����������֤ʱ���ã�ֻ��Ϊ�����㺯������Ҫ��
		//�������֤�����룬�ͻ�һ�ײ���
		//��֤�������ʱ���Ƿ���Ҫ��������ʱ���أ�2014.0729.1509��ΰ
		myGetCloseCodeVarItem(&l_datetime, &l_validity, &l_closecode);
		l_timestep = ZW_CLOSECODE_STEP;
		assert(ZW_CLOSECODE_STEP > 0 && ZW_CLOSECODE_STEP < 60);
	}
	//����ʱ�����ʼ���������m_stepoftime���������ϣ�������޷�ƥ��	
	//������ʼ��������ʱ�Ѿ���񻯹��ˣ�����Ϊ�˷�ֹ֮�������ò�����
	//�����ڴˣ��õ���ʱ���ٴθ��ݲ��������ʼ��ʱ��
	l_datetime=myGetNormalTime(jcp->SearchTimeStart, jcp->SearchTimeStep);;
	l_datetime = myGetNormalTime(l_datetime, l_timestep);
	int tail = l_datetime % l_timestep;
	l_datetime -= tail;	//ȡ�������ݽṹ��ָ���Ĳ���

	//����ʱ�䣬��ǰ�����ݽṹ��ָ����һ��ʱ�䣬�����ӵ�һ���첻��
	int tend = l_datetime - jcp->SearchTimeLength;

	for (int tdate = l_datetime; tdate >= tend; tdate -= l_timestep) {			
		ZWDBG_INFO("%d\t",tdate);	
		for (int v = 0; v < NUM_VALIDITY; v++) {
			SM3 sm3;
			char outHmac[ZW_SM3_DGST_SIZE];

			SM3_Init(&sm3);
			/////////////////////////////���Ԫ�ؽ���HASH����/////////////////////////////////////////////
			mySM3Update(&sm3, jcp->AtmNo, sizeof(jcp->AtmNo));
			mySM3Update(&sm3, jcp->LockNo,
				sizeof(jcp->LockNo));
			mySM3Update(&sm3, jcp->PSK, sizeof(jcp->PSK));

			mySM3Update(&sm3, tdate);
			mySM3Update(&sm3, jcp->ValidityArray[v]);
			mySM3Update(&sm3, l_closecode);
			mySM3Update(&sm3, jcp->CmdType);
			//////////////////////////////HASH�������////////////////////////////////////////////
			memset(outHmac, 0, ZWSM3_DGST_LEN);
			SM3_Final(&sm3, (char *)(outHmac));
			unsigned int res =
				zwBinString2Int32(outHmac, ZWSM3_DGST_LEN);
			//ZWPRINTF("%d:%d\t",tdate,res);	
			//if (3==v)
			//{
			//	ZWPRINTF("\n");
			//}
			if (dstCode == res)	//������ƥ���ʱ�����Ч��
			{
				//��дƥ���ʱ�����Ч�ڵ����
				ZWDBG_WARN("FOUND MATCH UTC SECONDS:%d\tMinites:%d\n", tdate,
					jcp->ValidityArray[v]);
				jcoff.s_datetime = tdate;
				jcoff.s_validity = jcp->ValidityArray[v];
				goto foundMatch;
			}			
		}		//END OF VALIDITY LOOP		
		//ZWPRINTF("\n");
	}			//END OF DATE LOOP
foundMatch:
	return jcoff;
}

int JCLMSCCB2014_API JcLockGetDynaCode(const int handle)
{
	return zwJcLockGetDynaCode(handle);
}

//���ɵ�һ���ڶ�������Ĺ�ͬ����������ֻ����CloseCode�Ǹ�λ�ã������ɵ�һ������ʱ
//��д����ǰһ�εı����룬������֤��ʱ��д���ǵ�һ�����룬���ɵڶ�������ʱ��д������֤��
//atm��ţ�����Ŷ��ǲ�����һ�������޶ȵ�������ַ�����PSK�Ƕ���64�ֽ�HEX�ַ�����س����������ͷ�ļ�
//DyCodeUTCTimeΪָ����̬���ʱ��UTC������һ�㶼�ǵ�ǰʱ�䣬��Ҳ����Ϊ������ǰ���ɶ�̬���ָ��������ʱ��
int embSrvGenDyCode(const JCCMD Pass,const time_t DyCodeUTCTime,const int CloseCode,
	const char *AtmNo,const char *LockNo,const char *PSK)
{
	int handle = JcLockNew();
	JcLockSetString(handle, JCI_ATMNO, AtmNo);
	JcLockSetString(handle, JCI_LOCKNO, LockNo);
	JcLockSetString(handle, JCI_PSK, PSK);
	const int JCMOD=6;
	int tail=DyCodeUTCTime % JCMOD;	//��6���ʱ���񻯣�ʹ��ʱ��Э��һ��
	JcLockSetInt(handle, JCI_DATETIME,static_cast < int >(DyCodeUTCTime-tail));
	JcLockSetCmdType(handle, JCI_CMDTYPE, Pass);
	JcLockSetInt(handle, JCI_CLOSECODE, CloseCode);
	int pass1DyCode = JcLockGetDynaCode(handle);	
	JcLockDelete(handle);
	return pass1DyCode;
}

//У�鶯̬�룬����ƥ���UTCʱ������,��Ҫ�������У�
//JCI_ATMNO,JCI_LOCKNO,JCI_PSK��3����������
//�Լ�CloseCode(�˴�ָ�������ɸö�̬��ʱ��д���Ǹ�ǰһ���ڵ���������)
//JCCMDָʾУ�������һ��Ķ�̬�� 
//SearchStartTimeָ��������ʼʱ�䣬һ������¾��ǵ�ǰʱ���UTC����
int embSrvReverseDyCode(const JCCMD Pass,const int dyCode, const int CloseCode,const time_t SearchStartTime,
	const char *AtmNo,const char *LockNo,const char *PSK)
{
	int handle = JcLockNew();
	JcLockSetString(handle, JCI_ATMNO, AtmNo);
	JcLockSetString(handle, JCI_LOCKNO, LockNo);
	JcLockSetString(handle, JCI_PSK, PSK);
	//���ɶ�̬��ʱ��������������ʼʱ�����������ʱ����Ҫ
	//�ӽ���3���ӿ�ʼ��ǰ����
	JcLockSetInt(handle,JCI_SEARCH_TIME_START,static_cast<int>(SearchStartTime+3*60));
		
	JcLockSetInt(handle, JCI_CLOSECODE, CloseCode);
	JcLockSetCmdType(handle, JCI_CMDTYPE, Pass);	
	//////////////////////////////////////////////////////////////////////////
	JCMATCH pass1Match =
		JcLockReverseVerifyDynaCode(handle, dyCode);
#ifdef WIN32	//�ܿ�ARMû��time����������(����û��RTCʱ���޷��ṩʱ��)
	printf("current time=\t\t%d\n", time(NULL));
#endif // WIN32
	printf("pass1Match Time =\t%d\tValidity=%d\n",
		pass1Match.s_datetime, pass1Match.s_validity);
	JcLockDelete(handle);
	return pass1Match.s_datetime;
}

//�ӽ��е�2��������������PSK�������64�ֽ�HEX�ַ�����
const char * zwGenPSKFromCCB(const char * ccbFact1, const char * ccbFact2)
{
	char ccbIn[ZW_ECIES_HASH_LEN];
	memset(ccbIn,0,ZW_ECIES_HASH_LEN);
	strcpy(ccbIn,ccbFact1);
	strcat(ccbIn,ccbFact2);
	//��ccbInStr����PSK
	const char *ccbPSK=zwMergePsk(ccbIn);
	return ccbPSK;
}


////////////////////////////////ECIES//////////////////////////////////////////
//�ӹ�Կ�����е�2�����������ַ��������������Ϣ�ַ��������������������ͷ�ļ�����ָ�����㹻��С
void zwGenActiveInfo(const char *pubkey,const char *ccbFact1,const char *ccbFact2,char *ccbActiveInfo)
{
	if (NULL==ccbFact1 ||NULL==ccbFact2 || NULL==ccbActiveInfo
		||0==strlen(ccbFact1) || 0==strlen(ccbFact2))
	{
		return;
	}
	const char * ccbPSK=zwGenPSKFromCCB(ccbFact1, ccbFact2);

#ifdef _DEBUG
	printf("ccbPSK=\t%s\n",ccbPSK);
#endif // _DEBUG
	//��PSK�͹�Կ���ɼ�����ϢccbActiveInfo��Ȼ�󼤻���Ϣ�Ϳ���ͨ�����紫���ȥ��
	strcpy(ccbActiveInfo, EciesEncrypt(pubkey, ccbPSK));
}

//���ɹ�Կ˽Կ��,���뻺����������ͷ�ļ�����궨��ֵ��ָ�����㹻��С
void zwGenKeyPair(char *pubKey,char *priKey)
{
	if (NULL==pubKey || NULL==priKey)
	{
		return;
	}
	int hd=EciesGenKeyPair();
	strcpy(pubKey,EciesGetPubKey(hd));
	strcpy(priKey,EciesGetPriKey(hd));
	EciesDelete(hd);
}


//��˽Կ��������Ϣ����ȡPSK�����������������ͷ�ļ�����ָ�����㹻��С
void zwGetPSK(const char *priKey,const char *ccbActiveInfo,char *PSK)
{
	if (NULL==priKey || NULL==ccbActiveInfo || NULL==PSK
		||0==strlen(priKey) || 0==strlen(ccbActiveInfo))
	{
		return;
	}
	strcpy(PSK,EciesDecrypt(priKey,ccbActiveInfo));
}

////////////////////////////////3DES//////////////////////////////////////////
string zwCode8ToHex(int Code8)
{
	//8λ��̬��ת��Ϊ�ַ�����Ȼ���ַ���8�ֽ�ת��ΪHEX���Ա�����3DES��
	//64bit����Ҫ�󣬹������������㽨�е�Ҫ����Ա���ȷ�����ˣ�
	const int BUFLEN = 32;
	char buf[BUFLEN];
	memset(buf, 0, BUFLEN);
	sprintf(buf, "%08d", Code8);
	assert(strlen(buf) == 8);
	char hexbuf[BUFLEN];
	memset(hexbuf, 0, BUFLEN);
	for (int i = 0; i < 8; i++) {
		unsigned char ch = buf[i] % 256;
		sprintf(hexbuf + i * 2, "%02X", ch);
	}
	string retHexStr = hexbuf;
	return retHexStr;
}

