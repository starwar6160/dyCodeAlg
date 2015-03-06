// stm32Test2.cpp : �������̨Ӧ�ó������ڵ㡣
//
#define _ZWUSE_AS_JNI
#include "jclmsCCB2014AlgCore.h"
#include "zwEcies529.h"
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <time.h>

JCINPUT g_jcInputTest304;

time_t myNormalTime(const time_t inTime)
{
	const time_t tmFact=600;
	time_t tail=inTime % tmFact;
	return inTime-tail;
}

void myJclmsTest20150305()
{
	int handle = JcLockNew();
	JcLockSetString(handle, JCI_ATMNO, "atm10455761");
	JcLockSetString(handle, JCI_LOCKNO, "lock14771509");
	JcLockSetString(handle, JCI_PSK, "PSKDEMO728");
	//JcLockSetInt(handle,JCI_SEARCH_TIME_START,static_cast<int>(time(NULL)));
	int initCloseCode =38149728;
#ifdef _DEBUG_INITCOLSECODE306
	JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_INIT_CLOSECODE);
	JcLockDebugPrint(handle);
	initCloseCode = JcLockGetDynaCode(handle);
	//����ʼ�������Ƿ���������Χ��
	printf("initCloseCode=\t%d Expect 38149728\n", initCloseCode);
#endif // _DEBUG_INITCOLSECODE306
	//�˴��ڴ�ֵ�Ѿ���Ϊ�̶�����1400M���ʱ��ֵ��Ӧ�ò����ٱ��ˡ�
	//20141113.1751����ǰ���쿪����������޸ġ���ΰ
	//������һ���Լ���ԣ����ʧ�ܣ���˵���бȽϴ�������ˣ��������Ʒ�������
	//ARM�������Ż��������⵼�µ����ɴ���Ķ����ƴ���ȵ�
	//dynaPass1
	//ע�����ںϷ���ʱ��ֵӦ����1.4G�����ˣ�ע��λ����20140721.1709 

	JcLockSetInt(handle, JCI_DATETIME,static_cast < int >(myNormalTime(time(NULL))));
	JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_CCB_DYPASS1);
	JcLockSetInt(handle, JCI_CLOSECODE, initCloseCode);
	JcLockDebugPrint(handle);
	int pass1DyCode = JcLockGetDynaCode(handle);
	printf("dynaPass1=\t%d\n", pass1DyCode);
	JCMATCH pass1Match =
		JcLockReverseVerifyDynaCode(handle, pass1DyCode);
	printf("current time=\t\t%d\n", time(NULL));
	printf("pass1Match Time =\t%d\tValidity=%d\n",
		pass1Match.s_datetime, pass1Match.s_validity);

	JcLockDelete(handle);
}

//���ɵ�һ������
int embSrvGenDyCodePass1(const char *AtmNo,const char *LockNo,const char *PSK,
	const time_t CurUTCTime,const int CloseCode)
{
	int handle = JcLockNew();
	JcLockSetString(handle, JCI_ATMNO, AtmNo);
	JcLockSetString(handle, JCI_LOCKNO, LockNo);
	JcLockSetString(handle, JCI_PSK, PSK);
	//���ɶ�̬��ʱ��������������ʼʱ�����������ʱ����Ҫ
	//JcLockSetInt(handle,JCI_SEARCH_TIME_START,static_cast<int>(SearchStartUTCTime));
	JcLockSetInt(handle, JCI_DATETIME,static_cast < int >(CurUTCTime));
	JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_CCB_DYPASS1);
	JcLockSetInt(handle, JCI_CLOSECODE, CloseCode);
	//JcLockDebugPrint(handle);
	int pass1DyCode = JcLockGetDynaCode(handle);	
	JcLockDelete(handle);
	return pass1DyCode;
}

void myJclmsTest20150306()
{

	int pass1DyCode=embSrvGenDyCodePass1("atm10455761","lock14771509","PSKDEMO728",
		myNormalTime(time(NULL)),33334444);
	printf("dynaPass1=\t%d\n", pass1DyCode);
}

void myECIES_KeyGenTest123(void)
{
	//Ԥ�����úõ����ɵ�һ�ԷǶԳ���Կ����Base64����Ķ���������
	//pubkey= BFlfjkxoiRZFdjQKa/W1JWBwFx+FPyzcFGqXjnlVzMcvIAQyK3C1Ha+G2uGUM4nX5khPQP5AiPFiCyuH2WxZefg=
	//prikey= y+tgryY83ibv2RaQeb93a97+JX0/9cpWf4MrmUUtrzs=
	//���ܽ��ʵ��������Ӣ�ľ��ָ���3��Base64����Ķ��������ݣ����ǲ�����⣬ԭ��͸������
	//ECIES ENC Text= BMMXMJYun+G/Oz4i1LZYmNXR1UM9qTKVfNQPqdorUFCRLvBTE8+SMMoCC/OKAxflDafaosWqnLOA+nkcwvTV8iI=.4AF8XhKkuybS+BQ
	//On+M5BwgwScoCHmkr.0zqyC1eg+7HOhVcbadE7+FRlVZAscomIx9VIfXeHl64wdoDC0X3HJbjEQfIA+flD
	//ECIES DEC Text= C# Port Test plain text 20140722.1625

	//һ����˵��������Կ������һ�ξ����ˣ����µĳ�����Կ�Ծ���ĳһ�����ɵĽ������������
#ifdef _DEBUG126
	//��������һ�γ������ɹ�Կ˽Կ�ԣ�Ȼ�󱣴����ڴ��FLASH���棬�Ժ��Ҫ�õ���ʱ�򣬾ʹ��ڴ����FLASH����ȡ����ʹ��
	//ע��һ��ARM�豸����������һ����γ�������ˣ�һ����Կ/˽Կ�Դ���������ARM�豸���������ڣ��������³�ʼ���Ż��ٴ�����
	int hd = 0;
	hd = EciesGenKeyPair();
	const char *myPubKey=EciesGetPubKey(hd);
	const char *myPriKey=EciesGetPriKey(hd);
	//�����������Կ�ԣ���ô������ɾ�����ͷ��ڴ�
	EciesDelete(hd);
#endif // _DEBUG126
	//����
	char pubkey[ZW_ECIES_PUBKEY_LEN];
	char prikey[ZW_ECIES_PRIKEY_LEN];
	memset(pubkey, 0, sizeof(pubkey));
	memset(prikey, 0, sizeof(prikey));
	//���¹�Կ/˽Կ����ǰ��EciesGenKeyPair���ɣ�Ȼ����EciesGetPubKey��EciesGetPriKeyȡ�õģ��뱣����FLASH�����Ա�����
	strcpy(pubkey,"BFlfjkxoiRZFdjQKa/W1JWBwFx+FPyzcFGqXjnlVzMcvIAQyK3C1Ha+G2uGUM4nX5khPQP5AiPFiCyuH2WxZefg=");
	strcpy(prikey,"y+tgryY83ibv2RaQeb93a97+JX0/9cpWf4MrmUUtrzs=");
	printf("pubkey=%s\nprikey=%s\n",pubkey,prikey);
	//////////////////////////////////////////////////////////////////////////
	//���е�������������PSK���������ӣ�����ƴ����ccbInStr����
	const char *ccbInput1="0123456789ABCDEF";
	const char *ccbInput2="01234ABCDEF56789";
	char ccbInStr[40];
	memset(ccbInStr,0,40);
	strcpy(ccbInStr,ccbInput1);
	strcat(ccbInStr,ccbInput2);
	//��ccbInStr����PSK
	const char *ccbPSK=zwMergePsk(ccbInStr);
	printf("from CCB1 %s and CCB2 %s result \nccbPSK=\t%s\n",ccbInput1,ccbInput2,ccbPSK);
	char ccbActiveInfo[ZW_ECIES_CRYPT_TOTALLEN];
	memset(ccbActiveInfo, 0, sizeof(ccbActiveInfo));
	//��PSK�͹�Կ���ɼ�����ϢccbActiveInfo��Ȼ�󼤻���Ϣ�Ϳ���ͨ�����紫���ȥ��
	strcpy(ccbActiveInfo, EciesEncrypt(pubkey, ccbPSK));
	printf("ccbActiveInfo= %s\n",ccbActiveInfo);
	//��˽Կ�⿪������Ϣ�����PSK
	char dePSK[ZW_ECIES_CRYPT_TOTALLEN];
	memset(dePSK,0,ZW_ECIES_CRYPT_TOTALLEN);
	strcpy(dePSK,EciesDecrypt(prikey, ccbActiveInfo));	
	printf("ccbPSK=\t%s\n",dePSK);
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

//�ӹ�Կ�����е�2�����������ַ��������������Ϣ�ַ��������������������ͷ�ļ�����ָ�����㹻��С
void zwGenActiveInfo(const char *pubkey,const char *ccbFact1,const char *ccbFact2,char *ccbActiveInfo)
{
	if (NULL==ccbFact1 ||NULL==ccbFact2 || NULL==ccbActiveInfo
		||0==strlen(ccbFact1) || 0==strlen(ccbFact2))
	{
		return;
	}
	char ccbIn[ZW_ECIES_HASH_LEN];
	memset(ccbIn,0,ZW_ECIES_HASH_LEN);
	strcpy(ccbIn,ccbFact1);
	strcat(ccbIn,ccbFact2);
	//��ccbInStr����PSK
	const char *ccbPSK=zwMergePsk(ccbIn);
#ifdef _DEBUG
	printf("ccbPSK=\t%s\n",ccbPSK);
#endif // _DEBUG
	//��PSK�͹�Կ���ɼ�����ϢccbActiveInfo��Ȼ�󼤻���Ϣ�Ϳ���ͨ�����紫���ȥ��
	strcpy(ccbActiveInfo, EciesEncrypt(pubkey, ccbPSK));
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

void myECIESTest305();

int main(int argc, char * argv[])
{
	//myECIES_KeyGenTest123();
//////////////////////////////////////////////////////////////////////////
	//myECIESTest305();

	//////////////////////////////////////////////////////////////////////////
	//myJclmsTest20150305();
	myJclmsTest20150306();
	return 0;
}

void myECIESTest305()
{
	//���ɹ�Կ˽Կ�Բ���
	char pubKey[ZW_ECIES_PUBKEY_LEN];
	char priKey[ZW_ECIES_PRIKEY_LEN];
	memset(pubKey,0,ZW_ECIES_PUBKEY_LEN);
	memset(priKey,0,ZW_ECIES_PRIKEY_LEN);
	//���ɲ���ֻ��һ�Σ�����ǰ���Ѿ����ɹ��ˣ����Դ˴�����ע�͵������������ɵĽ��ֱ�Ӹ��ƽ���
	//��ʽʹ��ʱӦ���������ɹ�Կ˽Կ��֮�󱣴浽FLASH���õ�ʱȡ����ʹ��
	//zwGenKeyPair(pubKey,priKey);
	strcpy(pubKey,"BFlfjkxoiRZFdjQKa/W1JWBwFx+FPyzcFGqXjnlVzMcvIAQyK3C1Ha+G2uGUM4nX5khPQP5AiPFiCyuH2WxZefg=");
	strcpy(priKey,"y+tgryY83ibv2RaQeb93a97+JX0/9cpWf4MrmUUtrzs=");
	printf("pubkey=%s\nprikey=%s\n",pubKey,priKey);
	/////////////////////////////���ɼ�����Ϣ/////////////////////////////////////////////
	char ccbActiveInfo[ZW_ECIES_CRYPT_TOTALLEN];
	//const char *ccbInput1="0123456789ABCDEF";
	//const char *ccbInput2="01234ABCDEF56789";
	const char *ccbInput1="1234567890abcdef";
	const char *ccbInput2="1234567890abcdef";

	memset(ccbActiveInfo,0,ZW_ECIES_CRYPT_TOTALLEN);
	zwGenActiveInfo(pubKey,ccbInput1,ccbInput2,ccbActiveInfo);
	printf("ccbActiveInfo=%s\n",ccbActiveInfo);
	/////////////////////////////���ܼ�����Ϣ/////////////////////////////////////////////
	char PSK[ZW_ECIES_HASH_LEN*2];
	memset(PSK,0,ZW_ECIES_HASH_LEN*2);
	zwGetPSK(priKey,ccbActiveInfo,PSK);
	printf("PSK=\t%s\n",PSK);
}

