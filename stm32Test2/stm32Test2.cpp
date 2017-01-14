// stm32Test2.cpp : �������̨Ӧ�ó������ڵ㡣
//
#define _ZWUSE_AS_JNI
#include "jclmsCCB2014AlgCore.h"
#include "zwEcies529.h"
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <time.h>
#include <string>
#include <assert.h>
#include <string>
#include <iostream>
using std::string;
using std::cout;
using std::endl;
#include "des.h"

extern "C"
{
	void	__stdcall	Sleep(uint32_t dwMilliseconds	);	
};


void myECIES_KeyGenTest325(void)
{
	//Ԥ�����úõ����ɵ�һ�ԷǶԳ���Կ����Base64����Ķ���������
	//pubkey= BFlfjkxoiRZFdjQKa/W1JWBwFx+FPyzcFGqXjnlVzMcvIAQyK3C1Ha+G2uGUM4nX5khPQP5AiPFiCyuH2WxZefg=
	//prikey= y+tgryY83ibv2RaQeb93a97+JX0/9cpWf4MrmUUtrzs=
	//���ܽ��ʵ��������Ӣ�ľ��ָ���3��Base64����Ķ��������ݣ����ǲ������⣬ԭ��͸������
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
	time_t nowTime=time(NULL);
	printf("EciesEncryptCCB1503 set Origin ActInfo Time is %u\n",nowTime);
	strcpy(ccbActiveInfo, EciesEncryptCCB1503(pubkey, ccbPSK,nowTime));
	printf("ccbActiveInfo= %s\n",ccbActiveInfo);
	//��˽Կ�⿪������Ϣ�����PSK
	char dePSK[ZW_ECIES_CRYPT_TOTALLEN];
	memset(dePSK,0,ZW_ECIES_CRYPT_TOTALLEN);
	time_t origTime=0;
	strcpy(dePSK,EciesDecryptCCB1503(prikey, ccbActiveInfo,&origTime));	
	printf("EciesDecryptCCB1503 get Origin ActInfo Time is %u\n",origTime);
	printf("ccbPSK=\t%s\n",dePSK);
}

void myECIESTest305ForArm()
{
	/////////////////////////////���ɼ�����Ϣ/////////////////////////////////////////////
	char ccbActiveInfo[ZW_ECIES_CRYPT_TOTALLEN];
	//const char *ccbInput1="0123456789ABCDEF";
	//const char *ccbInput2="01234ABCDEF56789";
	const char *ccbInput1="1234567890abcdef";
	const char *ccbInput2="1234567890abcdef";
	
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

	memset(ccbActiveInfo,0,ZW_ECIES_CRYPT_TOTALLEN);
	time_t nowTime=1400111222;
	zwGenActiveInfo(pubKey,ccbInput1,ccbInput2,nowTime,ccbActiveInfo);
	printf("ccbActiveInfo=%s\nnowTime=\t%u\n",ccbActiveInfo,nowTime);
	/////////////////////////////���ܼ�����Ϣ/////////////////////////////////////////////
	char PSK[ZW_ECIES_HASH_LEN*2];
	memset(PSK,0,ZW_ECIES_HASH_LEN*2);
	time_t origTime=0;
	embGetPSK2(priKey,ccbActiveInfo,PSK,&origTime);
	printf("PSK=\t%s \norigTime=\t%u\n",PSK,origTime);
}

void myECIESTest326ForArmTest1WM()
{
	//���ɹ�Կ˽Կ�Բ���
	char pubKey[ZW_ECIES_PUBKEY_LEN];
	char priKey[ZW_ECIES_PRIKEY_LEN];
	memset(pubKey,0,ZW_ECIES_PUBKEY_LEN);
	memset(priKey,0,ZW_ECIES_PRIKEY_LEN);
	//���ɲ���ֻ��һ�Σ�����ǰ���Ѿ����ɹ��ˣ����Դ˴�����ע�͵������������ɵĽ��ֱ�Ӹ��ƽ���
	//��ʽʹ��ʱӦ���������ɹ�Կ˽Կ��֮�󱣴浽FLASH���õ�ʱȡ����ʹ��
	//zwGenKeyPair(pubKey,priKey);
	strcpy(pubKey,"BCsvfsK4WGcvECbJGq69ZWS20B+LRv+n+FqQt79esR5DLM2TZny0atXngTUXa7kg5cEfAG1mjueu95L3buAW5xg=");
	strcpy(priKey,"O5AA9G0HWtw5cW6We7LER2A6Fkli+Pgy3mZ7or+q8/k=");
	printf("pubkey=%s\nprikey=%s\n",pubKey,priKey);
	/////////////////////////////���ɼ�����Ϣ/////////////////////////////////////////////
	char ccbActiveInfo[ZW_ECIES_CRYPT_TOTALLEN];
	//const char *ccbInput1="0123456789ABCDEF";
	//const char *ccbInput2="01234ABCDEF56789";
	const char *ccbInput1="1234567890abcdef";
	const char *ccbInput2="1234567890abcdef";

	memset(ccbActiveInfo,0,ZW_ECIES_CRYPT_TOTALLEN);
	time_t nowTime=time(NULL);
	zwGenActiveInfo(pubKey,ccbInput1,ccbInput2,nowTime,ccbActiveInfo);
	printf("ccbActiveInfo=%s\nnowTime=\t%u\n",ccbActiveInfo,nowTime);
	/////////////////////////////���ܼ�����Ϣ/////////////////////////////////////////////
	char PSK[ZW_ECIES_HASH_LEN*2];
	memset(PSK,0,ZW_ECIES_HASH_LEN*2);
	time_t origTime=0;
	const char *wmTest954="BHy3c7f6oSpJVOq0ona/1VZ28SC18C53/eGAO5Tk7LwmEjUWdDaS1+kpfEjPLAGRXVaXP6NYvJG4qC8Gz9pUkz0=.KAB9g96yj7IqnlFfxIICo8Q0orLw5A8E.VQf0J0Tv6je2r9LZOie4Ihg9VbUyQR7ae1R5dATHTIBqvmdhFwO7PyVokiv58QrPqVZhy9vJIkdi8ytmgzxJSAoeThmewvfZHT+o2cabIoA=";
	embGetPSK2(priKey,wmTest954,PSK,&origTime);
	printf("PSK=\t%s \norigTime=\t%u\n",PSK,origTime);
}


void myECIESTest305ForArm();

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

	JcLockSetInt(handle, JCI_DATETIME,static_cast < int >(time(NULL)));
	JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_CCB_DYPASS1);
	JcLockSetInt(handle, JCI_CLOSECODE, initCloseCode);
	JcLockDebugPrint(handle);
	int pass1DyCode = JcLockGetDynaCode(handle);
	printf("dynaPass1=\t%d\n", pass1DyCode);
	JcLockDelete(handle);
	//////////////////////////////////////////////////////////////////////////

	handle = JcLockNew();
	JcLockSetString(handle, JCI_ATMNO, "atm10455761");
	JcLockSetString(handle, JCI_LOCKNO, "lock14771509");
	JcLockSetString(handle, JCI_PSK, "PSKDEMO728");
	JcLockSetInt(handle,JCI_SEARCH_TIME_START,static_cast<int>(time(NULL)));
	JcLockSetInt(handle, JCI_CLOSECODE, initCloseCode);
	JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_CCB_DYPASS1);
	JCMATCH pass1Match =
		JcLockReverseVerifyDynaCode(handle, pass1DyCode);
	printf("current time=\t\t%d\n", static_cast<uint32_t>(time(NULL)));
	printf("pass1Match Time =\t%d\tValidity=%d\n",
		pass1Match.s_datetime, pass1Match.s_validity);

	JcLockDelete(handle);
}

void myJclmsTest20150306STM32Demo()
{
	//��������
	const char *atmno="atm10455761";
	const char *lockno="lock14771509";
	const char *psk="PSKDEMO728";
	//�˴��ǳ�ʼ������,���ɱ�����ͳ�ʼ������ķ�ʽ����,��ʼ�����벻��Ҫʱ���closecode���룬��������0
	int initCloseCode=embSrvGenDyCode(JCCMD_INIT_CLOSECODE,0,0,atmno,lockno,psk);

	//////////////////////////////////////////////////////////////////////////
	//��3����������(ATM��ţ����߱�ţ�PSK(Ҳ���Ǽ�����Ϣ��������֮�������)
	//��UTCʱ����������ʼ��������Ϊ���룬������������ɵ�һ��������Ϊ���
	time_t curTime=time(NULL);
	curTime=1425711000;	//20150309������ʱ�޸Ĺ̶�ʱ��ֵ���ڵ���
	int pass1DyCode=embSrvGenDyCode(JCCMD_CCB_DYPASS1,curTime,initCloseCode,atmno,lockno,psk);
	printf("��һ������=\t%d\n", pass1DyCode);
	//������֤��һ������
	printf("��֤��һ�����뿪ʼ\n");
	time_t pass1MatchTime=embSrvReverseDyCode(JCCMD_CCB_DYPASS1,pass1DyCode,initCloseCode, 
		//time(NULL),
		curTime,
		atmno,lockno,psk);
	printf("��֤��һ���������,ʱ����%u\n",static_cast<uint32_t>(pass1MatchTime));

	//////////////////////////////////////////////////////////////////////////
	//����������֤��,��һ��������Ϊ����Ҫ��,
	int VerifyDyCode=embSrvGenDyCode(JCCMD_CCB_LOCK_VERCODE,curTime,pass1DyCode,atmno,
		lockno,psk);
	printf("��֤��=\t%d\n", VerifyDyCode);
	//�����������֤��֤��
	printf("��֤��֤�뿪ʼ\n");
	time_t vercodeMatchTime=embSrvReverseDyCode(JCCMD_CCB_LOCK_VERCODE,VerifyDyCode,pass1DyCode, 
		//time(NULL),
		curTime,
		atmno,lockno,psk);
	printf("��֤��֤�����,ʱ����%u\n",static_cast<uint32_t>(vercodeMatchTime));

	//////////////////////////////////////////////////////////////////////////
	//������������ɵڶ������룬��֤����Ϊ����Ҫ��
	int pass2DyCode=embSrvGenDyCode(JCCMD_CCB_DYPASS2,curTime,VerifyDyCode,"atm10455761",
		"lock14771509","PSKDEMO728");
	printf("�ڶ�������=\t%d\n", pass2DyCode);
	//������֤�ڶ�������
	printf("��֤�ڶ������뿪ʼ\n");
	time_t pass2MatchTime=embSrvReverseDyCode(JCCMD_CCB_DYPASS2,pass2DyCode,VerifyDyCode,
		//time(NULL),
		curTime,
		atmno,lockno,psk);

	printf("��֤�ڶ����������,ʱ����%u\n",static_cast<uint32_t>(pass2MatchTime));

	//�����룬��3�����������͵�ǰʱ���Լ��ڶ���������Ϊ��������
	int curCloseCode=embSrvGenDyCode(JCCMD_CCB_CLOSECODE,curTime,pass2DyCode,atmno,lockno,psk);
	printf("������=\t%d\n", curCloseCode);
}




void test4CCB3DES_ECB_EDE2();
//�ѽ�����64������Ϣת��Ϊ64�����޷�������
ui64 myChar2Ui64(const char *inStr);

void myCCB3DESTest324();


void myCCB3DESTest324()
{
	printf("%016I64X\n",myChar2Ui64("23456789"));
	JC3DES_ERROR pchk1= myIsDESWeakKey("0123456789abcdef");
	char outEncDyCode[16*2+1];
	memset(outEncDyCode,0,16*2+1);
	const char *tdesKey=		//"0123456789ABCDEF"
		"1234567890123456"
		//"0000000000000000"
		//"AAAABBBBCCCCDDDD"
;	int dyCodeSrc=19780417;
	JC3DES_ERROR err= zwCCB3DESEncryptDyCode(tdesKey,dyCodeSrc,outEncDyCode);
	int dyCodeDec=0;
	zwCCB3DESDecryptDyCode(tdesKey,outEncDyCode,&dyCodeDec);
	printf("dyCodeSrc=%d\tdyCodeDec=%d\n",dyCodeSrc,dyCodeDec);

	if (JC3DES_OK==err)
	{
		printf("zwCCB3DESEncryptDyCode test result is %s\n",outEncDyCode);
	}
	else
	{
		printf("ERROR CODE OF zwCCB3DESEncryptDyCode is %d\n",err);
	}
}


void myECIESTest709ForArmTest()
{
	//���ɹ�Կ˽Կ�Բ���
	char pubKey[ZW_ECIES_PUBKEY_LEN];
	char priKey[ZW_ECIES_PRIKEY_LEN];
	memset(pubKey,0,ZW_ECIES_PUBKEY_LEN);
	memset(priKey,0,ZW_ECIES_PRIKEY_LEN);
	//���ɲ���ֻ��һ�Σ�����ǰ���Ѿ����ɹ��ˣ����Դ˴�����ע�͵������������ɵĽ��ֱ�Ӹ��ƽ���
	//��ʽʹ��ʱӦ���������ɹ�Կ˽Կ��֮�󱣴浽FLASH���õ�ʱȡ����ʹ��
	//zwGenKeyPair(pubKey,priKey);
	strcpy(pubKey,"BL07r0BBLHSyTfF/MF4Z/+C//fBuvm8yrwcw5SY85h4DRXrUuJ2rw8WW48l+kn9wi7Ss+3Q2dstJThtYS2I6F+I=");
	strcpy(priKey,"BthBk76cTXctaIP/PVOGHYGLVLB2W2PA+CwYcZeZess=");
	printf("pubkey=%s\nprikey=%s\n",pubKey,priKey);
	/////////////////////////////���ɼ�����Ϣ/////////////////////////////////////////////
	char ccbActiveInfo[ZW_ECIES_CRYPT_TOTALLEN];
	const char *ccbInput1="1234567890654321";
	const char *ccbInput2="1234567890654321";

	memset(ccbActiveInfo,0,ZW_ECIES_CRYPT_TOTALLEN);
	time_t nowTime=time(NULL);
	zwGenActiveInfo(pubKey,ccbInput1,ccbInput2,nowTime,ccbActiveInfo);
	printf("ccbActiveInfo=%s\nnowTime=\t%u\n",ccbActiveInfo,nowTime);

	/////////////////////////////���ܼ�����Ϣ/////////////////////////////////////////////
	char PSK[ZW_ECIES_HASH_LEN*2];
	memset(PSK,0,ZW_ECIES_HASH_LEN*2);
	time_t origTime=0;
	const char *panfeiTest1518="BNRW+I+aavhzpfHm2ZFLnLqYXYKmcSWZ3Xj1bQ5ejQAOBNVceXhcyfKwGKp01mEzBL11907NxlP98iCzkbu4CdI=.3D+2dOuRjAj2q9Z\/YEbOhIerOrc6+96U.qnJt5n\/8YV8X\/y6DPGPDwxaISzOYvVneMkm7g2+\/6PJAfDl\/FKVqakzFq6DcNQnjkC5iBXzv8gUwwBuYXyJlyx3ObpEwA0hMvQ31eXxKpjQ=";
	embGetPSK2(priKey,panfeiTest1518,PSK,&origTime);
	printf("PSK=\t%s \norigTime=\t%u\n",PSK,origTime);
}

void myWangJiHuExample20160830(void);


int main(int argc, char * argv[])
{	
	myWangJiHuExample20160830();
	//myCCB3DESTest324();
	//printf("\n\n\nmyJclmsTest20150306STM32Demo\n");
	//myJclmsTest20150306STM32Demo();

	//myECIESTest709ForArmTest();
	//test4CCB3DES_ECB_EDE2();

	//////////////////////////////////////////////////////////////////////////
	//myECIESTest305ForArm();
	//Sleep(2000);
	//myECIESTest305ForArm();
	
	//myECIESTest326ForArmTest1WM();
	//myECIESTest326ForArmTest1WM();

	//////////////////////////////////////////////////////////////////////////
	//myJclmsTest20150305();
	//printf("%s\n",zw3desTest311("0123456789ABCDEF").c_str());



	//test4CCB3DES_ECB_EDE2();
	//myECIES_KeyGenTest325();
	//EciesEncryptCCB1503("ECIESPUBKEY","ECIESPLAINTEXT",time(NULL));

	return 0;
}

void myWangJiHuExample20160830(void)
{
////////////////////////////////��ʼ�������ø������//////////////////////////////////////////
	//Ԥ�����úõ����ɵ�һ�ԷǶԳ���Կ����Base64����Ķ���������
	//�ù�Կ˽Կ��ʹ��zwGenKeyPair�������ɣ��˴��������ɺõ�ֵ��
	// ����ʹ�øú������ɹ�Կ˽Կ�ԣ�Ȼ��ѹ�Կ����0000���Ľ�����淵��
	// ��Բ���߼����㷨��Կ
	const char *pubkey="BFlfjkxoiRZFdjQKa/W1JWBwFx+FPyzcFGqXjnlVzMcvIAQyK3C1Ha+G2uGUM4nX5khPQP5AiPFiCyuH2WxZefg=";
	//��Բ���߼����㷨˽Կ
	const char *prikey="y+tgryY83ibv2RaQeb93a97+JX0/9cpWf4MrmUUtrzs=";
	cout<<"��Բ���߼����㷨��Կ="<<pubkey<<endl;
	cout<<"��Բ���߼����㷨˽Կ="<<prikey<<"��ֵ��Ҫ�ϸ��ܣ����ܴ�����������"<<endl;
	//char aaPubKey[128];
	//char aaPriKey[32];
	//zwGenKeyPair(aaPubKey,aaPriKey);
	//�˴���VH�������������ע����Կ���ĵ�ʵ�ʴ��룬�����������ӣ����ɵ�
	// ccbPSK������������������ڲ�����Ϊ�Ժ����ɸ��ֶ�̬��ĸ���Կ��
	const char *ccbFact1="A1B1C1D1A1B1C1D1";
	const char *ccbFact2="A2B2C2D2A2B2C2D2";
	cout<<"����Կ�������������ӷֱ���"<<ccbFact1<<" �� "<<ccbFact2<<endl;
	string ccbPSK=zwGenPSKFromCCB(ccbFact1,ccbFact2);
	cout<<"ccbPSK�� "<<ccbPSK<<"\n��ֵ��Ҫ�߶ȱ��ܲ��ܳ���������������ߵ�Ӳ��֮�⣬���ܰ������κα�����"<<endl;
	//ccbPSK���������������߲�ͬ�Ĺ�Կ���ܺ����ʽ��Ϊ������Ϣ���ڡ�����
	//���߼�����Ϣ�����ĵĽ���з��أ�
	// ���ĸ�������GMT�������Դ�1970���������ģ���Լ��һ��14��ͷ��10λ����
	// ���ĸ��������ڵ�ԭ���ǽ���Ҫ���ͬһ�����ڲ�ͬʱ�����ɵļ�����Ϣ����
	// ������ͬ����ֹ�طŹ�����������Щ��ͬ�ļ�����Ϣ���ܳ��������һ����
	string actInfo=embGenActInfo(pubkey,ccbFact1,ccbFact2,time(NULL));
	cout<<"������Ϣ��\t"<<actInfo<<endl;
	//��������actInfoͨ��0001���ķ������ߣ��������ڲ�ͨ��prikey���ܳ���ccbPSK
	string decedPsk= embDecActInfo(prikey,actInfo.c_str());
	cout<<"�������Լ���˽Կ���ܳ�������������������ļ�����Ϣ�е�PSK���£�"
		"���Լ�ȥ������Լ������GMT����\n"<<decedPsk<<endl;

	//���������ɶ�̬�����֤��̬��Ĳ���
	//������Ҫ�õ�ö������jc_cmd_type����ĸ���ֵ��C/C++��ö���ǵ�һ��Ԫ��Ϊ0
	// �ڶ���Ϊ1���Դ����ƣ�����JCCMD_INIT_CLOSECODE��ֵ��1������������
	// ���ո�ֵ����һ��ö�٣��Ա����ɶ��Ը���
	const char *myAtmNo="atmno830a1";
	const char *myLockNo="lockNo1019";
	//��һ�������μ�ö��jc_cmd_type��Ҳ����ֱ�Ӵ���1��ָ��Ҫ���ɳ�ʼ������
	//��ʼ�������������Ϊÿ����һ�����붼Ҫ��ǰһ�εı�������Ϊ����������
	// ���ʼ��һ�ο���ʱ�������ڿ����룬���Զ�����һ����ʼ������ĸ���
	// ���Գ�ʼ������ֻӦ����һ�����ߵ�һ�ο���ʱ����1�Σ����������������
	// ˫����������ͬ��ATM��ţ����߱�ţ��Լ�ʹ��ǰ��ĳ�ʼ�����轻��һ��
	// ��PSK������˫�����øú�����������ͬ�ĳ�ʼ�������������µĶ�̬������
	// ����
	// �ڶ�������SearchStartTime����ָ��ҪΪʲôʱ�����ɶ�̬�롣���еĳ���
	// һ�㶼�����������Ͼ��õģ����Դ˴�ֱ��ȡֵ��ǰʱ�䡣����Ҳ��������
	// ����ĳ��ʱ��Ķ�̬�룻
	// �����������Ǳ����룬�˴����ɳ�ʼ������ʱ��ֵ��Ч������0���ɡ��Ժ��һ
	// �����룬������֤�룬�ڶ������룬������ʱ�ı����룬��Щ��̬�����ɵ�
	//ʱ��ÿ�ζ�������һ������Ķ�̬�����������λ����
	// ��������������߸������ɳ�ʼ������
	int initCloseCode= embSrvCodeGen(JCCMD_INIT_CLOSECODE,time(NULL),0,
		myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"��ʼ��������\t"<<initCloseCode<<endl;
	//������������ɵ�һ������
	//��ע��˴����ɵ�һ�����룬��֮ͬ���������ڣ�����1�Ķ�̬�����Ͳ�ͬ������2
	//�Ķ�̬��Ŀ��ʱ�䲻ͬ(���ǵ����еĳ���һ�㶼������ʹ������Ŀ��ʱ��һ�㶼
	// ȡ���ǵ�ǰʱ�䣬�����������Կ��ǲ�ͬ��ʱ��),����3��д�˳�ʼ��̬��
	int passCode1=embSrvCodeGen(JCCMD_CCB_DYPASS1,time(NULL),initCloseCode,myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"��һ��������\t"<<passCode1<<endl;
	//������֤��һ�������Ƿ�Ϸ�
	int pass1SrcTime= embSrvCodeRev(JCCMD_CCB_DYPASS1,passCode1,initCloseCode,time(NULL),myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"��֤��һ�������Ӧ������ʱ�������£����Ϊ0������֤ʧ��.�����ֵӦ���ڵ�ǰʱ��֮ǰ���ǲ�����5���ӷ�Χ\t"<<pass1SrcTime<<endl;
	//����������֤��
	int verCode=embSrvCodeGen(JCCMD_CCB_LOCK_VERCODE,time(NULL),passCode1,myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"�������ɵ���֤�����£���ֵ��ͨ�������ͱ���������֤�뱨�Ĵ���VH\t"<<verCode<<endl;
	//��������������ɵڶ�������֮ǰ��֤���ߵ���֤���Ƿ�Ϸ�
	int verCodeSrcTime= embSrvCodeRev(JCCMD_CCB_LOCK_VERCODE,verCode,passCode1,time(NULL),myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"��֤������ʱ����\t"<<verCodeSrcTime<<endl;
	//��֤��Ϸ��Ļ���������������ɵڶ�������
	int passCode2=embSrvCodeGen(JCCMD_CCB_DYPASS2,time(NULL),verCode,myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"�ڶ���������\t"<<passCode2<<endl;
	//������֤�ڶ��������Ƿ�Ϸ�
	int pass2SrcTime= embSrvCodeRev(JCCMD_CCB_DYPASS2,passCode2,verCode,time(NULL),myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"�ڶ�����������ʱ����\t"<<pass2SrcTime<<endl;
	//��֤�ɹ��ڶ�������󣬿����ɹ���������Ϲ����Ժ��������ɱ�����
	int endCloseCode= embSrvCodeGen(JCCMD_CCB_CLOSECODE,time(NULL),passCode2,myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"��������\t"<<endCloseCode<<endl;
	//VH��֤������ĺϷ��ԣ�
	int encCloseCodeSrcTime= embSrvCodeRev(JCCMD_CCB_CLOSECODE,endCloseCode,passCode2,time(NULL),myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"����������ʱ����\t"<<encCloseCodeSrcTime<<endl;
	//����ÿ������֮�䶼������ۣ�������һ������Ķ�̬��ʱ�������ɺ���������һ����̬����Ϊ���룬��֤ʱҲ�����
}