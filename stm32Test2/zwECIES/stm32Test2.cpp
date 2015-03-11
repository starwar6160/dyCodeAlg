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
#include "tests.h"


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

void myECIESTest305();

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
	printf("current time=\t\t%d\n", time(NULL));
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
	printf("��֤��һ���������,ʱ����%u\n",pass1MatchTime);

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
	printf("��֤��֤�����,ʱ����%u\n",vercodeMatchTime);

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

	printf("��֤�ڶ����������,ʱ����%u\n",pass2MatchTime);

	//�����룬��3�����������͵�ǰʱ���Լ��ڶ���������Ϊ��������
	int curCloseCode=embSrvGenDyCode(JCCMD_CCB_CLOSECODE,curTime,pass2DyCode,atmno,lockno,psk);
	printf("������=\t%d\n", curCloseCode);
}

using std::string;
string zw3desTest311(const char *ccbKey)
{
	//8λ��̬��ת��Ϊ�ַ�����Ȼ���ַ���8�ֽ�ת��ΪHEX���Ա�����3DES��
	//64bit����Ҫ�󣬹������������㽨�е�Ҫ����Ա���ȷ�����ˣ�
	int ccbKeyLen=strlen(ccbKey);
	assert(16==ccbKeyLen);

	const int BUFLEN = 48;
	char buf[BUFLEN];
	memset(buf, 0, BUFLEN);
	char hexbuf[BUFLEN];
	memset(hexbuf, 0, BUFLEN);
	for (int i = 0; i < ccbKeyLen; i++) {
		unsigned char ch = ccbKey[i];
		sprintf(hexbuf + i * 2, "%02X", ch);
	}
	string retHexStr = hexbuf;
	return retHexStr;
}


int main(int argc, char * argv[])
{
	//myECIES_KeyGenTest123();
	//////////////////////////////////////////////////////////////////////////
	//myECIESTest305();

	//////////////////////////////////////////////////////////////////////////
	//myJclmsTest20150305();
	//myJclmsTest20150306STM32Demo();
	//printf("%s\n",zw3desTest311("0123456789ABCDEF").c_str());
	test4CCB3DES_ECB_EDE2();
	return 0;
}


