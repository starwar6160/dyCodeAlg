// stm32Test2.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "zwEcies529.h"
#include <stdio.h>
#include <memory.h>
#include <string.h>


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

int main(int argc, char * argv[])
{
	myECIES_KeyGenTest123();
	return 0;
}

