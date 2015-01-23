// stm32Test2.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include <iostream>
#include <string>
using std::cout;
using std::endl;
using std::string;


#include "zwEcies529.h"

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
	//int hd = 0;
	//hd = EciesGenKeyPair();
	//EXPECT_NE(hd, 0);
	char pubkey[ZW_ECIES_PUBKEY_LEN];
	char prikey[ZW_ECIES_PRIKEY_LEN];
	memset(pubkey, 0, sizeof(pubkey));
	memset(prikey, 0, sizeof(prikey));
	//strcpy(pubkey, EciesGetPubKey(hd));
	//strcpy(prikey, EciesGetPriKey(hd));
	strcpy(pubkey,"BFlfjkxoiRZFdjQKa/W1JWBwFx+FPyzcFGqXjnlVzMcvIAQyK3C1Ha+G2uGUM4nX5khPQP5AiPFiCyuH2WxZefg=");
	strcpy(prikey,"y+tgryY83ibv2RaQeb93a97+JX0/9cpWf4MrmUUtrzs=");
	//EXPECT_GT(strlen(pubkey), 0);
	//EXPECT_GT(strlen(prikey), 0);
	cout << "pubkey=\t" << pubkey << endl;
	cout << "prikey=\t" << prikey << endl;
	//////////////////////////////////////////////////////////////////////////
	const char *csPlainText =
		"C# Port Test plain text 20140722.1625";
	char crypt[ZW_ECIES_CRYPT_TOTALLEN];
	memset(crypt, 0, sizeof(crypt));
	strcpy(crypt, EciesEncrypt(pubkey, csPlainText));
	cout<<"ECIES ENC Text= "<<crypt<<endl;
	//strcpy(crypt2, EciesEncrypt(pubkey, csPlainText));
	//EXPECT_GT(strlen(crypt), 0);
	//EXPECT_NE(0, memcmp(crypt, crypt2, ZW_ECIES_CRYPT_TOTALLEN));
	string crStr = EciesDecrypt(prikey, crypt);
	cout<<"ECIES DEC Text= "<<crStr<<endl;
	//EXPECT_GT(strlen(outPlain), 0);
	//�����������Կ�ԣ���ô������ɾ�����ͷ��ڴ�
	//EciesDelete(hd);
}

int main(int argc, char * argv[])
{
	myECIES_KeyGenTest123();
	return 0;
}

