// stm32Test2.cpp : 定义控制台应用程序的入口点。
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
	//预先设置好的生成的一对非对称密钥，是Base64编码的二进制内容
	//pubkey= BFlfjkxoiRZFdjQKa/W1JWBwFx+FPyzcFGqXjnlVzMcvIAQyK3C1Ha+G2uGUM4nX5khPQP5AiPFiCyuH2WxZefg=
	//prikey= y+tgryY83ibv2RaQeb93a97+JX0/9cpWf4MrmUUtrzs=
	//加密结果实质上是用英文句点分隔的3个Base64编码的二进制内容，但是不必理解，原样透传即可
	//ECIES ENC Text= BMMXMJYun+G/Oz4i1LZYmNXR1UM9qTKVfNQPqdorUFCRLvBTE8+SMMoCC/OKAxflDafaosWqnLOA+nkcwvTV8iI=.4AF8XhKkuybS+BQ
	//On+M5BwgwScoCHmkr.0zqyC1eg+7HOhVcbadE7+FRlVZAscomIx9VIfXeHl64wdoDC0X3HJbjEQfIA+flD
	//ECIES DEC Text= C# Port Test plain text 20140722.1625

	//一般来说，生成密钥操作做一次就行了，以下的常量密钥对就是某一次生成的结果复制下来的
#ifdef _DEBUG126
	//首先用这一段程序生成公钥私钥对，然后保存在内存和FLASH里面，以后别处要用到的时候，就从内存或者FLASH里面取出来使用
	//注意一个ARM设备基本上运行一次这段程序就行了，一个公钥/私钥对存在于整个ARM设备的生命周期，除非重新初始化才会再次生成
	int hd = 0;
	hd = EciesGenKeyPair();
	const char *myPubKey=EciesGetPubKey(hd);
	const char *myPriKey=EciesGetPriKey(hd);
	//如果生成了密钥对，那么别忘了删除，释放内存
	EciesDelete(hd);
#endif // _DEBUG126
	//以下
	char pubkey[ZW_ECIES_PUBKEY_LEN];
	char prikey[ZW_ECIES_PRIKEY_LEN];
	memset(pubkey, 0, sizeof(pubkey));
	memset(prikey, 0, sizeof(prikey));
	//以下公钥/私钥对是前面EciesGenKeyPair生成，然后用EciesGetPubKey和EciesGetPriKey取得的，请保存在FLASH里面以备后用
	strcpy(pubkey,"BFlfjkxoiRZFdjQKa/W1JWBwFx+FPyzcFGqXjnlVzMcvIAQyK3C1Ha+G2uGUM4nX5khPQP5AiPFiCyuH2WxZefg=");
	strcpy(prikey,"y+tgryY83ibv2RaQeb93a97+JX0/9cpWf4MrmUUtrzs=");
	printf("pubkey=%s\nprikey=%s\n",pubkey,prikey);
	//////////////////////////////////////////////////////////////////////////
	//建行的两个用于生成PSK的输入因子，将其拼接在ccbInStr里面
	const char *ccbInput1="0123456789ABCDEF";
	const char *ccbInput2="01234ABCDEF56789";
	char ccbInStr[40];
	memset(ccbInStr,0,40);
	strcpy(ccbInStr,ccbInput1);
	strcat(ccbInStr,ccbInput2);
	//从ccbInStr生成PSK
	const char *ccbPSK=zwMergePsk(ccbInStr);
	printf("from CCB1 %s and CCB2 %s result \nccbPSK=\t%s\n",ccbInput1,ccbInput2,ccbPSK);
	char ccbActiveInfo[ZW_ECIES_CRYPT_TOTALLEN];
	memset(ccbActiveInfo, 0, sizeof(ccbActiveInfo));
	//从PSK和公钥生成激活信息ccbActiveInfo，然后激活信息就可以通过网络传输出去了
	time_t nowTime=time(NULL);
	printf("EciesEncryptCCB1503 set Origin ActInfo Time is %u\n",nowTime);
	strcpy(ccbActiveInfo, EciesEncryptCCB1503(pubkey, ccbPSK,nowTime));
	printf("ccbActiveInfo= %s\n",ccbActiveInfo);
	//用私钥解开激活信息，获得PSK
	char dePSK[ZW_ECIES_CRYPT_TOTALLEN];
	memset(dePSK,0,ZW_ECIES_CRYPT_TOTALLEN);
	time_t origTime=0;
	strcpy(dePSK,EciesDecryptCCB1503(prikey, ccbActiveInfo,&origTime));	
	printf("EciesDecryptCCB1503 get Origin ActInfo Time is %u\n",origTime);
	printf("ccbPSK=\t%s\n",dePSK);
}

void myECIESTest305ForArm()
{
	/////////////////////////////生成激活信息/////////////////////////////////////////////
	char ccbActiveInfo[ZW_ECIES_CRYPT_TOTALLEN];
	//const char *ccbInput1="0123456789ABCDEF";
	//const char *ccbInput2="01234ABCDEF56789";
	const char *ccbInput1="1234567890abcdef";
	const char *ccbInput2="1234567890abcdef";
	
	//生成公钥私钥对操作
	char pubKey[ZW_ECIES_PUBKEY_LEN];
	char priKey[ZW_ECIES_PRIKEY_LEN];
	memset(pubKey,0,ZW_ECIES_PUBKEY_LEN);
	memset(priKey,0,ZW_ECIES_PRIKEY_LEN);
	//生成操作只用一次，由于前面已经生成过了，所以此处改行注释掉，后面用生成的结果直接复制进来
	//正式使用时应该是先生成公钥私钥对之后保存到FLASH，用到时取出来使用
	//zwGenKeyPair(pubKey,priKey);
	strcpy(pubKey,"BFlfjkxoiRZFdjQKa/W1JWBwFx+FPyzcFGqXjnlVzMcvIAQyK3C1Ha+G2uGUM4nX5khPQP5AiPFiCyuH2WxZefg=");
	strcpy(priKey,"y+tgryY83ibv2RaQeb93a97+JX0/9cpWf4MrmUUtrzs=");
	printf("pubkey=%s\nprikey=%s\n",pubKey,priKey);

	memset(ccbActiveInfo,0,ZW_ECIES_CRYPT_TOTALLEN);
	time_t nowTime=1400111222;
	zwGenActiveInfo(pubKey,ccbInput1,ccbInput2,nowTime,ccbActiveInfo);
	printf("ccbActiveInfo=%s\nnowTime=\t%u\n",ccbActiveInfo,nowTime);
	/////////////////////////////解密激活信息/////////////////////////////////////////////
	char PSK[ZW_ECIES_HASH_LEN*2];
	memset(PSK,0,ZW_ECIES_HASH_LEN*2);
	time_t origTime=0;
	embGetPSK2(priKey,ccbActiveInfo,PSK,&origTime);
	printf("PSK=\t%s \norigTime=\t%u\n",PSK,origTime);
}

void myECIESTest326ForArmTest1WM()
{
	//生成公钥私钥对操作
	char pubKey[ZW_ECIES_PUBKEY_LEN];
	char priKey[ZW_ECIES_PRIKEY_LEN];
	memset(pubKey,0,ZW_ECIES_PUBKEY_LEN);
	memset(priKey,0,ZW_ECIES_PRIKEY_LEN);
	//生成操作只用一次，由于前面已经生成过了，所以此处改行注释掉，后面用生成的结果直接复制进来
	//正式使用时应该是先生成公钥私钥对之后保存到FLASH，用到时取出来使用
	//zwGenKeyPair(pubKey,priKey);
	strcpy(pubKey,"BCsvfsK4WGcvECbJGq69ZWS20B+LRv+n+FqQt79esR5DLM2TZny0atXngTUXa7kg5cEfAG1mjueu95L3buAW5xg=");
	strcpy(priKey,"O5AA9G0HWtw5cW6We7LER2A6Fkli+Pgy3mZ7or+q8/k=");
	printf("pubkey=%s\nprikey=%s\n",pubKey,priKey);
	/////////////////////////////生成激活信息/////////////////////////////////////////////
	char ccbActiveInfo[ZW_ECIES_CRYPT_TOTALLEN];
	//const char *ccbInput1="0123456789ABCDEF";
	//const char *ccbInput2="01234ABCDEF56789";
	const char *ccbInput1="1234567890abcdef";
	const char *ccbInput2="1234567890abcdef";

	memset(ccbActiveInfo,0,ZW_ECIES_CRYPT_TOTALLEN);
	time_t nowTime=time(NULL);
	zwGenActiveInfo(pubKey,ccbInput1,ccbInput2,nowTime,ccbActiveInfo);
	printf("ccbActiveInfo=%s\nnowTime=\t%u\n",ccbActiveInfo,nowTime);
	/////////////////////////////解密激活信息/////////////////////////////////////////////
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
	//检查初始闭锁码是否在正常范围内
	printf("initCloseCode=\t%d Expect 38149728\n", initCloseCode);
#endif // _DEBUG_INITCOLSECODE306
	//此处期待值已经改为固定依赖1400M秒的时间值，应该不会再变了。
	//20141113.1751根据前两天开会决定做的修改。周伟
	//这里是一个自检测试，如果失败，就说明有比较大的问题了，比如类似发生过的
	//ARM编译器优化级别问题导致的生成错误的二进制代码等等
	//dynaPass1
	//注意现在合法的时间值应该是1.4G以上了，注意位数。20140721.1709 

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
	//基本条件
	const char *atmno="atm10455761";
	const char *lockno="lock14771509";
	const char *psk="PSKDEMO728";
	//此处是初始闭锁码,生成闭锁码和初始闭锁码的方式类似,初始闭锁码不需要时间和closecode输入，所以输入0
	int initCloseCode=embSrvGenDyCode(JCCMD_INIT_CLOSECODE,0,0,atmno,lockno,psk);

	//////////////////////////////////////////////////////////////////////////
	//从3个基本条件(ATM编号，锁具编号，PSK(也就是激活信息经过解密之后的内容)
	//和UTC时间秒数，初始闭锁码作为输入，密码服务器生成第一开锁码作为输出
	time_t curTime=time(NULL);
	curTime=1425711000;	//20150309调试临时修改固定时间值便于调试
	int pass1DyCode=embSrvGenDyCode(JCCMD_CCB_DYPASS1,curTime,initCloseCode,atmno,lockno,psk);
	printf("第一开锁码=\t%d\n", pass1DyCode);
	//锁具验证第一开锁码
	printf("验证第一开锁码开始\n");
	time_t pass1MatchTime=embSrvReverseDyCode(JCCMD_CCB_DYPASS1,pass1DyCode,initCloseCode, 
		//time(NULL),
		curTime,
		atmno,lockno,psk);
	printf("验证第一开锁码完毕,时间是%u\n",static_cast<uint32_t>(pass1MatchTime));

	//////////////////////////////////////////////////////////////////////////
	//锁具生成验证码,第一开锁码作为生成要素,
	int VerifyDyCode=embSrvGenDyCode(JCCMD_CCB_LOCK_VERCODE,curTime,pass1DyCode,atmno,
		lockno,psk);
	printf("验证码=\t%d\n", VerifyDyCode);
	//密码服务器验证验证码
	printf("验证验证码开始\n");
	time_t vercodeMatchTime=embSrvReverseDyCode(JCCMD_CCB_LOCK_VERCODE,VerifyDyCode,pass1DyCode, 
		//time(NULL),
		curTime,
		atmno,lockno,psk);
	printf("验证验证码结束,时间是%u\n",static_cast<uint32_t>(vercodeMatchTime));

	//////////////////////////////////////////////////////////////////////////
	//密码服务器生成第二开锁码，验证码作为生成要素
	int pass2DyCode=embSrvGenDyCode(JCCMD_CCB_DYPASS2,curTime,VerifyDyCode,"atm10455761",
		"lock14771509","PSKDEMO728");
	printf("第二开锁码=\t%d\n", pass2DyCode);
	//锁具验证第二开锁码
	printf("验证第二开锁码开始\n");
	time_t pass2MatchTime=embSrvReverseDyCode(JCCMD_CCB_DYPASS2,pass2DyCode,VerifyDyCode,
		//time(NULL),
		curTime,
		atmno,lockno,psk);

	printf("验证第二开锁码结束,时间是%u\n",static_cast<uint32_t>(pass2MatchTime));

	//闭锁码，由3个基本条件和当前时间以及第二开锁码作为条件生成
	int curCloseCode=embSrvGenDyCode(JCCMD_CCB_CLOSECODE,curTime,pass2DyCode,atmno,lockno,psk);
	printf("闭锁码=\t%d\n", curCloseCode);
}




void test4CCB3DES_ECB_EDE2();
//把进来的64比特信息转换为64比特无符号整型
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
	//生成公钥私钥对操作
	char pubKey[ZW_ECIES_PUBKEY_LEN];
	char priKey[ZW_ECIES_PRIKEY_LEN];
	memset(pubKey,0,ZW_ECIES_PUBKEY_LEN);
	memset(priKey,0,ZW_ECIES_PRIKEY_LEN);
	//生成操作只用一次，由于前面已经生成过了，所以此处改行注释掉，后面用生成的结果直接复制进来
	//正式使用时应该是先生成公钥私钥对之后保存到FLASH，用到时取出来使用
	//zwGenKeyPair(pubKey,priKey);
	strcpy(pubKey,"BL07r0BBLHSyTfF/MF4Z/+C//fBuvm8yrwcw5SY85h4DRXrUuJ2rw8WW48l+kn9wi7Ss+3Q2dstJThtYS2I6F+I=");
	strcpy(priKey,"BthBk76cTXctaIP/PVOGHYGLVLB2W2PA+CwYcZeZess=");
	printf("pubkey=%s\nprikey=%s\n",pubKey,priKey);
	/////////////////////////////生成激活信息/////////////////////////////////////////////
	char ccbActiveInfo[ZW_ECIES_CRYPT_TOTALLEN];
	const char *ccbInput1="1234567890654321";
	const char *ccbInput2="1234567890654321";

	memset(ccbActiveInfo,0,ZW_ECIES_CRYPT_TOTALLEN);
	time_t nowTime=time(NULL);
	zwGenActiveInfo(pubKey,ccbInput1,ccbInput2,nowTime,ccbActiveInfo);
	printf("ccbActiveInfo=%s\nnowTime=\t%u\n",ccbActiveInfo,nowTime);

	/////////////////////////////解密激活信息/////////////////////////////////////////////
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
////////////////////////////////初始化，设置各方面的//////////////////////////////////////////
	//预先设置好的生成的一对非对称密钥，是Base64编码的二进制内容
	//该公钥私钥对使用zwGenKeyPair函数生成，此处就用生成好的值；
	// 锁具使用该函数生成公钥私钥对，然后把公钥放在0000报文结果里面返回
	// 椭圆曲线加密算法公钥
	const char *pubkey="BFlfjkxoiRZFdjQKa/W1JWBwFx+FPyzcFGqXjnlVzMcvIAQyK3C1Ha+G2uGUM4nX5khPQP5AiPFiCyuH2WxZefg=";
	//椭圆曲线加密算法私钥
	const char *prikey="y+tgryY83ibv2RaQeb93a97+JX0/9cpWf4MrmUUtrzs=";
	cout<<"椭圆曲线加密算法公钥="<<pubkey<<endl;
	cout<<"椭圆曲线加密算法私钥="<<prikey<<"该值需要严格保密，不能传出锁具以外"<<endl;
	//char aaPubKey[128];
	//char aaPriKey[32];
	//zwGenKeyPair(aaPubKey,aaPriKey);
	//此处是VH向密码服务器灌注根密钥报文的实际代码，两个输入因子，生成的
	// ccbPSK被保存在密码服务器内部，作为以后生成各种动态码的根密钥；
	const char *ccbFact1="A1B1C1D1A1B1C1D1";
	const char *ccbFact2="A2B2C2D2A2B2C2D2";
	cout<<"根密钥的两个输入因子分别是"<<ccbFact1<<" 和 "<<ccbFact2<<endl;
	string ccbPSK=zwGenPSKFromCCB(ccbFact1,ccbFact2);
	cout<<"ccbPSK是 "<<ccbPSK<<"\n该值需要高度保密不能出密码服务器和锁具的硬件之外，不能包括在任何报文中"<<endl;
	//ccbPSK接下来被各个锁具不同的公钥加密后的形式成为激活信息，在“请求
	//锁具激活信息”报文的结果中返回；
	// 第四个参数是GMT秒数，自从1970年算起来的，大约是一个14开头的10位整数
	// 第四个参数存在的原因是建行要求给同一把锁在不同时间生成的激活信息内容
	// 各不相同，防止重放攻击。但是这些不同的激活信息解密出来结果是一样的
	string actInfo=embGenActInfo(pubkey,ccbFact1,ccbFact2,time(NULL));
	cout<<"激活信息是\t"<<actInfo<<endl;
	//接下来，actInfo通过0001报文发给锁具，锁具在内部通过prikey解密出来ccbPSK
	string decedPsk= embDecActInfo(prikey,actInfo.c_str());
	cout<<"锁具用自己的私钥解密出来的来自密码服务器的激活信息中的PSK如下，"
		"请自己去掉句号以及后面的GMT秒数\n"<<decedPsk<<endl;

	//以下是生成动态码和验证动态码的部分
	//其中需要用到枚举类型jc_cmd_type里面的各个值，C/C++的枚举是第一个元素为0
	// 第二个为1，以此类推，所以JCCMD_INIT_CLOSECODE的值是1，其他语言请
	// 参照该值定义一个枚举，以便代码可读性更高
	const char *myAtmNo="atmno830a1";
	const char *myLockNo="lockNo1019";
	//第一个参数参见枚举jc_cmd_type，也可以直接传入1，指明要生成初始闭锁码
	//初始闭锁码存在是因为每个第一开锁码都要求前一次的闭锁码作为因素来生成
	// 而最开始第一次开锁时还不存在开锁码，所以定义了一个初始闭锁码的概念
	// 所以初始闭锁码只应该在一个锁具第一次开锁时生成1次；密码服务器和锁具
	// 双方都持有相同的ATM编号，锁具编号，以及使用前面的初始化步骤交换一致
	// 的PSK，所以双方都用该函数生成了相同的初始闭锁码用于余下的动态码生成
	// 步骤
	// 第二个参数SearchStartTime，是指明要为什么时间生成动态码。建行的场景
	// 一般都是现生成马上就用的，所以此处直接取值当前时间。我们也可以生成
	// 将来某个时间的动态码；
	// 第三个参数是闭锁码，此处生成初始闭锁码时该值无效，传入0即可。以后第一
	// 开锁码，锁具验证码，第二开锁码，最后关锁时的闭锁码，这些动态码生成的
	//时候，每次都传入上一个步骤的动态码在这个参数位置上
	// 密码服务器和锁具各自生成初始闭锁码
	int initCloseCode= embSrvCodeGen(JCCMD_INIT_CLOSECODE,time(NULL),0,
		myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"初始闭锁码是\t"<<initCloseCode<<endl;
	//密码服务器生成第一开锁码
	//请注意此处生成第一开锁码，不同之处仅仅在于，参数1的动态码类型不同，参数2
	//的动态码目标时间不同(考虑到建行的场景一般都是马上使用所以目标时间一般都
	// 取的是当前时间，其他场景可以考虑不同的时间),参数3填写了初始动态码
	int passCode1=embSrvCodeGen(JCCMD_CCB_DYPASS1,time(NULL),initCloseCode,myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"第一开锁码是\t"<<passCode1<<endl;
	//锁具验证第一开锁码是否合法
	int pass1SrcTime= embSrvCodeRev(JCCMD_CCB_DYPASS1,passCode1,initCloseCode,time(NULL),myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"验证第一开锁码对应的生成时间结果如下，如果为0就是验证失败.此外该值应该在当前时间之前但是不超过5分钟范围\t"<<pass1SrcTime<<endl;
	//锁具生成验证码
	int verCode=embSrvCodeGen(JCCMD_CCB_LOCK_VERCODE,time(NULL),passCode1,myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"锁具生成的验证码如下，该值会通过主动和被动两条验证码报文传给VH\t"<<verCode<<endl;
	//密码服务器在生成第二开锁码之前验证锁具的验证码是否合法
	int verCodeSrcTime= embSrvCodeRev(JCCMD_CCB_LOCK_VERCODE,verCode,passCode1,time(NULL),myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"验证码生成时间是\t"<<verCodeSrcTime<<endl;
	//验证码合法的话，密码服务器生成第二开锁码
	int passCode2=embSrvCodeGen(JCCMD_CCB_DYPASS2,time(NULL),verCode,myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"第二开锁码是\t"<<passCode2<<endl;
	//锁具验证第二开锁码是否合法
	int pass2SrcTime= embSrvCodeRev(JCCMD_CCB_DYPASS2,passCode2,verCode,time(NULL),myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"第二开锁码生成时间是\t"<<pass2SrcTime<<endl;
	//验证成功第二开锁码后，开锁成功，操作完毕关锁以后锁具生成闭锁码
	int endCloseCode= embSrvCodeGen(JCCMD_CCB_CLOSECODE,time(NULL),passCode2,myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"闭锁码是\t"<<endCloseCode<<endl;
	//VH验证闭锁码的合法性：
	int encCloseCodeSrcTime= embSrvCodeRev(JCCMD_CCB_CLOSECODE,endCloseCode,passCode2,time(NULL),myAtmNo,myLockNo,decedPsk.c_str());
	cout<<"闭锁码生成时间是\t"<<encCloseCodeSrcTime<<endl;
	//以上每个步骤之间都环环相扣，生成下一个步骤的动态码时，在生成函数中有上一个动态码作为输入，验证时也是如此
}
