#include "stdafx.h"
#include "jclmsCCB2014.h"
#include "zwEcies529.h"
#include "..\\YinBao15\YinBao15.h"

//#define _DEBUG_ECIES_NORMAL_TEST1117
//#define _DEBUG_ECIES_BADINPUT_TEST1117
//#define _DEBUG_ECIES_CSTEST1117


namespace CcbV11Test722Ecies {
	const int ZWMEGA = 1000 * 1000;
	const char *ts100 = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	    "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
	const char *g_invalid_testkey = "myInvalidPubkey";
	const char *g_invalid_prikey = "myInvalidPrikey";

#ifdef _DEBUG722
	int Foo(int a, int b) {
		if (a == 0 || b == 0) {
			throw "don't do that";
		}
		int c = a % b;
		if (c == 0)
			return b;
		return Foo(b, c);
	}

	TEST(FooTest, HandleNoneZeroInput) {
		EXPECT_EQ(2, Foo(4, 10));
		EXPECT_EQ(6, Foo(30, 18));
	}
#endif // _DEBUG722

	class ECIES_Test:public testing::Test {
		// Some expensive resource shared by all tests.
		//      static T* shared_resource_;
	      public:
		//注意要使得一个测试集合中的前后相关的各个测试共用变量
		//就需要设置变量为static才可以在多个测试中保留值
		//不然就会在每个测试新建一个新的类实例，变量被重新初始化，中间值不保留
		static char s_priKey[ZW_ECIES_PRIKEY_LEN];
		static char s_pubKey[ZW_ECIES_PUBKEY_LEN];

		static char s_syncKey[ZW_ECIES_ENCSYNCKEY_LEN];
		static char s_hash[ZW_ECIES_HASH_LEN];
		static char s_crypt[ZW_ECIES_MESSAGE_MAXLEN];
		//为了验证是否内存中同一个ECIES对象对于不同的明文确实加密出来不同的密文
		static char s_syncKey2[ZW_ECIES_ENCSYNCKEY_LEN];
		static char s_hash2[ZW_ECIES_HASH_LEN];
		static char s_crypt2[ZW_ECIES_MESSAGE_MAXLEN];

		static char *s_PlainText;

	      protected:
		static void SetUpTestCase() {
			//shared_resource_ = new ;              
		} static void TearDownTestCase() {
			//delete shared_resource_;
			//shared_resource_ = NULL;
		}
	};
	char ECIES_Test::s_priKey[ZW_ECIES_PRIKEY_LEN];
	char ECIES_Test::s_pubKey[ZW_ECIES_PUBKEY_LEN];

	char ECIES_Test::s_syncKey[ZW_ECIES_ENCSYNCKEY_LEN];
	char ECIES_Test::s_hash[ZW_ECIES_HASH_LEN];
	char ECIES_Test::s_crypt[ZW_ECIES_MESSAGE_MAXLEN];
//为了验证是否内存中同一个ECIES对象对于不同的明文确实加密出来不同的密文
	char ECIES_Test::s_syncKey2[ZW_ECIES_ENCSYNCKEY_LEN];
	char ECIES_Test::s_hash2[ZW_ECIES_HASH_LEN];
	char ECIES_Test::s_crypt2[ZW_ECIES_MESSAGE_MAXLEN];

	char *ECIES_Test::s_PlainText;

#ifdef _DEBUG_ECIES_NORMAL_TEST1117
	TEST_F(ECIES_Test, NormalKeyPairGen) {
		//只有明文是这一个特定值时，输出才会不随机化，便于单元测试；
		s_PlainText = "zhouweiPlaintext20140722.1534Test";
		memset(s_priKey, 0, sizeof(s_priKey));
		memset(s_pubKey, 0, sizeof(s_pubKey));

		EXPECT_GT(ZW_ECIES_PUBKEY_LEN, 0);
		EXPECT_LT(ZW_ECIES_PUBKEY_LEN, 100);
		int keygenResult =
		    zwEciesKeyPairGen("", s_priKey, ZW_ECIES_PRIKEY_LEN,
				      s_pubKey, ZW_ECIES_PUBKEY_LEN);
		EXPECT_EQ(keygenResult, ECIES_SUCCESS);
		EXPECT_GT(strlen(s_priKey), 0);
		EXPECT_GT(strlen(s_pubKey), 0);
		EXPECT_EQ(0,strcmp(s_priKey,"7CxIpo/gyn7eY8UvZteTu8ntDjtowtCaJz8cN/g28WI="));
		EXPECT_EQ(0,strcmp(s_pubKey,"BGN5aG7J5MLBFCiMQhaHJUI54SOVEO+Amti+cYmh17wgiJm+dnUq/C2p5daHrCmc3XxbVeVQWNEOGXDoHajwcNU="));
#ifdef _DEBUG
		cout << "s_priKey=\t" << s_priKey << endl;
		cout << "s_pubKey=\t" << s_pubKey << endl;
#endif // _DEBUG
	}

	TEST_F(ECIES_Test, NormalEnc) {
		memset(s_syncKey, 0, sizeof(s_syncKey));
		memset(s_hash, 0, sizeof(s_hash));
		memset(s_crypt, 0, sizeof(s_crypt));
		EXPECT_GT(strlen(s_priKey), 0);
		EXPECT_GT(strlen(s_pubKey), 0);
		int eciesEncRet =
		    zwEciesEncrypt(s_pubKey, s_PlainText, s_syncKey,
				   sizeof(s_syncKey),
				   s_hash, sizeof(s_hash), s_crypt,
				   sizeof(s_crypt));
		EXPECT_EQ(eciesEncRet, ECIES_SUCCESS);
		EXPECT_GT(strlen(s_syncKey), 0);
		EXPECT_GT(strlen(s_hash), 0);
		EXPECT_GT(strlen(s_crypt), 0);
		EXPECT_EQ(0,strcmp(s_syncKey,"BANpS+0YV6/uBVeoxteXL8BGktEOxdxr7zgO4B1F3XmBllXvEVxl4cXnM7dDdhwTSkHcOD8jqzjRKl0nkrC7ISY="));
		EXPECT_EQ(0,strcmp(s_hash,"LGyzsQJ0qRAGYOCltSVlh4bFfqUxM+88"));
		EXPECT_EQ(0,strcmp(s_crypt,"1g/k87w4K7e1MDIpwjATpDvGxC4UAqZXUiaxteLz23RhDH/lfUR5kk3Zbno4FNFs"));

//试试看同一个对象两次加密不同的明文，结果是否不同
		string myPlainText2 = s_PlainText;
		myPlainText2 = myPlainText2 + "aaa";
		zwEciesEncrypt(s_pubKey, myPlainText2.c_str(), s_syncKey2,
			       sizeof(s_syncKey2), s_hash2, sizeof(s_hash2),
			       s_crypt2, sizeof(s_crypt2));
		EXPECT_NE(s_syncKey, s_syncKey2);
		EXPECT_NE(s_hash, s_hash2);
		EXPECT_NE(s_crypt, s_crypt2);
#ifdef _DEBUG
		cout << "syncKey=\t" << s_syncKey << endl;
		cout << "s_hash=\t" << s_hash << endl;
		cout << "s_crypt=\t" << s_crypt << endl;
		cout << "syncKey2=\t" << s_syncKey2 << endl;
		cout << "s_hash2=\t" << s_hash2 << endl;
		cout << "s_crypt2=\t" << s_crypt2 << endl;

#endif // _DEBUG

	}

	TEST_F(ECIES_Test, NormalDec) {
		EXPECT_GT(strlen(s_syncKey), 0);
		EXPECT_GT(strlen(s_hash), 0);
		EXPECT_GT(strlen(s_crypt), 0);
		char plainOut[ZW_ECIES_MESSAGE_MAXLEN];
		memset(plainOut, 0, sizeof(plainOut));
		int eciesEncRet =
		    zwEciesDecrypt(s_priKey, plainOut, sizeof(plainOut),
				   s_syncKey, s_hash, s_crypt);
		EXPECT_EQ(eciesEncRet, ECIES_SUCCESS);
		EXPECT_GT(strlen(plainOut), 0);
		EXPECT_EQ(0,strcmp(plainOut,s_PlainText));
#ifdef _DEBUG
		cout << "plainOut=\t" << plainOut << endl;
#endif // _DEBUG
	}

	TEST_F(ECIES_Test, SM3_StandTestVector) {
		EXPECT_EQ(0,zwSM3StandardTestVector());
	}
#endif // _DEBUG_ECIES_NORMAL_TEST1117



#ifdef _DEBUG_ECIES_BADINPUT_TEST1117
	TEST_F(ECIES_Test, NormalKeyPairGen_BadInput) {
		int keygenResult = ECIES_SUCCESS;
		keygenResult = zwEciesKeyPairGen("aaa",
						 NULL, ZW_ECIES_PRIKEY_LEN,
						 s_pubKey, ZW_ECIES_PUBKEY_LEN);
		EXPECT_NE(keygenResult, ECIES_SUCCESS);
		keygenResult = zwEciesKeyPairGen("aaa",
						 s_priKey, 0, s_pubKey,
						 ZW_ECIES_PUBKEY_LEN);
		EXPECT_NE(keygenResult, ECIES_SUCCESS);
		keygenResult = zwEciesKeyPairGen("aaa",
						 s_priKey, ZW_ECIES_PRIKEY_LEN,
						 NULL, ZW_ECIES_PUBKEY_LEN);
		EXPECT_NE(keygenResult, ECIES_SUCCESS);
		keygenResult = zwEciesKeyPairGen("aaa",
						 s_priKey, ZW_ECIES_PRIKEY_LEN,
						 s_pubKey, 0);
		EXPECT_NE(keygenResult, ECIES_SUCCESS);
	}

	TEST_F(ECIES_Test, NormalEnc_BadInput) {
		memset(s_syncKey, 0, sizeof(s_syncKey));
		memset(s_hash, 0, sizeof(s_hash));
		memset(s_crypt, 0, sizeof(s_crypt));
		int eciesEncRet = ECIES_SUCCESS;
		eciesEncRet =
		    zwEciesEncrypt(NULL, s_PlainText, s_syncKey,
				   sizeof(s_syncKey), s_hash, sizeof(s_hash),
				   s_crypt, sizeof(s_crypt));
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
		eciesEncRet =
		    zwEciesEncrypt(s_pubKey, NULL, s_syncKey, sizeof(s_syncKey),
				   s_hash, sizeof(s_hash), s_crypt,
				   sizeof(s_crypt));
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
		eciesEncRet =
		    zwEciesEncrypt(s_pubKey, s_PlainText, NULL,
				   sizeof(s_syncKey), s_hash, sizeof(s_hash),
				   s_crypt, sizeof(s_crypt));
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
		eciesEncRet =
		    zwEciesEncrypt(s_pubKey, s_PlainText, s_syncKey, 0, s_hash,
				   sizeof(s_hash), s_crypt, sizeof(s_crypt));
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
		eciesEncRet =
		    zwEciesEncrypt(s_pubKey, s_PlainText, s_syncKey,
				   sizeof(s_syncKey), NULL, sizeof(s_hash),
				   s_crypt, sizeof(s_crypt));
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
		eciesEncRet =
		    zwEciesEncrypt(s_pubKey, s_PlainText, s_syncKey,
				   sizeof(s_syncKey), s_hash, 0, s_crypt,
				   sizeof(s_crypt));
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
		eciesEncRet =
		    zwEciesEncrypt(s_pubKey, s_PlainText, s_syncKey,
				   sizeof(s_syncKey), s_hash, sizeof(s_hash),
				   NULL, sizeof(s_crypt));
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
		eciesEncRet =
		    zwEciesEncrypt(s_pubKey, s_PlainText, s_syncKey,
				   sizeof(s_syncKey), s_hash, sizeof(s_hash),
				   s_crypt, 0);
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
	}

	TEST_F(ECIES_Test, NormalEnc_TooLongInput) {
		memset(s_syncKey, 0, sizeof(s_syncKey));
		memset(s_hash, 0, sizeof(s_hash));
		memset(s_crypt, 0, sizeof(s_crypt));
		int eciesEncRet = ECIES_SUCCESS;
		//超长公钥
		eciesEncRet =
		    zwEciesEncrypt(ts100, s_PlainText, s_syncKey,
				   sizeof(s_syncKey), s_hash, sizeof(s_hash),
				   s_crypt, sizeof(s_crypt));
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
		//不超长但是内容非法公钥
		eciesEncRet =
		    zwEciesEncrypt(g_invalid_testkey, s_PlainText, s_syncKey,
				   sizeof(s_syncKey), s_hash, sizeof(s_hash),
				   s_crypt, sizeof(s_crypt));
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
		//超长明文
		eciesEncRet =
		    zwEciesEncrypt(g_invalid_testkey, ts100, s_syncKey,
				   sizeof(s_syncKey), s_hash, sizeof(s_hash),
				   s_crypt, sizeof(s_crypt));
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
	}

	TEST_F(ECIES_Test, NormalDec_BadInput) {
		char plainOut[ZW_ECIES_MESSAGE_MAXLEN];
		memset(plainOut, 0, sizeof(plainOut));
		int eciesEncRet = ECIES_SUCCESS;
		eciesEncRet = zwEciesDecrypt(NULL, plainOut, sizeof(plainOut),
					     s_syncKey, s_hash, s_crypt);
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
		eciesEncRet = zwEciesDecrypt(s_priKey, NULL, sizeof(plainOut),
					     s_syncKey, s_hash, s_crypt);
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
		eciesEncRet = zwEciesDecrypt(s_priKey, plainOut, 0,
					     s_syncKey, s_hash, s_crypt);
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
		eciesEncRet =
		    zwEciesDecrypt(s_priKey, plainOut, sizeof(plainOut), NULL,
				   s_hash, s_crypt);
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
		eciesEncRet =
		    zwEciesDecrypt(s_priKey, plainOut, sizeof(plainOut),
				   s_syncKey, NULL, s_crypt);
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
		eciesEncRet =
		    zwEciesDecrypt(s_priKey, plainOut, sizeof(plainOut),
				   s_syncKey, s_hash, NULL);
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);

	}

	TEST_F(ECIES_Test, NormalDec_TooLongInput) {
		char plainOut[ZW_ECIES_MESSAGE_MAXLEN];
		memset(plainOut, 0, sizeof(plainOut));
		int eciesEncRet = ECIES_SUCCESS;
		//超长私钥
		eciesEncRet = zwEciesDecrypt(ts100, plainOut, sizeof(plainOut),
					     s_syncKey, s_hash, s_crypt);
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
		//不超长但是内容非法私钥
		eciesEncRet =
		    zwEciesDecrypt(g_invalid_testkey, plainOut,
				   sizeof(plainOut), s_syncKey, s_hash,
				   s_crypt);
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);
		//不超长但是内容非法syncKey,hash,crypt
		eciesEncRet =
		    zwEciesDecrypt(g_invalid_testkey, plainOut,
				   sizeof(plainOut), g_invalid_testkey,
				   g_invalid_testkey, g_invalid_testkey);
		EXPECT_NE(eciesEncRet, ECIES_SUCCESS);

	}
#endif // _DEBUG_ECIES_BADINPUT_TEST1117

#ifdef _DEBUG_ECIES_CSTEST1117
	TEST_F(ECIES_Test, csGenKeyPair) {
		int hd = 0;
		hd = EciesGenKeyPair();
		EXPECT_NE(hd, 0);
		char pubkey[ZW_ECIES_PUBKEY_LEN];
		char prikey[ZW_ECIES_PRIKEY_LEN];
		memset(pubkey, 0, sizeof(pubkey));
		memset(prikey, 0, sizeof(prikey));
		strcpy(pubkey, EciesGetPubKey(hd));
		strcpy(prikey, EciesGetPriKey(hd));
		EXPECT_GT(strlen(pubkey), 0);
		EXPECT_GT(strlen(prikey), 0);
#ifdef _DEBUG
		cout << "pubkey=\t" << pubkey << endl;
		cout << "prikey=\t" << prikey << endl;
#endif // _DEBUG
		EciesDelete(hd);
	}

//C#接口的非法输入测试
	TEST_F(ECIES_Test, cs_BadInput) {
		int hd = 0;
		hd = EciesGenKeyPair();
		EXPECT_GT(hd, 0);

		char *pubKey = NULL;
		char *priKey = NULL;

		pubKey = (char *)EciesGetPubKey(NULL);
		priKey = (char *)EciesGetPriKey(NULL);
		EXPECT_EQ(NULL, pubKey);
		EXPECT_EQ(NULL, priKey);

#ifdef _DEBUG
		EXPECT_DEBUG_DEATH((char *)EciesEncrypt(NULL, "palintext"), "");
		EXPECT_DEBUG_DEATH((char *)EciesEncrypt("pubkey", NULL), "");
#else
		EXPECT_EQ(NULL, (char *)EciesEncrypt(NULL, "palintext"));
		EXPECT_EQ(NULL, (char *)EciesEncrypt("pubkey", NULL));
#endif // _DEBUG
		EXPECT_EQ(NULL, (char *)EciesDecrypt("pubkey", NULL));
		EXPECT_EQ(NULL, (char *)EciesDecrypt(NULL, "crypttext"));

	}

	TEST_F(ECIES_Test, csEncDec) {
		const char *csPlainText =
		    "C# Port Test plain text 20140722.1625";
		int hd = 0;
		hd = EciesGenKeyPair();
		EXPECT_NE(hd, 0);
		char pubkey[ZW_ECIES_PUBKEY_LEN];
		char prikey[ZW_ECIES_PRIKEY_LEN];
		memset(pubkey, 0, sizeof(pubkey));
		memset(prikey, 0, sizeof(prikey));
		strcpy(pubkey, EciesGetPubKey(hd));
		strcpy(prikey, EciesGetPriKey(hd));
		EXPECT_GT(strlen(pubkey), 0);
		EXPECT_GT(strlen(prikey), 0);
		char crypt[ZW_ECIES_CRYPT_TOTALLEN];
		char crypt2[ZW_ECIES_CRYPT_TOTALLEN];
		char outPlain[ZW_ECIES_CRYPT_TOTALLEN * 2];
		memset(crypt, 0, sizeof(crypt));
		memset(outPlain, 0, sizeof(outPlain));
		strcpy(crypt, EciesEncrypt(pubkey, csPlainText));
		strcpy(crypt2, EciesEncrypt(pubkey, csPlainText));
		EXPECT_GT(strlen(crypt), 0);
		EXPECT_NE(0, memcmp(crypt, crypt2, ZW_ECIES_CRYPT_TOTALLEN));
		string crStr = EciesDecrypt(prikey, crypt);
		strcpy(outPlain, crStr.c_str());
		EXPECT_GT(strlen(outPlain), 0);
		EciesDelete(hd);
#ifdef _DEBUG
		cout << "pubkey=\t" << pubkey << endl;
		cout << "prikey=\t" << prikey << endl;
		cout << "ecies crypt combie result is" << endl << crypt << endl;
		cout << "ecies crypt2 combie result is" << endl << crypt2 <<
		    endl;
#endif // _DEBUG

	}

	TEST_F(ECIES_Test, cs_TooLongInput) {
		char *pubKey = NULL;
		char *priKey = NULL;

		pubKey = (char *)EciesGetPubKey(NULL);
		priKey = (char *)EciesGetPriKey(NULL);
		EXPECT_EQ(NULL, pubKey);
		EXPECT_EQ(NULL, priKey);
		char *crypt = NULL;
		//超长公钥输入
		crypt = (char *)EciesEncrypt(ts100, "palintext");
		EXPECT_EQ(NULL, crypt);
		//内容长度合法但是根本不是公钥的输入
		crypt = (char *)EciesEncrypt("pubkey", "plaintext");
		EXPECT_EQ(NULL, crypt);
		//超长明文输入
		crypt = (char *)EciesEncrypt("pubkey", ts100);
		EXPECT_EQ(NULL, crypt);

		//超长私钥输入
		crypt = (char *)EciesDecrypt(ts100, "crypttext");
		EXPECT_EQ(NULL, crypt);
		//内容长度合法但是根本不是私钥的输入
		crypt =
		    (char *)EciesDecrypt("myFakePrivateKey", "crypt.text.333");
		EXPECT_EQ(NULL, crypt);
		//超长密文输入
		crypt = (char *)EciesDecrypt("pubkey", ts100);
		EXPECT_EQ(NULL, crypt);

	}
#endif // _DEBUG_ECIES_CSTEST1117

	TEST_F(ECIES_Test, zwMergePskTest) {		
		printf("INFO1210:\n%s\n",zwMergePsk("aaaaaaaaaa"));
	}

#ifdef _USEYB714TEST
	void yb714Test(const char *ybinput)
	{	
		const int ybLen=strlen(ybinput);
		char outHash[32*2+1];
		char *oth=outHash;
		jcGetHashSM3(ybinput,ybLen,oth);
		
		printf("印宝输入字符串为\t%s\t长度为%d\n",ybinput,ybLen);
		printf("印宝的输入第一阶段SM3 HASH结果是:\n%s\n",outHash);
#ifdef _DEBUG715A1
		for (int i=0;i<32;i++)
		{
			printf("%02X",outHash[i] & 0xFF);
		}
		printf("\n");
#endif // _DEBUG715A1
		char outCode[16];
		memset(outCode,0,16);
		char *occ=outCode;
		jcHash2Code8(outHash,occ);
		printf("印宝的输入第二阶段8位数字码结果是:\t%s\n",outCode);
	}

	//20150714.1714.印宝算法最基本组件测试
	TEST_F(ECIES_Test, zwYinBaoTest714) {				
		yb714Test("YBT1723.1");
		yb714Test("YinBaoMsg714.1607.1");
		yb714Test("YinBaoMsg714.1721.data1.1");
	}

#endif _USEYB714TEST

//////////////////////////////////////////////////////////////////////////
}				//namespace ccbtest722{
