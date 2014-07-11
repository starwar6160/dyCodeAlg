#ifdef  __cplusplus
extern "C" {
#endif
#include "ecdh.h"
#ifdef  __cplusplus
}
#endif
#include "..\stdafx.h"
//#include <assert.h>
#include <string>
#include <vector>
using std::string;
using std::vector;

void zwRandSeedGen603(char *randBuf,const int randBufLen);

//������HEX��BASE64֮���л�
enum zwOutputASCII_Format{
	ZWOUTFMT_HEX,
	ZWOUTFMT_BASE64
};
//����ECIES�㷨�����������װʹ��BASE64����HEX�ֻ����������ܵĸ�ʽ
const static int MYOUT_FORMAT=
	ZWOUTFMT_BASE64;
	//ZWOUTFMT_HEX;



#ifdef  __cplusplus
extern "C" {
#endif
#include "ecdh.h"
#include "octet.h"
#include "zwEcies529.h"

	//�˴��ĳ�ʼ��ֵ������ͬ�������ģ�������ͬ�ĶԳ���Կ
	void myPrngInit( csprng *RNG );
	/* Convert an octet string to base64 string */
	//����b�Ĵ�СҪ��w->max��2��+1���ֽ�
	void ZWOCTET_FROM_ASCII(octet *dstOct,const char *srcAscii);
	int ZWOCTET_TO_ASCII(const octet *srcOct,char *dstAscii,const int dstLen);
	void myKDFHMACSeed( octet *KDF2Seed, octet *HmacSeed );
	int ZWOCTET_OUTPUT_STRING(const octet *srcOct,char *dstStr,const int dstLen);


#ifdef  __cplusplus
}
#endif


class jcOctex
{
public:
	jcOctex(int MaxSize){
		assert(MaxSize>0);
		m_oct.len=0;
		m_oct.max=MaxSize;
		m_oct.val=new char[MaxSize];
		memset(m_oct.val,0,MaxSize);
	};
	~jcOctex(){
		assert(m_oct.max>0);
		assert(m_oct.max>=m_oct.len);
		assert(m_oct.val!=NULL);
		memset(m_oct.val,0,m_oct.max);
		delete [] m_oct.val;
		m_oct.len=0;
		m_oct.max=0;
	};
	octet &Value(){return m_oct;};
private:
	octet m_oct;
};

//�˴��ĳ�ʼ��ֵ������ͬ�������ģ�������ͬ�ĶԳ���Կ
void myPrngInit( csprng *RNG )
{
	assert(RNG!=NULL);
	int i;
	/* Crypto Strong RNG */
	jcOctex RAW(EFS*3);
	RAW.Value().len=EFS*3;				/* fake random seed source */
	zwRandSeedGen603(RAW.Value().val,RAW.Value().max);
	assert(RNG!=NULL);	
	//for (i=0;i<EFS*3;i++) RAW.Value().val[i]=i+1;
	//��ǰ��ļٵ��������������ʼ��������ѧǿ��α�������������
	//�����������������ǿ�������������ǲ����������������ĸ���
	//��Ϊͨ�����������������������ʶ���Ϊ���ޣ�������Ҫʹ��
	//�����������ʼ��������ѧǿ��α�������������
	CREATE_CSPRNG(RNG,&RAW.Value());   /* initialise strong RNG */
}


/* Convert an octet string to HEX string */
//����b�Ĵ�СҪ��w->max��2��+1���ֽ�
int ZWOCTET_TO_ASCII( const octet *srcOct,char *dstAscii,const int dstLen )
{
	int i=0;
	assert(dstAscii!=NULL);
	assert(srcOct!=NULL);
	assert(srcOct->len>0);
	assert(srcOct->max>=srcOct->len);
	assert(dstAscii!=0);	
	
	if (ZWOUTFMT_BASE64==MYOUT_FORMAT)
	{		
		if (srcOct->len*4/3+1>dstLen)
		{
			return ECIES_OUTPUT_BUFFER_TOO_SHORT;
		}
		assert(srcOct->len*4/3+1<=dstLen);
		OCTET_TO_BASE64(srcOct,dstAscii);
	}
//////////////////////////////////////////////////////////////////////////
	if (ZWOUTFMT_HEX==MYOUT_FORMAT)
	{		
		if (srcOct->len*2+1>dstLen)
		{
			return ECIES_OUTPUT_BUFFER_TOO_SHORT;
		}
		assert(srcOct->len*2+1<=dstLen);
		//��BIN��HEX��Ҫ*2��ĩβNULL��Ҫ+1
		int needBytes=srcOct->len*2+1;
		if (needBytes>dstLen)
		{		
			printf("Need %d bytes Real %d bytes\n",needBytes,dstLen);
			return ECIES_OUTPUT_BUFFER_TOO_SHORT;
		}

		for (i=0;i<srcOct->len;i++)
		{
			unsigned int ch=srcOct->val[i] & 0xFF;
			sprintf(dstAscii+i*2,"%02X",ch);
		}
		dstAscii[srcOct->len*2]=(char)NULL;
	}//ZWOUTFMT_HEX

	
	return ECIES_SUCCESS;
}

void ZWOCTET_FROM_ASCII( octet *dstOct,const char *srcAscii )
{
	int inLen=strlen(srcAscii);
	int i=0;
	assert(srcAscii!=NULL && strlen(srcAscii)>0);
	assert(dstOct!=NULL && dstOct->max>0);
	if (ZWOUTFMT_BASE64==MYOUT_FORMAT)
	{
		OCTET_FROM_BASE64(srcAscii,dstOct);
	}
//////////////////////////////////////////////////////////////////////////
	if (ZWOUTFMT_HEX==MYOUT_FORMAT)
	{
	for (i=0;i<inLen/2;i++)
	{
		char *dst=dstOct->val+i;
		sscanf(srcAscii+2*i,"%02X",dst);
		dstOct->len++;
	}
	}	//ZWOUTFMT_HEX
}

void myKDFHMACSeed( octet *KDF2Seed, octet *HmacSeed )
{
	assert(KDF2Seed!=NULL && KDF2Seed->max>0);
	assert(HmacSeed!=NULL && HmacSeed->max>0);
	HmacSeed->val[3]=0x3; 
	//KDF2Seed������KDF2��  HmacSeed�Ǽ���MAC�е�,����������ָ����ֻ��Ҫ���˱���һ��
	//���ԣ�KDF2Seed�ı��������CryptedText�ı����HmacSeed�ı��������MsgHash�ı��
	KDF2Seed->len=3; KDF2Seed->val[0]=0x90; KDF2Seed->val[1]=0x1; KDF2Seed->val[2]=0x2; 
	HmacSeed->len=4; HmacSeed->val[0]=0x41; HmacSeed->val[1]=0x1; HmacSeed->val[2]=0x2; 
}

int ZWOCTET_OUTPUT_STRING( const octet *srcOct,char *dstStr,const int dstLen )
{
	int i;
	unsigned char ch;
	if ((srcOct->len+1)>dstLen)
	{
		return ECIES_OUTPUT_BUFFER_TOO_SHORT;
	}
	
	for (i=0;i<srcOct->len;i++)
	{
		ch=srcOct->val[i];
		dstStr[i]=ch;
	}
	dstStr[srcOct->len]=NULL;
	return ECIES_SUCCESS;
}  


//��ʼ��ECIES��������˽Կ�͹�Կ
ZWECIES_API int zwEciesKeyPairGen( const char *password,char *outPriKeyStr,const int priLen, char *outPublicKeyStr ,const int pubLen )
{	
	if (password==NULL || strlen(password)==0)
	{
		return ECIES_INPUT_TOO_SHORT;
	}
	if (priLen==0 || pubLen==0)
	{
		return ECIES_INPUT_TOO_SHORT;
	}
	if (outPriKeyStr==NULL || outPublicKeyStr==NULL)
	{
		return ECIES_INPUT_NULL;
	}
	
	assert(password!=NULL && strlen(password)>0);
	assert(outPriKeyStr!=NULL);
	assert(outPublicKeyStr!=NULL);
	assert(priLen>0 && pubLen>0);

	//�ӹ̶��洢��ȡECC���߲���
	ecp_domain eciesCtx;
	ECP_DOMAIN_INIT(&eciesCtx,ecrom);	

	//�˴�SALT������ͬ����password������ͬ�Ĺ�Կ��˽Կ
	//������Ϊһ��д��������ֵ
	jcOctex PW(EFS),SALT(EFS);
	//ע��˴���SALT�ĳ��ȱ���Ҫ��ȷ��ʼ��������SALT�ͻ᲻�����õ���
	//ͬһ��password���ɵ���Կ��ʼ����ͬһ��
	SALT.Value().len=EFS;
	zwRandSeedGen603(SALT.Value().val,EFS);
	//��pp���ַ�������ŵ�PW��OCTET����
	OCTET_JOIN_STRING(password,&PW.Value());   // set Password from string
	/* private key S0 of size EGS bytes derived from Password and Salt */
	//���û������SALTͨ��PBKDF2��������256bit(EGS����)��ECC˽ԿS1
	//Ҳ����˵˽Կ����������ģ�����˽Կȥ���ɹ�Կ
	jcOctex oct_private_key(ZW_ECIES_PRIKEY_LEN);
	PBKDF2(&PW.Value(),&SALT.Value(),1000,EGS,&oct_private_key.Value());
	if (ECIES_SUCCESS!=
		ZWOCTET_TO_ASCII(&oct_private_key.Value(),outPriKeyStr, priLen))
	{
		printf("privateKey Buffer Too Short\n");
		return (ECIES_PRIKEY_TOO_SHORT);
	}
	//printf("Server private key= %s\n",outPriKeyHex);

	//��˽ԿS1���ɹ�ԿW1
	jcOctex oct_public_key(ZW_ECIES_PUBKEY_LEN);
	ECP_KEY_PAIR_GENERATE(&eciesCtx,NULL,&oct_private_key.Value(),&oct_public_key.Value());
	//�������ɵĹ�Կ��ȷ��
	int res=ECP_PUBLIC_KEY_VALIDATE(&eciesCtx,TRUE,&oct_public_key.Value());
	if (res!=0)
	{
		printf("ECP Public Key is invalid!\n");
		return ECIES_PUBKEY_GEN_FAIL;
	}
	if (ECIES_SUCCESS!=
	ZWOCTET_TO_ASCII(&oct_public_key.Value(),outPublicKeyStr, pubLen))
	{
		printf("publicKey Buffer Too Short\n");
		return (ECIES_PUBKEY_TOO_SHORT);
	}
	assert(strlen(outPublicKeyStr)>0);
	//printf("Servers public key= %s\n",outPublicKeyHex); 	
	return ECIES_SUCCESS;
}

ZWECIES_API int zwEciesEncrypt( const char *pubkeyStr,const char *PlainText, char *outEncryptedSyncKeyStr,const int syncKeyLen, char *outMsgHashStr,const int hashLen, char *outCryptedTextStr,const int cryptLen )
{		      
	if (pubkeyStr==NULL || strlen(pubkeyStr)==0)
	{
		return ECIES_INPUT_NULL;
	}
	if (PlainText==NULL || strlen(PlainText)==0)
	{
		return ECIES_INPUT_NULL;
	}
	if (outEncryptedSyncKeyStr==NULL || syncKeyLen==0)
	{
		return ECIES_INPUT_NULL;
	}	
	if (outCryptedTextStr==NULL || cryptLen==0)
	{
		return ECIES_INPUT_NULL;
	}	
	if (outMsgHashStr==NULL || hashLen==0)
	{
		return ECIES_INPUT_NULL;
	}	
	//��Կ��HEX�ַ�����Ϊoctet���ڲ���ʽ��������			
	assert(pubkeyStr!=NULL && strlen(pubkeyStr)>0);
	assert(PlainText!=NULL && strlen(PlainText)>0);
	assert(outEncryptedSyncKeyStr!=NULL && syncKeyLen>0);
	assert(outCryptedTextStr!=NULL && cryptLen>0);
	assert(outMsgHashStr!=NULL && hashLen>0);

	//��Կ��HEX�ַ�����Ϊoctet���ڲ���ʽ
	jcOctex oct_pubkey(ZW_ECIES_PUBKEY_LEN);
	jcOctex oct_PlainText(ZW_ECIES_MESSAGE_MAXLEN);
	ZWOCTET_FROM_ASCII(&oct_pubkey.Value(),pubkeyStr);
	OCTET_JOIN_STRING(PlainText,&oct_PlainText.Value());

	//�ӹ̶��洢��ȡECC���߲���
	ecp_domain ecies_ctx;
	ECP_DOMAIN_INIT(&ecies_ctx,ecrom);	

	//���ܺ����ڲ���ʼ��KDF��HMAC�����ӣ���Ϊ���ǵ��㷨��������������
	jcOctex KDF2Seed(EFS),HmacSeed(EFS);
	myKDFHMACSeed(&KDF2Seed.Value(),&HmacSeed.Value());
	csprng RNG; 
	myPrngInit(&RNG);
	//�˴�����ʱMSGHASH�ĳ������ֵ��Ҳ����MsgHash->maxָ���೤���������ж೤
	//������Ӱ����ܽ������ȷ�ԣ���֪����ʼ��MIRACL���Ӵ�����ֱ��ָ��ħ������12
	//��ʲô��˼��	20140522.1045.��ΰ
	jcOctex oct_syncKey(ZW_ECIES_ENCSYNCKEY_LEN);
	jcOctex oct_hash(ZW_ECIES_HASH_LEN);
	jcOctex oct_crypt(ZW_ECIES_MESSAGE_MAXLEN);
	ECP_ECIES_ENCRYPT(&ecies_ctx,&KDF2Seed.Value(),&HmacSeed.Value(),&RNG,&oct_pubkey.Value(),
		&oct_PlainText.Value(),oct_hash.Value().max/2,&oct_syncKey.Value(),&oct_crypt.Value(),&oct_hash.Value());
	if (ECIES_SUCCESS!=ZWOCTET_TO_ASCII(&oct_syncKey.Value(),outEncryptedSyncKeyStr, syncKeyLen))
	{
		printf("EncryptedSyncKey Buffer Too Short\n");
		return (ECIES_ENCEDSYNCKEY_TOO_SHORT);
	}
	if (ECIES_SUCCESS!=ZWOCTET_TO_ASCII(&oct_hash.Value(),outMsgHashStr, hashLen))
	{
		printf("MsgHash Buffer Too Short\n");
		return (ECIES_HASH_TOO_SHORT);
	}
	if (ECIES_SUCCESS!=ZWOCTET_TO_ASCII(&oct_crypt.Value(),outCryptedTextStr, cryptLen))
	{
		printf("CryptedText Buffer Too Short\n");
		return (ECIES_CRYPT_TOO_SHORT);
	}
	KILL_CSPRNG(&RNG);
	return ECIES_SUCCESS;
}


//����PlainText��Ҫ�Լ���֤�㹻������������һ�㶼�Ǽ��ܶԳ���Կ������ĳ�������Ķ����϶��Ϳ�����
ZWECIES_API BOOL zwEciesDecrypt( const char *prikeyStr,char *outPlainText,const int plainLen, const char *EncryptedSyncKeyStr,const char *MsgHashStr,const char *CryptedTextStr )
{
	if (prikeyStr==NULL || strlen(prikeyStr)==0)
	{
		return ECIES_INPUT_NULL;
	}
	if (EncryptedSyncKeyStr==NULL || strlen(EncryptedSyncKeyStr)==0)
	{
		return ECIES_INPUT_NULL;
	}
	if (MsgHashStr==NULL || strlen(MsgHashStr)==0)
	{
		return ECIES_INPUT_NULL;
	}
	if (CryptedTextStr==NULL || strlen(CryptedTextStr)==0)
	{
		return ECIES_INPUT_NULL;
	}
	if (outPlainText==NULL || plainLen==0)
	{
		return ECIES_INPUT_NULL;
	}
	//��ڲ�����У��
	assert(prikeyStr!=NULL && strlen(prikeyStr)>0);	
	assert(EncryptedSyncKeyStr!=NULL &&strlen(EncryptedSyncKeyStr)>0);
	assert(MsgHashStr!=NULL && strlen(MsgHashStr)>0);
	assert(CryptedTextStr!=NULL && strlen(CryptedTextStr)>0);	
	assert(outPlainText!=NULL && plainLen>0);

	//˽Կ��base64�ַ�����Ϊoctet���ڲ���ʽ
	jcOctex oct_prikey(ZW_ECIES_PRIKEY_LEN);
	jcOctex oct_sykey(ZW_ECIES_ENCSYNCKEY_LEN);
	jcOctex oct_hash(ZW_ECIES_HASH_LEN);
	jcOctex oct_crypted_bin(ZW_ECIES_MESSAGE_MAXLEN);
	jcOctex oct_plain(ZW_ECIES_MESSAGE_MAXLEN);
	ZWOCTET_FROM_ASCII(&oct_prikey.Value(),prikeyStr);
	ZWOCTET_FROM_ASCII(&oct_sykey.Value(),EncryptedSyncKeyStr);
	ZWOCTET_FROM_ASCII(&oct_hash.Value(),MsgHashStr);
	ZWOCTET_FROM_ASCII(&oct_crypted_bin.Value(),CryptedTextStr);	
	

	//�ӹ̶��洢��ȡECC���߲���
	ecp_domain ecies_ctx;
	ECP_DOMAIN_INIT(&ecies_ctx,ecrom);	

	//���ܺ����ڲ���ʼ��KDF��HMAC�����ӣ���Ϊ���ǵ��㷨�������������أ�
	//��������Ҫ�ͼ��ܺ����ڲ���ʼ��������ֵ��ȫһ�²�����ȷ���ܣ�
	jcOctex KDF2Seed(EFS),HmacSeed(EFS);
	myKDFHMACSeed(&KDF2Seed.Value(),&HmacSeed.Value());
	BOOL res=ECP_ECIES_DECRYPT(&ecies_ctx,&KDF2Seed.Value(),&HmacSeed.Value(),
		&oct_sykey.Value(),&oct_crypted_bin.Value(),
		&oct_hash.Value(),&oct_prikey.Value(),&oct_plain.Value());

	if (ECIES_SUCCESS!=ZWOCTET_OUTPUT_STRING(&oct_plain.Value(),outPlainText, plainLen))
	{
		printf("PlainText Buffer Too Short\n");
		return ECIES_PLAIN_TOO_SHORT;
	}
	if (TRUE==res)
	{
		return ECIES_SUCCESS;
	}
	else
	{
		return ECIES_FAIL;
	}
	
	return res;
}


int myTestEccMain()
{
	/* These octets are automatically protected against buffer overflow attacks */
	/* Note salt must be big enough to include an appended word */
	/* Note ECIES ciphertext C must be big enough to include at least 1 appended block */
	/* Recall EFS is field size in bytes. So EFS=32 for 256-bit curve */
	//c�����㹻���Ա���������һ�����ӵĿ�(����17�ֽڵ���������Ҫ��2��128bit��Ҳ����32�ֽڳ���)
	//��Ϊ�ڲ�ʹ�õ�AES��Ե�ʣ�����Padding�����Դ����Ĵ�С17�ֽڰ���128bit���С����ȡ�����Ĵ�С��32�ֽ�)
	//ecp_domain eciesCtx;	
	char PriKey[ZW_ECIES_PRIKEY_LEN*2];
	char PubKey[ZW_ECIES_PUBKEY_LEN*2];
	char encSyncKey[ZW_ECIES_ENCSYNCKEY_LEN*2],msgHashBuf[EFS*2+ZW_EXA];
	char cryptText[ZW_ECIES_MESSAGE_MAXLEN*2];
	if (ECIES_SUCCESS!=
		zwEciesKeyPairGen("privatekeypassword",PriKey, sizeof(PriKey), PubKey, sizeof(PubKey)))
	{
		printf("ECIES KeyPair Gen Fail!\n");
		return ECIES_PUBKEY_GEN_FAIL;
	}
		
	//////////////////////////////////////////////////////////////////////////
	{   
		const char *myPlainText="PlainText 20140523.1405";
		printf("Testing ECIES\n");

		//epdom:ECC���ܻ�����Ҳ���Ǹ����ڲ��������ڵĽṹ��
		//P1,P2:���ָ����P1����KDF2��P2����HMAC
		//W1:�Է���Կ	M:����	12����T(tag)���εĳ���
		//V:�Գ���Կ������	C:��������Ϣ������	T:HASHֵ	
		zwEciesEncrypt(PubKey,
			myPlainText,encSyncKey, sizeof(encSyncKey),
			msgHashBuf, sizeof(msgHashBuf),
			cryptText, sizeof(cryptText));

		assert(strlen(encSyncKey)>0);
		printf("V(Encrypted Sync Key)=\t%s\n",encSyncKey);	
		assert(strlen(cryptText)>0);
		printf("C(Encrypted Message)=\t%s\n",cryptText);
		printf("T(HASH of message)=\t%s\n",msgHashBuf);
		{				
			char plainTextBuf[ZW_ECIES_MESSAGE_MAXLEN];

			//����
			//��������ͼ��ܲ�࣬����PubKey�Ĺ�Կ�滻ΪPriKey��˽Կ
			memset(plainTextBuf,0,sizeof(plainTextBuf));

			if (!zwEciesDecrypt(PriKey,plainTextBuf, sizeof(plainTextBuf),
				encSyncKey,msgHashBuf,cryptText))
			{
				printf("*** ECIES Decryption Failed\n");
				return 0;
			}
			else printf("Decryption succeeded\n");

			printf("Message is \n%s\n",plainTextBuf); 
		}

		//ECP_DOMAIN_KILL(&eciesCtx);
	}
	return 0;
}

//ZWECIES_API const string & zwtestString(const string &inStr,const string &outStr)
//{
//	return "";
//}

struct zwEcies_t{
	int status;
	string pubKey;
	string priKey;
	string encoutSyncKey;
	string encoutHash;
	string encoutCryptText;
};
ZWECIES_API int EciesGenKeyPair(void)
{
#define ZWPRILEN	(ZW_ECIES_PRIKEY_LEN*4/3)
#define ZWPUBLEN	(ZW_ECIES_PUBKEY_LEN*4/3)
	zwEcies_t *stu=new zwEcies_t;
	stu->status=ECIES_INIT_FLAG;	//��־�ýṹ���Ѿ�����ʼ��
	char PriKey[ZWPRILEN];
	char PubKey[ZWPUBLEN];
	memset(PriKey,0,ZWPRILEN);
	memset(PubKey,0,ZWPUBLEN);
	zwEciesKeyPairGen("randpassword",PriKey,ZWPRILEN,PubKey,ZWPUBLEN);
	stu->pubKey=PubKey;
	stu->priKey=PriKey;
	return (int)stu;
}

ZWECIES_API void EciesDelete(int eciesHandle)
{
	zwEcies_t *stu=(zwEcies_t *)eciesHandle;
	if (NULL!=stu && ECIES_INIT_FLAG==stu->status)
	{
		delete stu;
	}
}

ZWECIES_API string EciesGetPubKey(int eciesHandle)
{
	zwEcies_t *stu=(zwEcies_t *)eciesHandle;
	if (NULL==stu || ECIES_INIT_FLAG!=stu->status)
	{
		return "BADHANDLE20140604";
	}
	return stu->pubKey;
}

ZWECIES_API string EciesGetPriKey(int eciesHandle)
{
	zwEcies_t *stu=(zwEcies_t *)eciesHandle;
	if (NULL==stu || ECIES_INIT_FLAG!=stu->status)
	{
		return "BADHANDLE20140604";
	}
	return stu->priKey;
}

//�Զ���ʵ��split����
void zwsplit(const std::string& s, std::string& delim,std::vector< std::string > *ret)
{
	size_t last = 0;
	size_t index=s.find_first_of(delim,last);
	while (index!=std::string::npos)
	{
		string tt = s.substr(last,index-last);		
		ret->push_back(tt);
		last=index+1;
		index=s.find_first_of(delim,last);
	}
	if (index-last>0)
	{
		ret->push_back(s.substr(last,index-last));
	}
}



//��3���������ϲ�Ϊһ���ַ�������
static string myMergeEncOutItems(int eciesHandle)
{
	zwEcies_t *stu=(zwEcies_t *)eciesHandle;
	if (NULL==stu || ECIES_INIT_FLAG!=stu->status)
	{
		return "BADHANDLE20140604";
	}
	if (stu->encoutSyncKey.length()==0 ||
		stu->encoutHash.length()==0 ||
		stu->encoutCryptText.length()==0)
	{
		return "NULL ENCRYPT OUT 20140604";
	}
	return	stu->encoutSyncKey+"."+
			stu->encoutHash+"."+
			stu->encoutCryptText;
}


//Ҫ��eciesHandle�Ѿ��������˹�Կ���ܳɹ�������ֵ��3��Ԫ�ص���ϣ��������������
ZWECIES_API string EciesEncrypt( const string &pubKey,const string &plainText )
{
#define SKELEN	(ZW_ECIES_ENCSYNCKEY_LEN*2)
#define HASHLEN	(EFS*2+ZW_EXA)
#define CRLEN	(ZW_ECIES_MESSAGE_MAXLEN*2)
	char encSyncKey[SKELEN],msgHashBuf[HASHLEN];
	char cryptText[CRLEN];
	memset(encSyncKey,0,SKELEN);
	memset(msgHashBuf,0,HASHLEN);
	memset(cryptText,0,CRLEN);
	int res=zwEciesEncrypt(pubKey.c_str(),plainText.c_str(),
		encSyncKey,SKELEN,msgHashBuf,HASHLEN,cryptText,CRLEN);
	string dot=".";
	return encSyncKey+dot+msgHashBuf+dot+cryptText;
}

//Ҫ��eciesHandle�Ѿ���������˽Կ���ܳɹ�������������3��Ԫ�ص���ϣ��������������
ZWECIES_API string EciesDecrypt(const string &priKey,const string &cryptText)
{
	if (priKey.length()==0)
	{
		return "";
	}

	//���Ȱ���ϵ�3����Ŀ�зֿ���
	vector<string> encout;
	string delm=".";
	zwsplit(cryptText,delm,&encout);
	char plainTextBuf[ZW_ECIES_MESSAGE_MAXLEN];
	memset(plainTextBuf,0,ZW_ECIES_MESSAGE_MAXLEN);

	zwEciesDecrypt(priKey.c_str(),plainTextBuf,ZW_ECIES_MESSAGE_MAXLEN,
		encout[0].c_str(),encout[1].c_str(),encout[2].c_str());
	return plainTextBuf;
}

