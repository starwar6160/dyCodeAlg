#ifndef zwEcies529_h__
#define zwEcies529_h__
//#include <string>
//using std::string;

#ifndef ECDH_H
//#define EFS 32 /* ECCSI Field Size - 256 bits */
typedef int BOOL;
#endif 
const int ZWEFS=256/8;	
const int ZW_EXA=4;
//EFS=32�ֽ�=256bit
//����ֵ������ʵ�����90�ֽڳ��ȵ�BASE64�ַ���
//��������ı����ֽ���Ŀ
//#define ZW_EXA	(4)
//����ֱ�Ӽ���base64������ַ������ȣ�����*4/3
//////////////////////////////////////////////////////////////////////////
#define ZW_ECIES_PUBKEY_LEN	((ZWEFS*2+ZW_EXA)*4/3)	//��Կ
#define ZW_ECIES_PRIKEY_LEN ((ZWEFS*1+ZW_EXA)*4/3)	//˽Կ
//////////////////////////////////////////////////////////////////////////
#define ZW_ECIES_ENCSYNCKEY_LEN ((ZWEFS*2+ZW_EXA)*4/3)	//���ܽ��PART1,���ܹ��ĶԳ���Կ
#define ZW_ECIES_HASH_LEN		((ZWEFS*1+ZW_EXA)*4/3)	//���ܽ��PART2,HASHֵ
//ECIES�����þ����������ܶԳ���Կ����֪����BLOWFISH��448bit��
//SHA512�������Ϊ��Կ�Ļ���512bit�����ǿ��ܼ�������һЩ������
//�������768bit(EFS*3)Ӧ���㹻��
#define ZW_ECIES_MESSAGE_MAXLEN	((ZWEFS*2+6)*4/3)			//���ܽ��PART3���ԳƼ��ܹ�������
//���ܽ��3���ֳ���֮��
#define ZW_ECIES_CRYPT_TOTALLEN	(ZW_ECIES_ENCSYNCKEY_LEN+ZW_ECIES_HASH_LEN+ZW_ECIES_MESSAGE_MAXLEN)
//////////////////////////////////////////////////////////////////////////


#define ZWECIES_API

#ifdef  __cplusplus
extern "C" {
#endif

	enum ECIES_ERROR{
		ECIES_SUCCESS,
		ECIES_FAIL,
		ECIES_OUTPUT_BUFFER_TOO_SHORT,
		ECIES_PRIKEY_TOO_SHORT,
		ECIES_PUBKEY_TOO_SHORT,
		ECIES_HASH_TOO_SHORT,
		ECIES_CRYPT_TOO_SHORT,
		ECIES_ENCEDSYNCKEY_TOO_SHORT,
		ECIES_PLAIN_TOO_SHORT,
		ECIES_PUBKEY_GEN_FAIL,
		ECIES_INPUT_TOO_SHORT,
		ECIES_PUBKEY_INVALID,
		ECIES_PRIKEY_INVALID,
		ECIES_INPUT_NULL,
		ECIES_INIT_FLAG
	};

	enum ECIES_ITEMS{
		ECIES_PUBKEY,
		ECIES_PRIKEY,
		ECIES_ENCSYNCKEY,
		ECIES_ENCHASH,
		ECIES_ENCTEXT,
		ECIES_ENCALLOUT
	};

#ifdef _DEBUG_123
//���������漰����β��Str�Ĳ���������Base64����HEX����֮һ��Ĭ��һ����Base64�Ա���ٲ�������
//����char�Ĳ�������ͨ�ַ�����
//��ʼ��ECIES��������˽Կ�͹�Կ
//password:�ַ�����ʽ�����룬����Կ�Ե�������ӣ�������ʱ������Ҫ
//outPriKeyStr��priLen��˽Կ���������ָ���Լ�����������
//outPublicKeyStr��pubLen�ǹ�Կ���������ָ���Լ�����������
//˽Կ�͹�Կ����������������Ȳ������Ļ�������أ�����ֵ��ECIES_ERROR���ö��
	ZWECIES_API int zwEciesKeyPairGen( const char *password,char *outPriKeyStr,const int priLen,
		char *outPublicKeyStr ,const int pubLen);

//ECIES���ܣ�
//pubkeyStr��������Ĺ�Կ	PlainText������
//����������������Ƿ�Ϊ3����Ŀ�ļ��ܽ���Լ�����
//����������������Ȳ������Ļ�������أ�����ֵ��ECIES_ERROR���ö��
//outEncryptedSyncKeyStr�����ܹ��ģ�������ĶԳƻỰ��Կ
//outMsgHashStr���������HASH���
//outCryptedTextStr���������ʹ��outEncryptedSyncKeyStr�ĶԳƼ��ܽ��
	ZWECIES_API int zwEciesEncrypt(const char *pubkeyStr,const char *PlainText, 
		char *outEncryptedSyncKeyStr,const int syncKeyLen, 
		char *outMsgHashStr,const int hashLen,
		char *outCryptedTextStr,const int cryptLen);
//ECIES���ܣ�
//prikeyStr���������˽Կ	outPlainText��������Ļ�����	plainLen�����Ļ���������
//EncryptedSyncKeyStr��MsgHashStr��CryptedTextStr������ͬ���������3����Ŀ
	ZWECIES_API int zwEciesDecrypt(const char *prikeyStr,char *outPlainText,const int plainLen, const char *EncryptedSyncKeyStr,const char *MsgHashStr,const char *CryptedTextStr);
//int myTestEccMain();
#endif // _DEBUG_123
//////////////////////////////�������ʺϰ�װ��C#ʹ�õĽӿ�////////////////////////////////////////////
//����ECIES��Կ/˽Կ�ԣ����ر�����Կ�Եȵȵ��ڲ����ݽṹ���
ZWECIES_API int		EciesGenKeyPair(void);
//ɾ��������Կ�Եȵȵ��ڲ����ݽṹ
ZWECIES_API void	EciesDelete(int eciesHandle);
//�Ӿ����ָ����ڲ����ݽṹ��ȡǰ�����ɺõĹ�Կ����Base64��ʽ�ַ�������������京�壬ԭ��͸������
ZWECIES_API const char * EciesGetPubKey(int eciesHandle);
//�Ӿ����ָ����ڲ����ݽṹ��ȡǰ�����ɺõ�˽Կ����Base64��ʽ�ַ�������������京�壬ԭ��͸������
ZWECIES_API const char * EciesGetPriKey(int eciesHandle);
//
//���������Լ�base64��ʽ�Ĺ�Կ������ֵ��base64�����3��Ԫ�ص���ϣ�������������壬ԭ��͸������
//���������ΪZW_ECIES_MESSAGE_MAXLEN-1���ַ�������Ϊ�ս����ַ�����-1����ΪNULL�ַ�ռ��λ��
ZWECIES_API const char * EciesEncrypt(const char *pubKey,const char *plainText);
//������ܺ��������base64�����3��Ԫ�ص���ϵ����ģ��Լ�base64��ʽ��˽Կ����������
ZWECIES_API const char * EciesDecrypt(const char *priKey,const char *cryptText);
//Ҫ��eciesHandle�Ѿ��������˹�Կ���ܳɹ�������ֵ��3��Ԫ�ص���ϣ��������������
//20150325.���а汾������������ʱ�������UTC�������ַ�����ʽ
ZWECIES_API const char *EciesEncryptCCB1503(const char *pubKey, const char *plainText,time_t nowTime);

ZWECIES_API const char * zwMergePsk(const char *pskInput);
#ifdef  __cplusplus
}
#endif




#endif // zwEcies529_h__
