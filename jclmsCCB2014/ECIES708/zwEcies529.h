#ifndef zwEcies529_h__
#define zwEcies529_h__
#include <string>
using std::string;

#ifndef ECDH_H
#define EFS 32 /* ECCSI Field Size - 256 bits */
typedef int BOOL;
#endif 
//EFS=32�ֽ�=256bit
//����ֵ������ʵ�����90�ֽڳ��ȵ�BASE64�ַ���
//��������ı����ֽ���Ŀ
#define ZW_EXA	(4)
#define ZW_ECIES_PUBKEY_LEN	(EFS*2+ZW_EXA)
#define ZW_ECIES_PRIKEY_LEN	(EFS*1+ZW_EXA)
#define ZW_ECIES_ENCSYNCKEY_LEN	(EFS*2+ZW_EXA)
#define ZW_ECIES_HASH_LEN	(EFS*1+ZW_EXA)
//ECIES�����þ����������ܶԳ���Կ����֪����BLOWFISH��448bit��
//SHA512�������Ϊ��Կ�Ļ���512bit�����ǿ��ܼ�������һЩ������
//�������768bit(EFS*3)Ӧ���㹻��
#define ZW_ECIES_MESSAGE_MAXLEN	(EFS*2)

#ifndef _ZWUSE_AS_JNI
#ifdef ZWECIES_EXPORTS
#define ZWECIES_API __declspec(dllexport)
#else
#define ZWECIES_API __declspec(dllimport)
#endif
#else
#define ZWECIES_API
#endif

//ZWECIES_API string & zwtestString(const string &inStr,string &outStr);
//ZWECIES_API const string & zwtestString(const string &inStr,const string &outStr);

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

//���������漰����β��Str�Ĳ���������Base64����HEX����֮һ��Ĭ��һ����Base64�Ա���ٲ�������
//����char�Ĳ�������ͨ�ַ�����
//��ʼ��ECIES��������˽Կ�͹�Կ
//password:�ַ�����ʽ�����룬����Կ�Ե�������ӣ�������ʱ������Ҫ
//outPriKeyStr��priLen��˽Կ���������ָ���Լ�����������
//outPublicKeyStr��pubLen�ǹ�Կ���������ָ���Լ�����������
//˽Կ�͹�Կ����������������Ȳ������Ļ���������أ�����ֵ��ECIES_ERROR���ö��
	ZWECIES_API int zwEciesKeyPairGen( const char *password,char *outPriKeyStr,const int priLen,
		char *outPublicKeyStr ,const int pubLen);

//ECIES���ܣ�
//pubkeyStr��������Ĺ�Կ	PlainText������
//����������������Ƿ�Ϊ3����Ŀ�ļ��ܽ���Լ�����
//����������������Ȳ������Ļ���������أ�����ֵ��ECIES_ERROR���ö��
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
	ZWECIES_API BOOL zwEciesDecrypt(const char *prikeyStr,char *outPlainText,const int plainLen, 
		const char *EncryptedSyncKeyStr,const char *MsgHashStr,const char *CryptedTextStr);
//int myTestEccMain();
//////////////////////////////�������ʺϰ�װ��C#ʹ�õĽӿ�////////////////////////////////////////////
//����ECIES��Կ/˽Կ�ԣ����ر�����Կ�Եȵȵ��ڲ����ݽṹ���
ZWECIES_API int		EciesGenKeyPair(void);
//ɾ��������Կ�Եȵȵ��ڲ����ݽṹ
ZWECIES_API void	EciesDelete(int eciesHandle);
//�Ӿ����ָ����ڲ����ݽṹ��ȡǰ�����ɺõĹ�Կ����Base64��ʽ�ַ��������������京�壬ԭ��͸������
ZWECIES_API string EciesGetPubKey(int eciesHandle);
//�Ӿ����ָ����ڲ����ݽṹ��ȡǰ�����ɺõ�˽Կ����Base64��ʽ�ַ��������������京�壬ԭ��͸������
ZWECIES_API string EciesGetPriKey(int eciesHandle);
//
//���������Լ�base64��ʽ�Ĺ�Կ������ֵ��base64�����3��Ԫ�ص���ϣ��������������壬ԭ��͸������
ZWECIES_API string EciesEncrypt(const string &pubKey,const string &plainText);
//������ܺ��������base64�����3��Ԫ�ص���ϵ����ģ��Լ�base64��ʽ��˽Կ����������
ZWECIES_API string EciesDecrypt(const string &priKey,const string &cryptText);

#ifdef  __cplusplus
}
#endif




#endif // zwEcies529_h__