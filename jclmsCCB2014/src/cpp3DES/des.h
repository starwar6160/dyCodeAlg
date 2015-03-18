#ifndef des_h__
#define des_h__

#include <stdint.h>
#ifdef  __cplusplus
extern "C" {
#endif

#define ui64 uint64_t
#define ui32 uint32_t
#define ui8  uint8_t

typedef enum {
	JC3DES_OK,	//�ɹ�����
	JC3DES_KEY_INVALID_LENGTH,	//��Կ���ȷǷ�
	JC3DES_KEY_NONHEX,			//��Կ����HEX�ַ���
	JC3DES_KEY_WEAKKEY,			//��Կ��DES����Կ
	JC3DES_DYCODE_OUTOFRANGE,	//��̬�뷶Χ������Ч��Χ
	JC3DES_OUTBUF_NULL			//���������Ϊ��
}JC3DES_ERROR;

//�ж������ַ����Ƿ���HEX�ַ���������ǣ�����HEX�ַ������ȣ�������ǣ�����0
int myHexStringLength(const char *hexStr);
//��ⳣ��DES����Կ��������64bit/16HEX�ַ���DES��Կ
JC3DES_ERROR myIsDESWeakKey(const char *desKey);

//ʹ�ý��е�ͨѶ������ԿccbComm3DESKeyHex��8λ��̬��dyCode���ܣ������ڳ���outEncDyCodeHex��
//����ͨѶ������Կ���Լ����ܽ������HEX�ַ�������̬��������
JC3DES_ERROR zwCCB3DESEncryptDyCode(const char *ccbComm3DESKeyHex,const int dyCode,char *outEncDyCodeHex);

#ifdef  __cplusplus
}	//extern "C" {
#endif

#endif // des_h__
