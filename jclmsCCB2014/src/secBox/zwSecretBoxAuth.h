#ifndef zwSecretBoxAuth_h__
#define zwSecretBoxAuth_h__
#include "zwSecBoxCSHdr.h"
//��֤Э�飺�����������������ֽ���
//��Э����ֻʹ��short int����Ϊ��������С��
//Ϊ�˱�������ͽṹ��ն��������������ֶ���2�ֽڵ�short int,���ⰲ�ŵĲ�������ն��Ľṹ���Ա�ֲ�
//Э�����ͣ�ʹ��ö��JC_SECBOX_TYPE������μ�����
//����5�����ݰ�����һ������+���ȵĺϼ�4�ֽ�ͷ����
//Ȼ����֤�����Ӧ�����Ч�غɲ��ֶ���20�ֽ�+20�ֽڶ������������,ʵ���϶���SHA1��HASH�㷨���ɵ�
//���ݶ�д��3���͵İ�����ȡ�����û����Ч�غɣ�ֻ��ͷ����
//��ȡ��д��İ������涼���޸�ʽ����������(��Ȼ�ı�����Ҳ��ȫ���Ա�������������������д)
//Ϊ�˱�̷��㣬���������нṹ����Ϊ�������ݸ�ʽ�ľ���ʵ�ַ�ʽ����ȻҲ����ֱ�Ӱ���ƫ��ֵ����д��Э���ʽ������


#define SHA1DGSTLEN	(160/8)	//SHA1�Ľ��������160bitҲ����20�ֽ�
typedef struct _jc_secbox_data_info_2014{
	unsigned char msg_type;			//������
	unsigned char data_index;	//���ݱ��
	short int data_len;	//�������������ݵĳ���
}SECBOX_DATA_INFO;

typedef struct _jc_secbox_auth_201410{
	char rand_data[SHA1DGSTLEN];		//һ��160bit�����
	char sha1_dgst[SHA1DGSTLEN];		//ǰ�ߺ�PSK��������SHA1ֵ
}SECBOX_AUTH;


typedef enum _jc_secbox_package_t{
	JC_SECBOX_AUTH_REQUEST,		//��֤����
	JC_SECBOX_AUTH_RESPONE,		//��֤�ظ�
	JC_SECBOX_DATA_READ_REQUEST,//���ݶ�ȡ����
	JC_SECBOX_DATA_READ_PAYLOAD,//���ݶ�ȡ�ظ���������	
	JC_SECBOX_DATA_WRITE,		//����д��
	//JC_SECBOX_ALG_3DES_ENC,		//3DES����
	//JC_SECBOX_ALG_3DES_DEC,		//3DES����
	//JC_SECBOX_DYCODE_INITCLOSECODE,	//��ʼ������
	//JC_SECBOX_DYCODE_CLOSECODE,		//������
	//JC_SECBOX_DYCODE_DYPASS1,	//��һ������
	//JC_SECBOX_DYCODE_VERCODE,	//У����
	//JC_SECBOX_DYCODE_DYPASS2,	//�ڶ�������
	JC_SECBOX_LMS_GENDYCODE,	//LMS���ɶ�̬�����ݰ�
	JC_SECBOX_LMS_VERDYCODE		//LMS��֤��̬�����ݰ�

}JC_SECBOX_TYPE;



extern const unsigned char  SECBOXPSK2014D[SHA1DGSTLEN];	//һ��160bit��PSK������λ����ͬ���ܳ���,��λ��ʹ��
extern const unsigned char  SECBOXPSK2014Z[SHA1DGSTLEN];	//һ��160bit��PSK������λ����ͬ���ܳ��У���λ��ʹ��

//HID֡�ĸ�ʽ��
//ͷ2���ֽ���һ��SHORT INT��ʵ������JC_SECBOX_TYPEö�ٵ�ֵ���϶��������
//��������������ݸ�ֵ��ָʾ���ǲ�ͬ���͵ı��Ľṹ��

#ifdef __cplusplus
extern "C" {
#endif
	//�����������֤����,�Լ���֤�ظ��������SECBOX_AUTH�ṹ�壬�ΪHID֡����64�ֽ�
	//ԭ�����ڣ�����λ��������һ�������+��ͬ���в����ܵ�PSK����һ��SHA1�����
	//Ȼ����������SHA1��������Է���Ϊ��֤�ķ�ʽ
	void zwSecboxAuthDataGen(SECBOX_AUTH *req);
	//��������Ļظ���֤Ӧ��,�����SECBOX_AUTH�ṹ�壬�ΪHID֡����64�ֽ�
	//����0������֤�ɹ�������ֵ����ʧ�ܣ�
	//�����Ӧ��ͨ��ͬһ���ṹ��req�������
	int zwSecboxAuthVerify(SECBOX_AUTH *req);
	//���ɰ���ǰ����2�ֽڡ������͡����ڵ��ܺ���Ȩ�����Ӧ���ֽڴ�����HID����
	void zwSecboxAuthByteGen(char *outReq,int *outLen,JC_SECBOX_TYPE type);
//////////////////////////////////////////////////////////////////////////
	//����PC���ܺе�����д�������뱣֤���������������"SECBOX_DATA_INFO+ʵ�����ݳ���"��ô��
	void pc2BoxDataWriteRequest(const unsigned char index,const char *inData,const int inLen,
		char *outBuf,int *outLen);
	//����PC���ܺе����ݶ�ȡ�����뱣֤���������������SECBOX_DATA_INFO��ô��
	//indexָ����ȡ���ٺ�����
	void pc2BoxDataReadRequest(const unsigned char index, char *outBuf,int *outLen);
	//�����ܺз��صĶ�ȡ���ݣ�������������ݺͳ���
	void box2PcDataParse(const char *inData,const int inLen,
		char *outBuf,int *outLen);



//////////////////////////////////////////////////////////////////////////
	void zwSecretBoxAuthTest1015A(void);
	void myDumpPsk1016(void);

#ifdef __cplusplus
}
#endif

#endif // zwSecretBoxAuth_h__

