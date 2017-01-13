#ifndef zwHidSplitMsg_h__
#define zwHidSplitMsg_h__
#ifdef __cplusplus
extern "C" {
#endif
//////////////////////////////////////////////////////////////////////////
	//�ýṹ��պ�����64�ֽ�
//JC_HID_TRANS_BYTES��ͬ��JCHID_FRAME_LENGTH�����߱��뱣��һ��
#define JC_HID_TRANS_BYTES		(64)	//HID�������ǵ���Ч�غɴ�С
//���ȥ�����ֽڱ�֤����HID�ײ����ݵ����
#define JC_HIDMSG_PAYLOAD_LEN	(JC_HID_TRANS_BYTES-3*(sizeof(unsigned short int)))
#define JC_HIDMSG_SPLIT_NUM		(12)		//����ж��ٿ�
	typedef struct jcMulPartMessage_t{		
		unsigned short int nIndex;	//�ڶ��ٿ�
		unsigned short int nTotalBlock;	//���ж��ٿ�		
		unsigned short int nDataLength;	//������Ч���ݳ���				
		unsigned char Data[JC_HIDMSG_PAYLOAD_LEN];
	}JC_MSG_MULPART;

typedef enum jcSplitStatus_t{
	JC_SP_OK,
	JC_SP_INPUT_NULL,
	JC_SP_OUTBUF_TOO_SHORT
}JC_SPLIT_STATUS;

//////////////////////////////////////////////////////////////////////////
//�����ڼ�������ֵȡֵ��С,�Ա�Ѹ�ٷ�������;20140917.1720
#define JC_MSG_MAXSIZE	(64*5)	//JSON��Ϣ������С�����ݼ���Ŀǰ����������С��272�ֽڣ������趨Ϊ64�ֽڵı���

extern JC_MSG_MULPART s_mpSplit[JC_HIDMSG_SPLIT_NUM];

//����һ���򵥵�����У���
int zwDataSum26(const char *Data,const int DataLen);
// ģ��htons�����������ֽ���ת�����ֽ���
unsigned short int HtoNs(unsigned short int h);
// ģ��ntohs�����������ֽ���ת�����ֽ���
unsigned short int NtoHs(unsigned short int n);
// ģ��htonl�����������ֽ���ת�����ֽ���
unsigned long int HtoNl(unsigned long int h);
// ģ��ntohl�����������ֽ���ת�����ֽ���
unsigned long int NtoHl(unsigned long int n);

//������������ָ��inData,����inDataLen��
//����ṹ�������׸���Աָ��outMsg���ṹ�������Ա����
//�������з�Ϊһ��������ṹ�壬���÷���HIDҪ���64�ֽڴ�С������ֱ�ӷ���
JC_SPLIT_STATUS jcMsgMulPartSplit(const char *inData,const int inLen,JC_MSG_MULPART outMsg[],const int outCount);
JC_SPLIT_STATUS jcMsgMulPartMerge(const JC_MSG_MULPART inMsg[],const int inCount,char *outData,int outLen);

#ifdef __cplusplus
}
#endif
#endif // zwHidSplitMsg_h__
