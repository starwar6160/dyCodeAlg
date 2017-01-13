#ifndef zwHidComm_h__
#define zwHidComm_h__

//20140922.1545.�ú궨���������⼸������ڼ���ʱ�л�HID��ԭʼ���з���Ϣ�Ĵ���ͨ�ţ�������������Ƶ���
#define ZWUSE_HID_MSG_SPLIT		//�Ƿ�ʹ��HID��64�ֽ���Ϣ�зַ���

#ifdef __cplusplus
extern "C" {
#endif

#define JCHID_SERIAL_LENGTH	(16)
#define JCHID_FRAME_LENGTH	(64)
#define JCHID_MESSAGE_MAXLENGTH	(JCHID_FRAME_LENGTH*5)
typedef struct jcHidCommon_t{
	unsigned short int vid;
	unsigned short int pid;
	char HidSerial[JCHID_SERIAL_LENGTH];	
	void * hid_device;	//Ϊ�˱���hid_device��HIDAPI���Ͷ�����ɢ���ⲿ�����䶨��Ϊvoid
} JCHID;

typedef enum jcHidStatus_t{
	JCHID_STATUS_OK,
	JCHID_STATUS_FAIL,
	JCHID_STATUS_INPUTNULL,
	JCHID_STATUS_HANDLE_NULL,
	JCHID_STATUS_RECV_ZEROBYTES
}JCHID_STATUS;

JCHID_STATUS jcHidOpen(JCHID *hid);
JCHID_STATUS jcHidClose(const JCHID *hid);
JCHID_STATUS jcHidSendData(JCHID *hid,const char *inData,const int inDataLen);

JCHID_STATUS jcHidRecvData(JCHID *hid,char *outData,
	const int outMaxLen,int *outLen,const int timeout);
//////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
}	//extern "C" {
#endif

#endif // zwHidComm_h__