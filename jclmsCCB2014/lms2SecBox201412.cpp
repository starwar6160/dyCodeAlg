#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "sm3.h"
#include "cJSON.h"
#include "jclmsCCB2014.h"

#include "dCodeHdr.h"
#include "zwhidComm.h"
#include "zwHidSplitMsg.h"
#include "zwSecretBoxAuth.h"

#define _DEBUG_USE_LMS_FUNC_CALL_20141202

void JCLMSCCB2014_API zwJclmsRsp( void * inLmsReq,const int inLmsReqLen,JCRESULT *lmsResult );

void myJcInputHton(JCINPUT *p)
{
	p->CodeGenDateTime=HtoNl(p->CodeGenDateTime);
	p->Validity=HtoNl(p->Validity);
	p->CloseCode=HtoNl(p->CloseCode);
	p->CmdType=static_cast<JCCMD>(HtoNl(p->CmdType));

	p->SearchTimeStart=HtoNl(p->SearchTimeStart);
	p->SearchTimeStep=HtoNl(p->SearchTimeStep);
	p->SearchTimeLength=HtoNl(p->SearchTimeLength);
	for (int i=0;i<NUM_VALIDITY;i++)
	{
		p->ValidityArray[i]=HtoNl(p->ValidityArray[i]);
	}
}

void myJcInputNtoh(JCINPUT *p)
{
	p->CodeGenDateTime=NtoHl(p->CodeGenDateTime);
	p->Validity=NtoHl(p->Validity);
	p->CloseCode=NtoHl(p->CloseCode);
	p->CmdType=static_cast<JCCMD>(NtoHl(p->CmdType));

	p->SearchTimeStart=NtoHl(p->SearchTimeStart);
	p->SearchTimeStep=NtoHl(p->SearchTimeStep);
	p->SearchTimeLength=NtoHl(p->SearchTimeLength);
	for (int i=0;i<NUM_VALIDITY;i++)
	{
		p->ValidityArray[i]=NtoHl(p->ValidityArray[i]);
	}
}

void myLmsReqZHton(JCLMSREQ *req)
{
	myJcInputHton(&req->inputData);
	req->Type=static_cast<JCLMSOP>(HtoNl(req->Type));
	req->dstCode=HtoNl(req->dstCode);
}

void myLmsReqZNtoh(JCLMSREQ *req)
{
	myJcInputNtoh(&req->inputData);
	req->Type=static_cast<JCLMSOP>(NtoHl(req->Type));
	req->dstCode=NtoHl(req->dstCode);
}

void myHexDump( const void * hidSendBuf,const int outLen )
{
	const char *pt=static_cast<const char *>(hidSendBuf);
	for (int i=0;i<outLen;i++)
	{
		if (i>0)
		{
			if(i%8==0 && i%16!=0)printf("\t");
			if(i%16==0)printf("\n");
		}
		unsigned char c=pt[i] & 0xFF;
		printf("%02X ",c);
	}
	printf("\n");
}

//һ�����㷨����ı�׼���ԣ������˶�̬�����ɺ���֤�������ڣ�����ARMУ���Լ��Ƿ��б������Ż�����ȵȣ�
//20141203.1001.��ΰ
int zwLmsAlgStandTest20141203(void)
{
	int handle=0;
	int pass1DyCode=0;
	handle = JcLockNew();
	JcLockSetString(handle, JCI_ATMNO, "atm10455761");
	JcLockSetString(handle, JCI_LOCKNO, "lock14771509");
	JcLockSetString(handle, JCI_PSK, "PSKDEMO728");
	//////////////////////////////////////////////////////////////////////////
	//�̶�����ʱ��,Ӧ�ó����̶��Ľ��
	const int ZWFIX_STARTTIME=1416*ZWMEGA;
	JcLockSetInt(handle,JCI_TIMESTEP,6);
	JcLockSetInt(handle,JCI_SEARCH_TIME_START,1416*ZWMEGA+127);
	JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_INIT_CLOSECODE);
	//////////////////////////////////////////////////////////////////////////
	JCRESULT lmsRsp;
	//printf("zwJclmsReqGenDyCode initCloseCode\n");
	int initCloseCode=0;
	initCloseCode=JcLockGetDynaCode(handle);
	//������һ���Լ���ԣ����ʧ�ܣ���˵���бȽϴ�������ˣ��������Ʒ�������
	//ARM�������Ż��������⵼�µ����ɴ���Ķ����ƴ���ȵ�
	if(38149728!=initCloseCode)
	{
		printf("initCloseCode Gen Error! JCLMS Algorithm GenDynaCode Self Check Fail! 20141203\n");
		return -1;
	}
	JcLockSetInt(handle, JCI_CLOSECODE, initCloseCode);
	JcLockSetInt(handle,JCI_DATETIME,1416*ZWMEGA);
	JcLockSetInt(handle,JCI_SEARCH_TIME_START,1416*ZWMEGA+127);
	JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_CCB_DYPASS1);
	pass1DyCode=JcLockGetDynaCode(handle);
	assert(57174184==pass1DyCode);
	JCMATCH pass1Match =
		JcLockReverseVerifyDynaCode(handle,pass1DyCode);
	if(ZWFIX_STARTTIME!=pass1Match.s_datetime)
	{
		printf("JcLockReverseVerifyDynaCode Error! JCLMS Algorithm Reverse DynaCode Self Check Fail! 20141203\n");
		return -2;
	}	
	//////////////////////////////////////////////////////////////////////////
	JcLockDelete(handle);
	return 0;
}

#ifdef _DEBUG_1205
void myLmsReq2Json( int lmsHandle, char * tmpjson )
{
	JCINPUT *jcp=reinterpret_cast<JCINPUT *>(lmsHandle);
	//zwJclmsReq2Json(jcp,tmpjson,ZWBUFLEN);
	cJSON *json,*jsReq;
	//����Ҫ��JCINPUT�ṹ��ת��ΪJSON�ڲ���ʽ
	zwJcInputConv2Json(&json,jcp);
	cJSON_AddItemToObject(json, "LMSRequest", jsReq=cJSON_CreateObject()); 
	cJSON_AddStringToObject(jsReq,"Type",     "JCLMS_CCB_CODEGEN");   
	char *cjout=cJSON_Print(json);
	strcpy(tmpjson,cjout);
	free(cjout);
	printf("%s jsonLen=%d\n%s\n",__FUNCTION__,strlen(tmpjson),tmpjson);
}
#endif // _DEBUG_1205


//�ú�������λ��ר��
//Input:void * inLmsReq:pointer of a JCLMSREQ struct
//input:const int inLmsReqLen:sizeof(JCLMSREQ)
//output:JCRESULT
void JCLMSCCB2014_API zwJclmsRsp( void * inLmsReq,const int inLmsReqLen,JCRESULT *lmsResult )
{
	//���ⲿ��������
	JCLMSREQ lmsReq;

	assert(NULL!=inLmsReq);
	assert(NULL!=lmsResult);
	if (NULL==inLmsReq || NULL==lmsResult)
	{
		return;
	}
#ifdef _DEBUG_USE_LMS_FUNC_CALL_20141202
	//PC����ʱ�����С������HID��Ч�غ�ͷ��+JCLMSREQ�Ĵ�С
	assert(sizeof(SECBOX_DATA_INFO)+sizeof(JCLMSREQ)==inLmsReqLen);
	//����HID��Ч�غ�ͷ��
	memcpy((void *)&lmsReq,(char *)inLmsReq+sizeof(SECBOX_DATA_INFO),inLmsReqLen-sizeof(SECBOX_DATA_INFO));
#else
	//��ARM�������С������JCLMSREQ��С
	assert(sizeof(JCLMSREQ)==inLmsReqLen);
	//����HID��Ч�غ�ͷ��
	memcpy((void *)&lmsReq,(char *)inLmsReq,inLmsReqLen);
#endif // _DEBUG_USE_LMS_FUNC_CALL_20141202

	myLmsReqZNtoh(&lmsReq);
	zwJcLockDumpJCINPUT((int)(&lmsReq));

	//ͨ�����νṹ�巵�ؼ��������ⲿ
	int dyCode=0;
	if (JCLMS_CCB_CODEGEN==lmsReq.Type)
	{
		dyCode=zwJcLockGetDynaCode((int)(&lmsReq.inputData));
		assert(dyCode>10*ZWMEGA);
		lmsResult->dynaCode=dyCode;
	}
	if (JCLMS_CCB_CODEVERIFY==lmsReq.Type)
	{
		JCMATCH jm=JcLockReverseVerifyDynaCode((int)(&lmsReq.inputData),lmsReq.dstCode);
		assert(jm.s_datetime>1400*ZWMEGA);
		assert(jm.s_validity>0 && jm.s_validity<=1440);
		memcpy((void *)&(lmsResult->verCodeMatch),(void *)&jm,sizeof(JCMATCH));
	}	
}

#ifdef _WIN32
void myHexDump(const void * hidSendBuf,const int outLen );
const int ZWHIDBUFLEN=512;
char g_dbg_hid_common1202[ZWHIDBUFLEN];

void myLmsReq2Json( int lmsHandle, char * tmpjson );

//����zwJclmsReq��������λ��ר��

//��д���handle��������ݽṹ�Ժ󣬵��øú������ɶ�̬�룬�ú����ڵײ㽫����
//ͨ��HID��ͨ����·���͵��ܺУ�Ȼ�����������ܺз��ؽ����ͨ�����η��أ�
int JCLMSCCB2014_API zwJclmsReqGenDyCode( int lmsHandle,int *dyCode )
{
	JCLMSREQ req;
	memset(&req,0,sizeof(JCLMSREQ));
	req.Type=JCLMS_CCB_CODEGEN;
	memcpy((void *)&req.inputData,(void *)lmsHandle,sizeof(JCINPUT));
	////////////////////////////JSON���л���ʼ//////////////////////////////////////////////
	const int ZWBUFLEN=640;
	char tmpjson[ZWBUFLEN];
	memset(tmpjson,0,ZWBUFLEN);
	//////////////////////////////////////////////////////////////////////////

	//myLmsReq2Json(lmsHandle, tmpjson);
	zwJclmsGenReq2Json(reinterpret_cast<JCINPUT *>(lmsHandle),tmpjson,ZWBUFLEN);
	JCLMSREQ req2t;
	zwJclmsReqDecode(tmpjson,&req2t);
	////////////////////////////JSON���л�����//////////////////////////////////////////////
	//////////////////////////////////ģ�ⷢ������////////////////////////////////////////
	//�˴�������ģ�⣬ʱ�򲻺ÿ��ƣ�Ϊ�˱��ڵ��ԣ��ڴ�ֱ�ӵ����ܺж˵ĺ���zwJclmsRsp��������
	printf("%s Send Data to Secbox for Gen DynaCode:\n",__FUNCTION__);
	zwJcLockDumpJCINPUT(lmsHandle);	
	//////////////////////////////////////////////////////////////////////////
	//��������HID�������ݰ������²�HID����ȥ�зֺͷ���
	char hidSendBuf[ZWHIDBUFLEN];
	memset(hidSendBuf,0,ZWHIDBUFLEN);
	//HID��Ч�غɵ�ͷ��
	const int outLen=sizeof(SECBOX_DATA_INFO)+sizeof(JCLMSREQ);
	SECBOX_DATA_INFO hidPayloadHeader;
	memset(&hidPayloadHeader,0,sizeof(SECBOX_DATA_INFO));
	hidPayloadHeader.data_index=1;
	hidPayloadHeader.msg_type=JC_SECBOX_LMS_GENDYCODE;
	hidPayloadHeader.data_len=sizeof(JCLMSREQ);
	hidPayloadHeader.data_len=HtoNs(hidPayloadHeader.data_len);
	//�ȼ���ͷ��
	memcpy(hidSendBuf,&hidPayloadHeader,sizeof(hidPayloadHeader));
	//Ȼ�����ʵ�ʵ����󲿷�
	myLmsReqZHton(&req);
	memcpy(hidSendBuf+sizeof(hidPayloadHeader),&req,sizeof(req));
	//printf("HidSend Data is(Net ByteOrder)\n");
	//myHexDump(hidSendBuf, outLen);
	//////////////////////////////////////////////////////////////////////////	
	JCRESULT rsp;
	memset(&rsp,0,sizeof(rsp));

#ifdef _DEBUG_USE_LMS_FUNC_CALL_20141202
	//����״̬��ֱ�ӵ�����λ����������
	zwJclmsRsp(hidSendBuf,outLen,&rsp);
#else
	JCHID hidHandle;
	memset(&hidHandle,0,sizeof(JCHID));
	hidHandle.vid=0x0483;
	hidHandle.pid=0x5710;

	if (JCHID_STATUS_OK != jcHidOpen(&hidHandle)) {
		return -1118;
	}
	jcHidSendData(&hidHandle,hidSendBuf,outLen);


	printf("GenWait To SecBox Return Result now..\n");
	int rspRealLen=0;
	jcHidRecvData(&hidHandle,(char *)&rsp,sizeof(rsp),&rspRealLen);
	printf("HidRecv Data is\n");
	myHexDump(&rsp, rspRealLen);

	assert(sizeof(rsp)==rspRealLen);
	if (sizeof(rsp)!=rspRealLen)
	{
		printf("Secbox Return of LMS result size not match JCRESULT!\n");
	}
	jcHidClose(&hidHandle);
#endif // _DEBUG_USE_LMS_FUNC_CALL_20141202
	//zwJclmsRsp(&req,sizeof(JCLMSREQ),&rsp);
	assert(0!=rsp.dynaCode);
	*dyCode=rsp.dynaCode;
	printf("%s Return dynaCode=%d\n",__FUNCTION__,rsp.dynaCode);

	return 0;
}


//��д���handle��������ݽṹ�Ժ󣬵��øú�����֤��̬�루��һ�͵ڶ���̬���м䣬�������ɵ�У����
//Ҳ��ʹ������������̬���ͬ���㷨���ɵģ�����Ҳ��һ�ֶ�̬�룬�ú����ڵײ㽫��֤����ͨ��HID��
//ͨ����·���͵��ܺУ�Ȼ�����������ܺз��ؽ����ͨ�����η��أ�
int JCLMSCCB2014_API zwJclmsReqVerifyDyCode( int lmsHandle,int dstCode,JCMATCH *match )
{
	JCLMSREQ req;
	memset(&req,0,sizeof(JCLMSREQ));
	req.Type=JCLMS_CCB_CODEVERIFY;
	req.dstCode=dstCode;
	memcpy((void *)&req.inputData,(void *)lmsHandle,sizeof(JCINPUT));

	//////////////////////////////////ģ�ⷢ������////////////////////////////////////////
	//�˴�������ģ�⣬ʱ�򲻺ÿ��ƣ�Ϊ�˱��ڵ��ԣ��ڴ�ֱ�ӵ����ܺж˵ĺ���zwJclmsRsp��������
	printf("%s Send Data to Secbox with Wait To Verify DestCode %d\n",__FUNCTION__,dstCode);
	zwJcLockDumpJCINPUT(lmsHandle);
	//////////////////////////////////////////////////////////////////////////
	//HID��Ч�غɵ�ͷ��
	const int outLen=sizeof(SECBOX_DATA_INFO)+sizeof(JCLMSREQ);
	SECBOX_DATA_INFO hidPayloadHeader;
	memset(&hidPayloadHeader,0,sizeof(SECBOX_DATA_INFO));
	hidPayloadHeader.data_index=1;
	hidPayloadHeader.msg_type=JC_SECBOX_LMS_VERDYCODE;
	hidPayloadHeader.data_len=sizeof(JCLMSREQ);
	hidPayloadHeader.data_len=HtoNs(hidPayloadHeader.data_len);
	//��������HID�������ݰ������²�HID����ȥ�зֺͷ���
	char hidSendBuf[ZWHIDBUFLEN];
	memset(hidSendBuf,0,ZWHIDBUFLEN);
	//�ȼ���ͷ��
	memcpy(hidSendBuf,&hidPayloadHeader,sizeof(hidPayloadHeader));
	//Ȼ�����ʵ�ʵ����󲿷�
	myLmsReqZHton(&req);
	memcpy(hidSendBuf+sizeof(hidPayloadHeader),&req,sizeof(req));
	//printf("HidSend Data is(Net ByteOrder)\n");
	//myHexDump(hidSendBuf, outLen);

	//////////////////////////////////////////////////////////////////////////
	JCRESULT rsp;
	memset(&rsp,0,sizeof(rsp));

#ifdef _DEBUG_USE_LMS_FUNC_CALL_20141202
	//����״̬��ֱ�ӵ�����λ����������
	zwJclmsRsp(hidSendBuf,outLen,&rsp);
#else
	JCHID hidHandle;
	hidHandle.vid=0x0483;
	hidHandle.pid=0x5710;
	if (JCHID_STATUS_OK != jcHidOpen(&hidHandle)) {
		return -1118;
	}
	jcHidSendData(&hidHandle,hidSendBuf,outLen);
	printf("VerWait To SecBox Return Result now..\n");
	int rspRealLen=0;
	jcHidRecvData(&hidHandle,(char *)&rsp,sizeof(rsp),&rspRealLen);
	printf("HidRecv Data is\n");
	myHexDump(&rsp, rspRealLen);
	assert(rsp.verCodeMatch.s_datetime>1400*ZWMEGA);
	assert(sizeof(rsp)==rspRealLen);
	if (sizeof(rsp)!=rspRealLen)
	{
		printf("Secbox Return of LMS result size not match JCRESULT!\n");
	}
	jcHidClose(&hidHandle);
#endif // _DEBUG_USE_LMS_FUNC_CALL_20141202
	memcpy((void *)match,(void *)&rsp.verCodeMatch,sizeof(JCMATCH));
	printf("%s Match DateTime=%d\tValidity=%d\n",__FUNCTION__,match->s_datetime,match->s_validity);	
	return 0;
}
#endif // _WIN32
