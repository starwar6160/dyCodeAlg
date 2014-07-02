// ccbTest702.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "jclmsCCB2014.h"

void myJcLockInputTest1();

void zwSm3HmacTest2();



using namespace jclms;

int _tmain(int argc, _TCHAR* argv[])
{
	myJcLockInputTest1();
	zwSm3HmacTest2();

	return 0;
}

//��������дJcLockInput�ṹ�岢����Ĳ���
void myJcLockInputTest1()
{
	JcLockInput aa;
	aa.m_atmno="atmno";
	aa.m_lockno="lockno";
	aa.m_psk="pskaaaabbbbbcccc";
	aa.m_datetime=140007775;
	aa.m_validity=240;
	aa.m_closecode=87654321;
	aa.m_cmdtype=0;
	aa.DebugPrint();
}

//�����Ƶ�SM3HMAC����
void zwSm3HmacTest2()
{
	const char *pska="mypskaaabbbcccdddeee";
	const char *msga="myplaintexttest201407021710.myplaintexttest201407021710";
	char tbuf[ZW_SM3_DGST_SIZE];
	memset(tbuf,0,ZW_SM3_DGST_SIZE);
	zwHexTool psk(pska,strlen(pska));
	zwHexTool msg(msga,strlen(msga));
	zwHexTool hmac(tbuf,ZW_SM3_DGST_SIZE);

	printf("Init Value of hmac\n");
	hmac.PrintBin();
	zwSm3Hmac7(psk,msg,hmac);
	printf("Result Value of hmac\n");
	hmac.PrintBin();
}

