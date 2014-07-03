// ccbTest702.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <iostream>
using std::cout;
using std::endl;

#include "jclmsCCB2014.h"

void myJcLockInputTest1();

void zwSm3HmacTest2();

void myStringTest1();


using namespace zwTools;
using namespace jclms;

int _tmain(int argc, _TCHAR* argv[])
{
	myJcLockInputTest1();
	zwSm3HmacTest2();

	myStringTest1();


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
	const char *msga="myplaintexttest201407021710.myplaintexttest201407021742";
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

//����std::string���ں���0�ַ��Ķ��������ݵĴ�������
void myStringTest1()
{
	const int BUFSIZE=16;
	string aa,bb,cc;
	char buf[BUFSIZE];
	char b2[BUFSIZE];
	memset(buf,'A',BUFSIZE);
	memset(b2,'B',BUFSIZE);
	buf[6]=NULL;
	b2[10]=NULL;
	//assign������ȷ��ֵ����0�ַ��Ķ���������
	aa.assign(buf,BUFSIZE);
	bb.assign(b2,BUFSIZE);
	//+�����������ȷ������0�ַ��Ķ���������
	cc=aa+bb;
	cout<<"aa="<<aa<<endl;
	cout<<"bb="<<bb<<endl;
	cout<<"cc="<<cc<<endl;
	//=�������������0�ַ��Ķ��������ݻ�ض�
	aa=buf;
	bb=b2;
	cc=aa+bb;
	cout<<"aa="<<aa<<endl;
	cout<<"bb="<<bb<<endl;
	cout<<"cc="<<cc<<endl;
}

