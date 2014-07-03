#include "stdafx.h"
#include <iostream>
using std::cout;
using std::endl;
#include "jclmsCCB2014.h"
using namespace zwTools;
using namespace jclms;
#include <vector>
#include <algorithm>
using std::vector;
using std::sort;
//�Ӱ������������ݵ��ַ������룬���һ��8λ���������
unsigned int zwBinString2Int32By8(const string &inStr);


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
	cout<<"aa="<<aa<<"len of aa ="<<aa.length()<<endl;
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

//���������ȡģ�������
void myBigNumModTest1()
{
	unsigned int aa=77778888,bb=88889999,cc=99998887;
	unsigned int rs=aa*bb % cc;
	cout<<aa<<"*"<<bb<<"%"<<cc<<"="<<rs<<endl;
}

void myBinString2intTest1()
{
	vector <unsigned int>res;
	string msg("zbouweiteststring201407031011c");
	for (int i=0;i<100;i++)
	{
		msg[0]=i;		
		unsigned int rv=zwBinString2Int32By8(msg);
		res.push_back(rv);
	}
	sort(res.begin(),res.end());
	for (size_t i=0;i<res.size();i++)
	{
		cout<<res[i]<<"\t";
	}
	cout<<endl;
}

