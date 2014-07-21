#include "stdafx.h"
#include <iostream>
#include <cassert>
using std::cout;
using std::endl;
#include "jclmsCCB2014.h"
#include "zwTools1.h"
using namespace zwTools;
//using namespace jclms;
#include <vector>
#include <algorithm>
#include <set>
using std::set;
using std::vector;
using std::sort;


//��������дJcLockInput�ṹ�岢����Ĳ���
void myJcLockInputTest1()
{
	JcLockInput aa;
	aa.m_atmno="atmnoddddddddsssssssssssssssssssss";
	aa.m_lockno="locknossssssssssssa1";
	aa.m_psk="pskaaaabbbbbccccsssssssssssssssssssssssssssssssssssss";
	//ע�����ںϷ���ʱ��ֵӦ����1.4G�����ˣ�ע��λ����20140721.1709
	aa.m_datetime=1400077751;
	aa.m_validity=5;
	aa.m_closecode=87654325;
	aa.m_cmdtype=JCCMD_CCB_DYPASS1;
	aa.DebugPrint();
	set <int> rset;
	//������������40K����������ʱ�ظ��ڸ�λ����13K�����ظ�
	//��1��9����ͷ�ֲ����棬��ǧ��ʱƫ����10%���ڣ�
	//�����ʱƫ��3.5%���ڣ�Ҳ����˵��������
	const int RCOUNT=900*3;
	int head[10];
	for (int i=0;i<10;i++)
	{
		head[i]=0;
	}
	for (int i=0;i<RCOUNT;i++)
	{
		aa.m_datetime++;
		int dycode=zwGetDynaCode(aa);
		rset.insert(dycode);
		if (i % (RCOUNT/32) ==0)
		{
			cout<<dycode<<"\t";
		}
		int hd=dycode /10000000;
		assert(hd>=0 && hd <=9);
		head[hd]++;
	}
	cout<<endl;
	int realSize=rset.size();
	cout<<"Total Item is "<<RCOUNT<<"\t";
	cout<<"Dups Item is "<<RCOUNT-realSize<<endl;
	for (int i=1;i<10;i++)
	{
		cout<<i<<":"<<head[i]*100.0f/(RCOUNT/9)<<"\n";
	}
}

#ifdef _DEBUG_USE_OLD_SM3HMAC20140703
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
#endif // _DEBUG_USE_OLD_SM3HMAC20140703

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

#ifdef _DEBUG_BINTEST703
void myBinString2intTest1()
{
	vector <unsigned int>res;
	char  msg[]="zbouweiteststring201407031011c";
	int msglen=sizeof(msg);
	for (int i=0;i<100;i++)
	{
		msg[0]=i;		
		unsigned int rv=zwBinString2Int32(msg,msglen);
		res.push_back(rv);
	}
	sort(res.begin(),res.end());
	cout<<"*******************\n";
	for (size_t i=0;i<res.size();i++)
	{
		cout<<res[i]<<"\t";
	}
	cout<<endl;
}
#endif // _DEBUG_BINTEST703

