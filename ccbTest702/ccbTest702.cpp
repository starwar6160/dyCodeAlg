// ccbTest702.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include <iostream>
using std::cout;
using std::endl;


void myJcLockInputTest1();
void zwSm3HmacTest2();
void myStringTest1();
void myBigNumModTest1();

//�Ӱ������������ݵ��ַ������룬���һ��8λ���������
unsigned int zwBinString2Int32By8(const string &inStr)
{
	//��1��ͷ��8λ����΢СһЩ������
	const int dyLow=10000019;
	//�ȿ�ͷ��8λ����΢СһЩ������
	const int dyMod=89999981;	
	int len=inStr.length();
	//int tail=len % (sizeof(int));
	const char *data=inStr.data();
	unsigned int sum=0;
	for (int i=0;i<len;i++)
	{
		unsigned char t=*(data+i);
		sum+=t;
		sum*=97;
	}
	//���������ֽ��ʹ�ã������϶���8λ���Ķ�̬��
	sum %=89999981;
	sum +=dyLow;
	return sum;
}

int _tmain(int argc, _TCHAR* argv[])
{
	//myJcLockInputTest1();
	//zwSm3HmacTest2();
	//myStringTest1();
	//myBigNumModTest1();
	string msg("zhouweiteststring201407031011b");
	for (int i=0;i<100;i++)
	{
		msg[0]=i;
		//cout<<"zwBinString2Int32By8 result=\t"<<zwBinString2Int32By8(msg)<<endl;
		cout<<zwBinString2Int32By8(msg)<<"\n";
	}


	return 0;
}

