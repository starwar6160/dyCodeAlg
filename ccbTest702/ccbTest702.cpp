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
	const int dyMul=257;	//����ҵ�һ��������Ϊ��˵�����
	int len=inStr.length();
	//int tail=len % (sizeof(int));
	const char *data=inStr.data();
	unsigned int sum=0;
	for (int i=0;i<len;i++)
	{
		unsigned char t=*(data+i);
		sum*=257;
		sum+=t;		
	}
	//���������ֽ��ʹ�ã������϶���8λ���Ķ�̬��
	sum %=89999981;
	sum +=dyLow;
	return sum;
}

void myBinString2intTest1();

int _tmain(int argc, _TCHAR* argv[])
{
	myJcLockInputTest1();
	//zwSm3HmacTest2();
	//myStringTest1();
	//myBigNumModTest1();
	//myBinString2intTest1();


	return 0;
}

