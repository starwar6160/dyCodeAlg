// jclmsCCB2014.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include "jclmsCCB2014.h"


// ���ǵ���������һ��ʾ��
JCLMSCCB2014_API int njclmsCCB2014=0;

// ���ǵ���������һ��ʾ����
JCLMSCCB2014_API int fnjclmsCCB2014(void)
{
	return 42;
}

// �����ѵ�����Ĺ��캯����
// �й��ඨ�����Ϣ������� jclmsCCB2014.h
CjclmsCCB2014::CjclmsCCB2014()
{
	return;
}

namespace jclms{
	void JcLockInput::print()
	{
		string conn=".";	//���ַ���
		//�����̶����������һ��
		string allItems=m_atmno+conn+m_lockno+conn+m_psk+conn;
		//�ɱ����������Ϊ�ַ�������ϵ�һ��
#define BLEN (16)
		char buf[BLEN];
		memset(buf,0,BLEN);
		sprintf(buf,"%d",m_datetime);
		allItems=allItems+buf+conn;
		memset(buf,0,BLEN);
		sprintf(buf,"%d",m_validity);
		allItems=allItems+buf+conn;
		memset(buf,0,BLEN);
		sprintf(buf,"%d",m_closecode);
		allItems=allItems+buf+conn;
		memset(buf,0,BLEN);
		sprintf(buf,"%d",m_cmdtype);
		allItems=allItems+buf;
		cout<<allItems<<endl;			
	}
}
