// ccbTest702.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "jclmsCCB2014.h"

int _tmain(int argc, _TCHAR* argv[])
{
	jclms::JcLockInput aa;
	aa.m_atmno="atmno";
	aa.m_lockno="lockno";
	aa.m_psk="pskaaaabbbbbcccc";
	aa.m_datetime=140007775;
	aa.m_validity=240;
	aa.m_closecode=87654321;
	aa.m_cmdtype=0;
	aa.print();
	return 0;
}

