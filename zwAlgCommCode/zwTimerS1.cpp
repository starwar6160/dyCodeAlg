//#include "stdafx.h"
#include <stdio.h>
#include "zwTimerHdr.h"
zwTrace1027::zwTrace1027(const char *strClassName)
{
	m_strClass=(char *)strClassName;
	memset(m_buf,0,64);
	sprintf(m_buf,"%s [START]",m_strClass);		
	OutputDebugStringA(m_buf);
	QueryPerformanceCounter(&nStart);
}

float zwTrace1027::DiffTime()
{
	LARGE_INTEGER nCur;
	QueryPerformanceCounter(&nCur);
	memset(m_buf,0,64);				
	LARGE_INTEGER nPerf;
	QueryPerformanceFrequency(&nPerf);
	//ʵ�ʸ߾��ȼ�ʱ������һ�㶼��1.2M��2.8M���ң�Ҳ���Ƕ����Ծ�ȷ��0.9-0.4΢�����ң�
	double fLifeMs=(nCur.QuadPart-nStart.QuadPart)*1000.0/nPerf.QuadPart;
	sprintf(m_buf,"%s [CURTIME DIFF]  %.1f ms",m_strClass,fLifeMs);		
	OutputDebugStringA(m_buf);
	printf("%s\n",m_buf);
	return (float)(fLifeMs);
}

zwTrace1027::~zwTrace1027()
{
	QueryPerformanceCounter(&nEnd);
	memset(m_buf,0,64);				
	LARGE_INTEGER nPerf;
	QueryPerformanceFrequency(&nPerf);
	//ʵ�ʸ߾��ȼ�ʱ������һ�㶼��1.2M��2.8M���ң�Ҳ���Ƕ����Ծ�ȷ��0.9-0.4΢�����ң�
	double fLifeMs=(nEnd.QuadPart-nStart.QuadPart)*1000.0/nPerf.QuadPart;
	if (fLifeMs>1.0f)
	{
		sprintf(m_buf,"%s [END] elps %.1f ms",m_strClass,fLifeMs);		
	}
	else
	{
		sprintf(m_buf,"%s [END] elps %.0f us",m_strClass,fLifeMs*1000);		
	}

	OutputDebugStringA(m_buf);
	printf("%s\n",m_buf);
	//pocoLog->information()<<m_buf<<endl;
}
