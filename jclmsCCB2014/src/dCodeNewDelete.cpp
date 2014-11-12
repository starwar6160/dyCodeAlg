#include "stdafx.h"
#include <time.h>
#include <memory.h>
#include "jclmsCCB2014.h"
#include "dCodeHdr.h"


//////////////////////////////////////////////////////////////////////////
int JCLMSCCB2014_API JcLockNew( void )
{
	JCINPUT *pjc=new JCINPUT;
	assert(pjc!=NULL);
	memset(pjc,0,sizeof(JCINPUT));
	memset(pjc->m_atmno,0,JC_ATMNO_MAXLEN+1);
	memset(pjc->m_lockno,0,JC_LOCKNO_MAXLEN+1);
	memset(pjc->m_psk,0,JC_PSK_LEN+1);
	//为没有可变输入的初始闭锁码指定3个常量
	pjc->m_datetime=1400*1000*1000;
	pjc->m_validity=5;		//用的最多的是5分钟有效期，所以直接初始化为
	pjc->m_closecode=0;		//防备初始闭锁码生成的时候此处未初始化
	pjc->m_cmdtype=JCCMD_INIT_CLOSECODE;
	pjc->m_stepoftime=6;	
	//默认在线模式，反推时间步长60秒.
	//20140805.0903.按照昨天张靖钰的要求，暂时改为5分钟默认值
	// 20140820.2329.按照建行要求从任意时间点开始5分钟有效期的要求，
	// 步长改为6秒 以便尽量接近该要求
	//默认在线模式，反推6分钟，比要求的5分钟多一点，保险一点
	pjc->m_reverse_time_length=9*60;	
	////将5分钟，4小时这样最常用到的有效期排列在前面，提高效率
	//int valarr[]={5,MIN_OF_HOUR*4,MIN_OF_HOUR*8,MIN_OF_HOUR*12,15,30,60,MIN_OF_HOUR*24};
	pjc->m_validity_array[0]=5;
	pjc->m_validity_array[1]=60*4;
	pjc->m_validity_array[2]=60*8;
	pjc->m_validity_array[3]=60*12;
	pjc->m_validity_array[4]=15;
	pjc->m_validity_array[5]=30;
	pjc->m_validity_array[6]=60;
	pjc->m_validity_array[7]=60*24;
	return (int)pjc;
}

int		JCLMSCCB2014_API JcLockDelete(const int handle)
{
	JCINPUT *jcp=(JCINPUT *)handle;
	assert(NULL!=jcp);
	if (NULL==jcp)
	{
		return EJC_INPUT_NULL;
	}
	memset(jcp,0xCC,sizeof(JCINPUT));
	delete jcp;
	return EJC_SUSSESS;
}

//时间GMT秒数转为字符串
static string zwTimeSecond2String(const time_t sec)
{
	char strTime[32];
	memset(strTime,0,32);
	struct tm *p;
	time_t tsec=sec;
	p=localtime(&tsec); 
	sprintf(strTime,"%04d.%02d%02d:%02d:%02d:%02d",
		(1900+p->tm_year),(1+p->tm_mon),p->tm_mday,
		p->tm_hour,p->tm_min,p->tm_sec);
	string rStr=strTime;
	return rStr;
}

void JCLMSCCB2014_API	zwJcLockDumpJCINPUT(const int handle)
{
	JCINPUT *jcp=(JCINPUT *)handle;
	assert(NULL!=jcp);
	if (NULL==jcp)
	{
		printf("%s input is NULL",__FUNCTION__);
		return ;
	}
	printf("########JCINPUT DUMP START############\n");
	printf("ATMNO:%s\t",jcp->m_atmno);
	printf("LOCKNO:%s\t",jcp->m_lockno);
	printf("PSK:%s\n",jcp->m_psk);
	printf("DATETIME:%d\t%s\n",jcp->m_datetime,zwTimeSecond2String(jcp->m_datetime).c_str());
	printf("VALIDITY:%d\tCloseCode:%d\t",jcp->m_validity,jcp->m_closecode);
	printf("CMDTYPE:");
	switch(jcp->m_cmdtype)
	{
	case JCI_ATMNO:
		printf("JCI_ATMNO");
		break;
	case JCI_LOCKNO:
		printf("JCI_LOCKNO");
		break;
	case JCI_PSK:
		printf("JCI_PSK");
		break;
	case JCI_DATETIME:
		printf("JCI_DATETIME");
		break;
	case JCI_VALIDITY:
		printf("JCI_VALIDITY");
		break;
	case JCI_CLOSECODE:
		printf("JCI_CLOSECODE");
		break;
	case JCI_CMDTYPE:
		printf("JCI_CMDTYPE");
		break;
	case JCI_TIMESTEP:
		printf("JCI_TIMESTEP");
		break;
	}
	printf("\n");
	printf("M_STEPOFTIME:%d\t",jcp->m_stepoftime);
	printf("M_REVERSE_TIME_LENGTH:%d\n",jcp->m_reverse_time_length);
	printf("M_VALIDITY_ARRAY:\n");
	for (int i=0;i<NUM_VALIDITY;i++)
	{
		printf("%d\t",jcp->m_validity_array[i]);
	}
	printf("\n########JCINPUT DUMP END############\n");
}

void JCLMSCCB2014_API JcLockDebugPrint( const int handle )
{
	JCINPUT *jcp=(JCINPUT *)handle;
	zwJcLockDumpJCINPUT(handle);
	if (EJC_SUSSESS!=JcLockCheckInput((const int)jcp))
	{
		printf("JcLock Input Para Error!\n");
	}	 		
	//三个固定条件组合在一起,还要为NULL，连接符等留出余量
	char mainstr[JC_ATMNO_MAXLEN+JC_LOCKNO_MAXLEN+JC_PSK_LEN+5];
	memset(mainstr,0,sizeof(mainstr));		
	sprintf(mainstr,"%s.%s.%s.",jcp->m_atmno,jcp->m_lockno,jcp->m_psk);
	//可变条件逐个化为字符串，组合到一起
	char vstr[40];	//大致把各个可变字段的位数估计一下
	int mdatetime=jcp->m_datetime;
	int mvalidity=jcp->m_validity;
	int mclosecode=jcp->m_closecode;
	if (JCCMD_INIT_CLOSECODE== jcp->m_cmdtype)
	{//如果是生成初始闭锁码，就用临时计算的值替代之
		myGetInitCloseCodeVarItem(&mdatetime,&mvalidity,&mclosecode);
	}		
	sprintf(vstr,"%d.%d.%d.%d",mdatetime,mvalidity,
		mclosecode,jcp->m_cmdtype
		//,jcp->m_stepoftime,jcp->m_reverse_time_length
		);
	//allItems=allItems+buf;
	char allStr[128];
	memset(allStr,0,128);
	strncpy(allStr,mainstr,128);
	strcat(allStr,vstr);
	printf("All Items = %s \n",allStr);
}
