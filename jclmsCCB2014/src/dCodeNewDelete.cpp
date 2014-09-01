#include "stdafx.h"
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
	//Ϊû�пɱ�����ĳ�ʼ������ָ��3������
	pjc->m_datetime=1400*1000*1000;
	pjc->m_validity=5;		//�õ�������5������Ч�ڣ�����ֱ�ӳ�ʼ��Ϊ
	pjc->m_closecode=0;		//������ʼ���������ɵ�ʱ��˴�δ��ʼ��
	pjc->m_cmdtype=JCCMD_INIT_CLOSECODE;
	pjc->m_stepoftime=6;	
	//Ĭ������ģʽ������ʱ�䲽��60��.
	//20140805.0903.���������ž��ڵ�Ҫ����ʱ��Ϊ5����Ĭ��ֵ
	// 20140820.2329.���ս���Ҫ�������ʱ��㿪ʼ5������Ч�ڵ�Ҫ��
	// ������Ϊ6�� �Ա㾡���ӽ���Ҫ��
	//Ĭ������ģʽ������6���ӣ���Ҫ���5���Ӷ�һ�㣬����һ��
	pjc->m_reverse_time_length=6*60;	
	////��5���ӣ�4Сʱ������õ�����Ч��������ǰ�棬���Ч��
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

void JCLMSCCB2014_API JcLockDebugPrint( const int handle )
{
	JCINPUT *jcp=(JCINPUT *)handle;
	if (EJC_SUSSESS!=JcLockCheckInput((const int)jcp))
	{
		printf("JcLock Input Para Error!\n");
	}	 		
	//�����̶����������һ��,��ҪΪNULL�����ӷ�����������
	char mainstr[JC_ATMNO_MAXLEN+JC_LOCKNO_MAXLEN+JC_PSK_LEN+5];
	memset(mainstr,0,sizeof(mainstr));		
	sprintf(mainstr,"%s.%s.%s.",jcp->m_atmno,jcp->m_lockno,jcp->m_psk);
	//�ɱ����������Ϊ�ַ�������ϵ�һ��
	char vstr[40];	//���°Ѹ����ɱ��ֶε�λ������һ��
	int mdatetime=jcp->m_datetime;
	int mvalidity=jcp->m_validity;
	int mclosecode=jcp->m_closecode;
	if (JCCMD_INIT_CLOSECODE== jcp->m_cmdtype)
	{//��������ɳ�ʼ�����룬������ʱ�����ֵ���֮
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
