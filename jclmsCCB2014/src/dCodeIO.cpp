#include "stdafx.h"
#include "jclmsCCB2014.h"
#include "dCodeHdr.h"

const int ZW_MAXDATA32=2048*ZWMEGA-3;	//32λ�з����������ܱ�ʾ�����ʱ��ֵ
const int ZW_LOWEST_DATE=1400*ZWMEGA-24*3600;	//���ǵ�ȡ���������ʹ��ʱ��ֵ����1400M�����԰���͵�ʱ����ǰһ������㹻��

//������������(��һ�����룬��ʼ������ȵ�)
JCERROR	JCLMSCCB2014_API JcLockSetCmdType(const int handle,const JCITYPE mtype,const JCCMD cmd)
{
	assert(handle>0);
	assert(mtype>JCI_START && mtype<JCI_END );
	assert(cmd>JCCMD_START && cmd<JCCMD_END);
	if (handle<=0 || mtype<=JCI_START || mtype>=JCI_END 
		|| cmd<=JCCMD_START || cmd>=JCCMD_END)
	{
		return EJC_INPUT_NULL;
	}
	JCINPUT *jcp=(JCINPUT *)handle;

	jcp->m_cmdtype=cmd;

	return EJC_SUSSESS;
}


//}	//end of namespace jclms

//�����ַ������͵�ֵ
JCERROR	JCLMSCCB2014_API JcLockSetString(const int handle,const JCITYPE mtype,const char *str)
{
	assert(handle>0);
	assert(mtype>JCI_START && mtype<JCI_END );
	assert(str!=NULL && strlen(str)>0);
	if (handle<=0 || mtype<=JCI_START || mtype>=JCI_END 
		|| str==NULL || strlen(str)==0)
	{
		return EJC_INPUT_NULL;
	}
	JCINPUT *jcp=(JCINPUT *)handle;
	switch (mtype)
	{
	case JCI_ATMNO:
		strncpy(jcp->m_atmno,str,sizeof(jcp->m_atmno));
		break;
	case JCI_LOCKNO:
		strncpy(jcp->m_lockno,str,sizeof(jcp->m_lockno));
		break;
	case JCI_PSK:
		strncpy(jcp->m_psk,str,sizeof(jcp->m_psk));
		break;
	}
	return EJC_SUSSESS;

}

//�����������͵�ֵ
JCERROR JCLMSCCB2014_API JcLockSetInt( const int handle,const JCITYPE mtype,int num )
{
	assert(handle>0);
	assert(mtype>JCI_START && mtype<JCI_END );
	assert(num>JC_INVALID_VALUE);
	if (handle<=0 || mtype<=JCI_START || mtype>=JCI_END || num <= JC_INVALID_VALUE)
	{
		return EJC_INPUT_NULL;
	}
	JCINPUT *jcp=(JCINPUT *)handle;
	assert(jcp->m_stepoftime>=6 && jcp->m_stepoftime<=24*3600);
	switch (mtype)
	{
	case JCI_DATETIME:
		//ʱ����뾭�����
		if (num<(1400*1000*1000))
		{
			return EJC_DATETIME_INVALID;
		}
		jcp->m_datetime=myGetNormalTime(num,jcp->m_stepoftime);
		break;
	case JCI_VALIDITY:
		assert(num>0 && num<=1440*7);
		if (num<=0 || num>(1440*7))
		{
			return EJC_VALIDRANGE_INVALID;
		}
		jcp->m_validity=num;
		break;
	case JCI_CLOSECODE:
		//assert(num>=10000000 && num<=99999999);
		//if (num<10000000 || num>99999999)
		//{
		//	return EJC_CLOSECODE_INVALID;
		//}
		jcp->m_closecode=num;
		break;
	case JCI_TIMESTEP:	//����ʱ�䲽��
		assert(num>=3 && num<=3600);
		if (num<0 || num > 3600)
		{
			return EJC_CMDTYPE_TIMESTEP_INVALID;
		}
		jcp->m_stepoftime=num;
		break;
	}
	return EJC_SUSSESS;
}


JCERROR JCLMSCCB2014_API JcLockCheckInput( const int handle )
{
	const int ZW_DIGI8_LOW=10*ZWMEGA;
	const int ZW_DIGI8_HIGH=100*ZWMEGA;
	JCINPUT *jcp=(JCINPUT *)handle;
	//�ٶ���Щ�����ֶ��ڶ����Ʋ��涼�ǵ�ͬ��int�ĳ��ȵģ��Ա�ͨ��һ��ͳһ�ĺ�������HASH����
	assert(sizeof(jcp->m_datetime)==sizeof(int));
	assert(sizeof(jcp->m_validity)==sizeof(int));
	assert(sizeof(jcp->m_closecode)==sizeof(int));
	assert(sizeof(jcp->m_cmdtype)==sizeof(int));

	assert(jcp->m_datetime>=(ZW_LOWEST_DATE) && jcp->m_datetime<ZW_MAXDATA32);
	assert(jcp->m_cmdtype>JCCMD_START && jcp->m_cmdtype<JCCMD_END);
	if (JCCMD_INIT_CLOSECODE!=jcp->m_cmdtype && JCCMD_CCB_CLOSECODE!=jcp->m_cmdtype)
	{	//���ɳ�ʼ������,�Լ�����������ʱ���������Ч�ںͱ������ֵ
		assert(jcp->m_validity>=0 && jcp->m_validity<=(24*60));
		//10,000,000 8λ����Ҳ����10-100M֮��
		assert(jcp->m_closecode>=ZW_DIGI8_LOW && jcp->m_closecode<=ZW_DIGI8_HIGH);
	}


	//�޶���С��14��ͷ��ʱ��(1.4G��)���߿�Ҫ����ZW_MAXDATA32��Ļ����ǷǷ���
	if (jcp->m_datetime<(ZW_LOWEST_DATE) || jcp->m_datetime>ZW_MAXDATA32)
	{//����ʱ��������2014���ĳ��1.4G��֮ǰ�����ӣ����߳���2038��(32λ�з����������ֵ)����Ч
		return EJC_DATETIME_INVALID;
	}
	if (JCCMD_INIT_CLOSECODE!=jcp->m_cmdtype && JCCMD_CCB_CLOSECODE!=jcp->m_cmdtype)
	{	//���ɳ�ʼ������,�Լ�����������ʱ���������Ч�ںͱ������ֵ
		if (jcp->m_validity<0 || jcp->m_validity>(24*60))
		{//��Ч�ڷ�����Ϊ�������ߴ���һ��������Ч
			return EJC_VALIDRANGE_INVALID;
		}
		if (jcp->m_closecode<ZW_DIGI8_LOW || jcp->m_closecode>ZW_DIGI8_HIGH)
		{//������С��8λ���ߴ���8λ����Ч
			return EJC_CLOSECODE_INVALID;
		}
	}	//if (JCCMD_INIT_CLOSECODE!=jcp->m_cmdtype)
	if (jcp->m_stepoftime<=0 || jcp->m_stepoftime>=(24*60*60))
	{//��������Ϊ�������ߴ���һ��������Ч
		return EJC_CMDTYPE_TIMESTEP_INVALID;
	}
	if (jcp->m_reverse_time_length<=0 || jcp->m_reverse_time_length>=(365*24*60*60))
	{//��ǰ����ʱ��Ϊ�������ߴ���һ��������Ч
		return EJC_CMDTYPE_TIMELEN_INVALID;
	}

	if (jcp->m_cmdtype<=JCCMD_START || jcp->m_cmdtype>=JCCMD_END)
	{
		return EJC_CMDTYPE_INVALID;
	}
	return EJC_SUSSESS;
}


