// jclmsCCB2014.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
#include "jclmsCCB2014.h"
#include "hashalg\\sm3.h"

namespace jclms{
int myGetDynaCodeImpl( const JcLockInput &lock );
//�Ӱ������������ݵ��ַ������룬���һ��8λ���������
unsigned int zwBinString2Int32(const char *data,const int len);

	void mySm3Process(SM3 *ctx,const char *data,const int len)
	{
		assert(ctx!=NULL);
		assert(ctx->length>0);
		assert(data!=NULL);
		assert(len>0);
		for (int i=0;i<len;i++)
		{
			SM3_process(ctx,*(data+i));
		}
	}

	void mySm3Process(SM3 *ctx,const int data)
	{
		assert(ctx!=NULL);
		assert(ctx->length>0);
		assert(data>=0);	//������������������0����������
		int td=data;
		for (int i=0;i<sizeof(data);i++)
		{
			unsigned char t=td & 0xff;
			SM3_process(ctx,t);
			td=td>>8;
		}
		assert(td==0);
	}

	int zwGetDynaCode(const JcLockInput &lock)
	{
		return myGetDynaCodeImpl(lock);
	}

	jclms::JCERROR zwVerifyDynaCode( const JcLockInput &lock,const int dstDyCode )
	{
		int calCode= myGetDynaCodeImpl(lock);
		if (calCode==dstDyCode)
		{
			return EJC_SUSSESS;
		}
		else
		{
			return EJC_FAIL;
		}
	}

	//�Ӱ������������ݵ��ַ������룬���һ��8λ���������
	unsigned int zwBinString2Int32(const char *data,const int len)
	{
		//��1��ͷ��8λ����΢СһЩ������
		const int dyLow=10000019;
		//�ȿ�ͷ��8λ����΢СһЩ������
		const int dyMod=89999981;	
		const int dyMul=257;	//����ҵ�һ��������Ϊ��˵�����
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


//////////////////////////////////////////////////////////////////////////
	JcLockInput::JcLockInput()
	{
		m_atmno="";
		m_lockno="";
		m_psk="";
		m_datetime=-1;
		m_validity=-1;
		m_closecode=-1;	
		m_cmdtype=JCCMD_INVALID;
		m_status=EJC_FAIL;
	}

	void JcLockInput::DebugPrint()
	{
		if (EJC_SUSSESS!=CheckInput())
		{
			printf("JcLock Input Para Error!\n");
		}
		 
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
		printf("All Items = %s \n",allItems.c_str());
	}

	JCERROR JcLockInput::CheckInput()
	{
		JCERROR status=EJC_SUSSESS;
		if (m_atmno=="")
		{
			status=EJC_INPUT_NULL;
		}
		if (m_lockno=="")
		{
			status=EJC_INPUT_NULL;
		}
		if (m_psk=="")
		{
			status=EJC_INPUT_NULL;
		}
		if (m_datetime<0)
		{
			status=EJC_INPUT_NULL;
		}
		if (m_validity<0)
		{
			status=EJC_INPUT_NULL;
		}
		if (m_closecode<0)
		{
			status=EJC_INPUT_NULL;
		}
		if (m_cmdtype==JCCMD_INVALID)
		{
			status=EJC_INPUT_NULL;
		}

		m_status=status;
		return status;
	}

	int myGetDynaCodeImpl( const JcLockInput &lock )
	{
		SM3 sm3;
		char outHmac[ZW_SM3_DGST_SIZE];
		SM3_init(&sm3);
		/////////////////////////////���Ԫ�ؽ���HASH����/////////////////////////////////////////////
		mySm3Process(&sm3,lock.m_atmno.data(),lock.m_atmno.size());
		mySm3Process(&sm3,lock.m_lockno.data(),lock.m_lockno.size());
		mySm3Process(&sm3,lock.m_psk.data(),lock.m_psk.size());

		int l_datetime=lock.m_datetime;
		int l_validity=lock.m_validity;
		int l_closecode=lock.m_closecode;	
		if (JCCMD_INIT_CLOSECODE==lock.m_cmdtype)
		{
			l_datetime=1400000000;	//��ʼ���������һ������Ĺ̶�ֵ��Ϊʱ��
			l_validity=0;	//��ʼ��������ѡһ���Ϸ���Ч��֮���ֵ
			l_closecode=0;	//��ʼ��������ѡһ���Ƿ�������			
		}
		mySm3Process(&sm3,l_datetime);
		mySm3Process(&sm3,l_validity);
		mySm3Process(&sm3,l_closecode);
		mySm3Process(&sm3,lock.m_cmdtype);
		//////////////////////////////HASH�������////////////////////////////////////////////
		memset(outHmac,0,ZWSM3_DGST_LEN);
		SM3_hash(&sm3,(char *)(outHmac));
		unsigned int res=zwBinString2Int32(outHmac,ZWSM3_DGST_LEN);
		return res;
	}

}
