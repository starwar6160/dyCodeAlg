// jclmsCCB2014.cpp : ���� DLL Ӧ�ó���ĵ���������
//
#include "stdafx.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "jclmsCCB2014.h"
#include "sm3.h"

typedef struct JcLockInput
{
	//�̶����ز���
	char m_atmno[JC_ATMNO_MAXLEN+1];		//ATM��
	char m_lockno[JC_LOCKNO_MAXLEN+1];	//����
	char m_psk[JC_PSK_LEN+1];			//PSK������λ����ͬ���е�Ψһ��������
	//�ɱ����ز���
	int m_datetime;		//����ʱ��
	int m_validity;		//��Ч��
	int m_closecode;	//������		
	JCCMD m_cmdtype;		//ģʽ���룬���翪��ģʽ��Զ������ģʽ�����е�����Ҫ��ĸ���ģʽ�ȵ�
	///////////////////////////////////����Ϊ�����㷨����ģʽ������///////////////////////////////////////
	//����ʱ�䲽��������Ĭ��Ϊ����ģʽ������1���ӣ�ֵΪ60������ģʽ���Լ�����Ϊ3600�����������ֵ
	int m_stepoftime;	
	//��ǰ���Ƶ�ʱ�䳤��������Ĭ��Ϊ����ģʽ��10���ӣ�ֵΪ600������ֵ��������24Сʱ���Լ�����
	int m_reverse_time_length;					
	//��Ч�ڣ�����NUM_VALIDITY��,Ĭ��ֵ�Ǵ�5���ӵ�24Сʱ��һϵ�У���λ�Ƿ��ӣ������Լ��趨
	//���԰���õ���Ч�������ڸ�������ʼ���ӿ�ƥ���ٶ�
	int m_validity_array[NUM_VALIDITY];
	//	void DebugPrint(void);	//
}JCINPUT;


//namespace jclms{
	const int G_TIMEMOD=60;	//Ĭ�ϰ���60��ȡ����������ݣ����ڷ�ֹһЩ1-3���ӵĴ���
	//ʵ���ϲ�����AES,ֻ����Ϊһ�������Ŀ������С��λ���㴦��
	//#define ZW_AES_BLOCK_SIZE	(128/8)	
	//#define ZW_SM3_DGST_SIZE	(256/8)
	const int ZW_AES_BLOCK_SIZE=(128/8)	;
	const int ZW_SM3_DGST_SIZE=(256/8)	;	

int myGetDynaCodeImplCCB201407a( const int handle );
//�Ӱ������������ݵ��ַ������룬���һ��8λ���������
unsigned int zwBinString2Int32(const char *data,const int len);

	int JcLockGetVersion(void)
	{
		//������������
		return 20140724;	
	}

	//��ù�񻯵�ʱ�䣬Ҳ���ǰ���ĳ��ֵȡ����ʱ��
	static int myGetNormalTime(int gmtTime,const int TIMEMOD) 
	{
		int tail=gmtTime % TIMEMOD;
		return gmtTime-tail;
	}

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

	int JCLMSCCB2014_API JcLockGetDynaCode( const int handle )
	{
		return myGetDynaCodeImplCCB201407a(handle);
	}


	//�Ӱ������������ݵ��ַ������룬���һ��8λ���������
	unsigned int zwBinString2Int32(const char *data,const int len)
	{
		//��1��ͷ��8λ����΢��һЩ������
		const int dyLow=10000019;
		//��9��ͷ��8λ����΢СһЩ������
		const int dyMod=89999969;	
		const int dyMul=257;	//����ҵ�һ��������Ϊ��˵�����

		unsigned __int64 sum=0;
		for (int i=0;i<len;i++)
		{
			unsigned char t=*(data+i);
			sum*=dyMul;
			sum+=t;		
		}
		//���������ֽ��ʹ�ã������϶���8λ���Ķ�̬��
		sum %=dyMod;
		sum +=dyLow;
		return sum;
	}


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
//#ifdef _DEBUG
//		pjc->m_stepoftime=6;	//����ģʽ����6��Ĳ��������ٷ�������
//#else
		pjc->m_stepoftime=60;	//Ĭ������ģʽ������ʱ�䲽��60��
//#endif // _DEBUG
		pjc->m_reverse_time_length=10*60;	//Ĭ������ģʽ������10����
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
		char vstr[11+5+9+3+3];	//���°Ѹ����ɱ��ֶε�λ������һ��
		sprintf(vstr,"%d.%d.%d.%d#%d.%d",jcp->m_datetime,jcp->m_validity,
			jcp->m_closecode,jcp->m_cmdtype,
			jcp->m_stepoftime,jcp->m_reverse_time_length);
		//allItems=allItems+buf;
		char allStr[128];
		memset(allStr,0,128);
		strncpy(allStr,mainstr,128);
		strcat(allStr,vstr);
		printf("All Items = %s \n",allStr);
	}


	//���ɸ������͵Ķ�̬��
	int myGetDynaCodeImplCCB201407a( const int handle )
	{		
		const JCINPUT *lock=(const JCINPUT *)handle;
		SM3 sm3;
		char outHmac[ZW_SM3_DGST_SIZE];
		SM3_init(&sm3);

		JCERROR err=JcLockCheckInput((const int)lock);
		if (EJC_SUSSESS!=err)
		{
			return err;
		}
		//�޶���С��14��ͷ��ʱ��(1.4G��)���߿�Ҫ����2048M��Ļ����ǷǷ���
		/////////////////////////////���Ԫ�ؽ���HASH����/////////////////////////////////////////////
		//���ȴ���̶��ֶε�HASHֵ����
		mySm3Process(&sm3,lock->m_atmno,sizeof(lock->m_atmno));
		mySm3Process(&sm3,lock->m_lockno,sizeof(lock->m_lockno));		
		mySm3Process(&sm3,lock->m_psk,sizeof(lock->m_psk));

		//���ʱ�䵽G_TIMEMOD��ô����
		int l_datetime=myGetNormalTime(lock->m_datetime,lock->m_stepoftime);
		//��Ч�ںͱ�������Ҫ���ݲ�ͬ����ֱ���
		int l_validity=lock->m_validity;
		int l_closecode=lock->m_closecode;	
		//�����ʼ������ʱ�����ù̶���ʱ�䣬��Ч�ڣ��������ֵ
		//�Ա�����ض������ߺ�PSK��˵����ʼ��������һ���㶨ֵ
		if (JCCMD_INIT_CLOSECODE==lock->m_cmdtype)
		{
			//l_datetime=myGetNormalTime(time(NULL),8*60*60);	//��ʼ���������8Сʱ��ȡ��ʱ��
			//l_validity=(24*60)*365;	//��ʼ��Ч����ѡһ���Ϸ���Ч��֮���ֵ,һ����
			//l_closecode=100001111;	//��ʼ��������ѡһ������Χ��9λ�Ƿ�������			
		}		
		//������������ɱ��ֶε�HASHֵ
		mySm3Process(&sm3,lock->m_datetime);
		mySm3Process(&sm3,lock->m_validity);
		mySm3Process(&sm3,lock->m_closecode);
		mySm3Process(&sm3,lock->m_cmdtype);
		//////////////////////////////HASH�������////////////////////////////////////////////
		memset(outHmac,0,ZWSM3_DGST_LEN);
		SM3_hash(&sm3,(char *)(outHmac));
		//��HASH���ת��Ϊ8λ�������
		unsigned int res=zwBinString2Int32(outHmac,ZWSM3_DGST_LEN);
		return res;
	}



	//����ģʽƥ�䣬ʱ��㾫��Ϊȡ����һ��Сʱ����㣬��Ч�ھ���Ϊ1Сʱ��
	//����ҵ��ˣ�����JCOFFLINE����ƥ���ʱ�����Ч�ڣ��������е�ֵ����0
	JCMATCH JCLMSCCB2014_API JcLockReverseVerifyDynaCode( const int handle,const int dstCode )
	{		
		JCINPUT *jcp=(JCINPUT *)handle;
		const int MIN_OF_HOUR=60;	//һСʱ�ķ�����
		JCMATCH jcoff;
		//����Ĭ�ϵ�ʧ�ܷ���ֵ
		jcoff.s_datetime=0;
		jcoff.s_validity=0;

		int l_datetime=time(NULL);
		//����ʱ�����ʼ���������m_stepoftime���������ϣ�������޷�ƥ��
		l_datetime=myGetNormalTime(l_datetime,jcp->m_stepoftime);
		int tail=l_datetime % jcp->m_stepoftime;
		l_datetime-=tail;	//ȡ�������ݽṹ��ָ���Ĳ���
		//����ʱ�䣬��ǰ�����ݽṹ��ָ����һ��ʱ�䣬�����ӵ�һ���첻��
		int tend=l_datetime-jcp->m_reverse_time_length;

		for (int tdate=l_datetime;tdate>=tend;tdate-=jcp->m_stepoftime)			
		{			
			printf("%d\t",tdate);
			for (int v=0;v<NUM_VALIDITY;v++)
			{
				SM3 sm3;
				char outHmac[ZW_SM3_DGST_SIZE];

				SM3_init(&sm3);
				/////////////////////////////���Ԫ�ؽ���HASH����/////////////////////////////////////////////
				mySm3Process(&sm3,jcp->m_atmno,sizeof(jcp->m_atmno));
				mySm3Process(&sm3,jcp->m_lockno,sizeof(jcp->m_lockno));
				mySm3Process(&sm3,jcp->m_psk,sizeof(jcp->m_psk));

				mySm3Process(&sm3,tdate);
				mySm3Process(&sm3,jcp->m_validity_array[v]);
				mySm3Process(&sm3,jcp->m_closecode);
				mySm3Process(&sm3,jcp->m_cmdtype);
				//////////////////////////////HASH�������////////////////////////////////////////////
				memset(outHmac,0,ZWSM3_DGST_LEN);
				SM3_hash(&sm3,(char *)(outHmac));
				unsigned int res=zwBinString2Int32(outHmac,ZWSM3_DGST_LEN);
				if (dstCode==res)	//������ƥ���ʱ�����Ч��
				{
					//��дƥ���ʱ�����Ч�ڵ����
					printf("FOUND MATCH %d %d\n",tdate,jcp->m_validity_array[v]);
					jcoff.s_datetime=tdate;
					jcoff.s_validity=jcp->m_validity_array[v];
					goto foundMatch;
				}
			}	//END OF VALIDITY LOOP
		} //END OF DATE LOOP
		foundMatch:
		return jcoff;
	}

	JCERROR JCLMSCCB2014_API JcLockCheckInput( const int handle )
	{
		const int ZWMEGA=1000*1000;
		JCINPUT *jcp=(JCINPUT *)handle;
		//�ٶ���Щ�����ֶ��ڶ����Ʋ��涼�ǵ�ͬ��int�ĳ��ȵģ��Ա�ͨ��һ��ͳһ�ĺ�������HASH����
		assert(sizeof(jcp->m_datetime)==sizeof(int));
		assert(sizeof(jcp->m_validity)==sizeof(int));
		assert(sizeof(jcp->m_closecode)==sizeof(int));
		assert(sizeof(jcp->m_cmdtype)==sizeof(int));

		assert(jcp->m_datetime>=(1400*ZWMEGA) && jcp->m_datetime<((2048*ZWMEGA)-3));
		assert(jcp->m_cmdtype>JCCMD_START && jcp->m_cmdtype<JCCMD_END);
if (JCCMD_INIT_CLOSECODE!=jcp->m_cmdtype)
{	//���ɳ�ʼ������ʱ���������Ч�ںͱ������ֵ
	assert(jcp->m_validity>=0 && jcp->m_validity<=(24*60));
	assert(jcp->m_closecode>=0 && jcp->m_closecode<=(100*ZWMEGA));
}


		//�޶���С��14��ͷ��ʱ��(1.4G��)���߿�Ҫ����2048M��Ļ����ǷǷ���
		if (jcp->m_datetime<(1400*ZWMEGA) || jcp->m_datetime>((2048*ZWMEGA)-3))
		{//����ʱ��������2014���ĳ��1.4G��֮ǰ�����ӣ����߳���2038��(32λ�з����������ֵ)����Ч
			return EJC_DATETIME_INVALID;
		}
		if (JCCMD_INIT_CLOSECODE!=jcp->m_cmdtype)
		{	//���ɳ�ʼ������ʱ���������Ч�ںͱ������ֵ
		if (jcp->m_validity<0 || jcp->m_validity>(24*60))
		{//��Ч�ڷ�����Ϊ�������ߴ���һ��������Ч
			return EJC_VALIDRANGE_INVALID;
		}
		if (jcp->m_closecode<0 || jcp->m_closecode>(100*ZWMEGA))
		{//������Ϊ�������ߴ���8λ����Ч
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
		switch (mtype)
		{
		case JCI_DATETIME:
			jcp->m_datetime=num;
			break;
		case JCI_VALIDITY:
			jcp->m_validity=num;
			break;
		case JCI_CLOSECODE:
			jcp->m_closecode=num;
			break;
		}
		return EJC_SUSSESS;
	}

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
