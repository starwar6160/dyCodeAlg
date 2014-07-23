// jclmsCCB2014.cpp : ���� DLL Ӧ�ó���ĵ���������
//

#include "stdafx.h"
//#include <cassert>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "jclmsCCB2014.h"
#include "hashalg\\sm3.h"



//namespace jclms{
	const int G_TIMEMOD=10;	//Ĭ�ϰ���10��ȡ����������ݣ����ڷ�ֹһЩ1-3���ӵĴ���
	//ʵ���ϲ�����AES,ֻ����Ϊһ�������Ŀ������С��λ���㴦��
	//#define ZW_AES_BLOCK_SIZE	(128/8)	
	//#define ZW_SM3_DGST_SIZE	(256/8)
	const int ZW_AES_BLOCK_SIZE=(128/8)	;
	const int ZW_SM3_DGST_SIZE=(256/8)	;	

int myGetDynaCodeImplCCB201407a( const JCINPUT *lock );
//�Ӱ������������ݵ��ַ������룬���һ��8λ���������
unsigned int zwBinString2Int32(const char *data,const int len);

	int getVersion(void)
	{
		//������������
		return 20140721;	
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

	int zwGetDynaCode(const JCINPUT *lock)
	{
		return myGetDynaCodeImplCCB201407a(lock);
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

	void JcLockSetValidity(JCINPUT *jc,const int index,const int val)
	{
		if (index>=0 && index<=NUM_VALIDITY)
		{
			jc->m_validity_array[index]=val;
		}		
	}
//////////////////////////////////////////////////////////////////////////
	void zwNewJcInput(JCINPUT *pjc)
	{
		memset(pjc->m_atmno,0,JC_ATMNO_MAXLEN+1);
		memset(pjc->m_lockno,0,JC_LOCKNO_MAXLEN+1);
		memset(pjc->m_psk,0,JC_PSK_LEN+1);
		pjc->m_datetime=-1;
		pjc->m_validity=-1;
		pjc->m_closecode=-1;	
		pjc->m_cmdtype=JCCMD_INVALID_START;
		pjc->m_status=EJC_FAIL;
		pjc->m_stepoftime=60;	//Ĭ������ģʽ������ʱ�䲽��60��
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
	}

	void JcLockDebugPrint(const JCINPUT *jc)
	{
		if (EJC_SUSSESS!=JcLockCheckInput(jc))
		{
			printf("JcLock Input Para Error!\n");
		}	 		
		//�����̶����������һ��
		char mainstr[JC_ATMNO_MAXLEN+JC_LOCKNO_MAXLEN+JC_PSK_LEN+3];
		memset(mainstr,0,sizeof(mainstr));		
		sprintf(mainstr,"%s.%s.%s.",jc->m_atmno,jc->m_lockno,jc->m_psk);
		//�ɱ����������Ϊ�ַ�������ϵ�һ��
		char vstr[11+5+9+3+3];	//���°Ѹ����ɱ��ֶε�λ������һ��
		sprintf(vstr,"%d.%d.%d.%d",jc->m_datetime,jc->m_validity,
			jc->m_closecode,jc->m_cmdtype);
		//allItems=allItems+buf;
		char allStr[128];
		memset(allStr,0,128);
		strncpy(allStr,mainstr,JC_ATMNO_MAXLEN+JC_LOCKNO_MAXLEN+JC_PSK_LEN+3);
		strcat(allStr,vstr);
		printf("All Items = %s \n",allStr);
	}

	JCERROR JcLockCheckInput(const JCINPUT *jc)
	{
		JCERROR status=EJC_SUSSESS;
		if (strlen(jc->m_atmno)==0)
		{
			status=EJC_INPUT_NULL;
		}
		if (strlen(jc->m_lockno)==0)
		{
			status=EJC_INPUT_NULL;
		}
		if (strlen(jc->m_psk)==0)
		{
			status=EJC_INPUT_NULL;
		}
		if (jc->m_datetime<0)
		{
			status=EJC_INPUT_NULL;
		}
		if (jc->m_validity<0)
		{
			status=EJC_INPUT_NULL;
		}
		if (jc->m_closecode<0)
		{
			status=EJC_INPUT_NULL;
		}
		if (jc->m_cmdtype==JCCMD_INVALID_START)
		{
			status=EJC_INPUT_NULL;
		}
		return status;
	}

	//���ɸ������͵Ķ�̬��
	int myGetDynaCodeImplCCB201407a( const JCINPUT *lock )
	{
		SM3 sm3;
		char outHmac[ZW_SM3_DGST_SIZE];
		SM3_init(&sm3);

		JCERROR err=CheckInputValid(lock);
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
		int l_datetime=myGetNormalTime(lock->m_datetime,G_TIMEMOD);
		//��Ч�ںͱ�������Ҫ���ݲ�ͬ����ֱ���
		int l_validity=lock->m_validity;
		int l_closecode=lock->m_closecode;	
		//�����ʼ������ʱ�����ù̶���ʱ�䣬��Ч�ڣ��������ֵ
		//�Ա�����ض������ߺ�PSK��˵����ʼ��������һ���㶨ֵ
		if (JCCMD_INIT_CLOSECODE==lock->m_cmdtype)
		{
			l_datetime=myGetNormalTime(time(NULL),8*60*60);	//��ʼ���������8Сʱ��ȡ��ʱ��
			l_validity=(24*60)*365;	//��ʼ��Ч����ѡһ���Ϸ���Ч��֮���ֵ,һ����
			l_closecode=100001111;	//��ʼ��������ѡһ������Χ��9λ�Ƿ�������			
		}		
		//������������ɱ��ֶε�HASHֵ
		mySm3Process(&sm3,l_datetime);
		mySm3Process(&sm3,l_validity);
		mySm3Process(&sm3,l_closecode);
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
	JCMATCH zwReverseVerifyDynaCode( const JCINPUT &lock,const int dstCode )
	{
		const int MIN_OF_HOUR=60;	//һСʱ�ķ�����

		JCMATCH jcoff;
		//����Ĭ�ϵ�ʧ�ܷ���ֵ
		jcoff.s_datetime=0;
		jcoff.s_validity=0;
		
		int l_datetime=time(NULL);
		int tail=l_datetime % lock.m_stepoftime;
		l_datetime-=tail;	//ȡ�������ݽṹ��ָ���Ĳ���
		//����ʱ�䣬��ǰ�����ݽṹ��ָ����һ��ʱ�䣬�����ӵ�һ���첻��
		int tend=l_datetime-lock.m_reverse_time_length;
		
		for (int tdate=l_datetime;tdate>=tend;tdate-=lock.m_stepoftime)
		{			
			//printf("TDATE=\t%d\n",tdate);
			for (int v=0;v<NUM_VALIDITY;v++)
			{
				SM3 sm3;
				char outHmac[ZW_SM3_DGST_SIZE];

				SM3_init(&sm3);
				/////////////////////////////���Ԫ�ؽ���HASH����/////////////////////////////////////////////
				mySm3Process(&sm3,lock.m_atmno,sizeof(lock.m_atmno));
				mySm3Process(&sm3,lock.m_lockno,sizeof(lock.m_lockno));
				mySm3Process(&sm3,lock.m_psk,sizeof(lock.m_psk));

				mySm3Process(&sm3,tdate);
				mySm3Process(&sm3,lock.m_validity_array[v]);
				mySm3Process(&sm3,lock.m_closecode);
				mySm3Process(&sm3,lock.m_cmdtype);
				//////////////////////////////HASH�������////////////////////////////////////////////
				memset(outHmac,0,ZWSM3_DGST_LEN);
				SM3_hash(&sm3,(char *)(outHmac));
				unsigned int res=zwBinString2Int32(outHmac,ZWSM3_DGST_LEN);
				if (dstCode==res)	//������ƥ���ʱ�����Ч��
				{
					//��дƥ���ʱ�����Ч�ڵ����
					printf("FOUND MATCH %d %d\n",tdate,lock.m_validity_array[v]);
					jcoff.s_datetime=tdate;
					jcoff.s_validity=lock.m_validity_array[v];
					goto foundMatch;
				}
			}	//END OF VALIDITY LOOP
		} //END OF DATE LOOP
foundMatch:

		return jcoff;
	}

	JCERROR CheckInputValid( const JCINPUT *lock )
	{
		const int ZWMEGA=1000*1000;
		//�ٶ���Щ�����ֶ��ڶ����Ʋ��涼�ǵ�ͬ��int�ĳ��ȵģ��Ա�ͨ��һ��ͳһ�ĺ�������HASH����
		assert(sizeof(lock->m_datetime)==sizeof(int));
		assert(sizeof(lock->m_validity)==sizeof(int));
		assert(sizeof(lock->m_closecode)==sizeof(int));
		assert(sizeof(lock->m_cmdtype)==sizeof(int));

		assert(lock->m_datetime>(1400*ZWMEGA) && lock->m_datetime<((2048*ZWMEGA)-3));
		assert(lock->m_validity>=0 && lock->m_validity<=(24*60));
		assert(lock->m_closecode>=0 && lock->m_closecode<=(100*ZWMEGA));
		assert(lock->m_cmdtype>JCCMD_INVALID_START && lock->m_cmdtype<JCCMD_INVALID_END);

		//�޶���С��14��ͷ��ʱ��(1.4G��)���߿�Ҫ����2048M��Ļ����ǷǷ���
		if (lock->m_datetime<(1400*ZWMEGA) || lock->m_datetime>((2048*ZWMEGA)-3))
		{
			return EJC_DATETIME_INVALID;
		}
		if (lock->m_validity<0 || lock->m_validity>(24*60))
		{
			return EJC_VALIDRANGE_INVALID;
		}
		if (lock->m_closecode<0 || lock->m_closecode>(100*ZWMEGA))
		{
			return EJC_CLOSECODE_INVALID;
		}
		if (lock->m_cmdtype<=JCCMD_INVALID_START || lock->m_cmdtype>=JCCMD_INVALID_END)
		{
			return EJC_CMDTYPE_INVALID;
		}

		return EJC_SUSSESS;
	}


//}	//end of namespace jclms
