// jclmsCCB2014.cpp : ���� DLL Ӧ�ó���ĵ���������
//
#include "stdafx.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "jclmsCCB2014.h"
#include "sm3.h"
#include "dCodeHdr.h"

const int ZW_SM3_DGST_SIZE=(256/8)	;
const int ZW_CLOSECODE_STEP=12;	//������ļ��㲽��ʱ�侫��
//�ӵ�ǰʱ��ƫ�Ƶ�����������ô���룬�Է�ֹ��������ļ��ܷ�����ʱ��ȽϿ죬�����λ��ƥ��
//��ʱ�򣬴ӵ�ǰʱ�俪ʼƥ�䣬ʼ���޷�ƥ�䵽��Ӧ�ڡ�������ĳ��ʱ���Ķ�̬�룻
//����20140821�ڽ��й㿪���ķ��ֵ����⣻
const int JC_DCODE_MATCH_FUTURE_SEC=60*3;	


 	int JCLMSCCB2014_API JcLockGetDynaCode( const int handle )
	{
		return myGetDynaCodeImplCCB201407a(handle);
	}

	//���ɸ������͵Ķ�̬��
	int myGetDynaCodeImplCCB201407a( const int handle )
	{		
		const JCINPUT *lock=(const JCINPUT *)handle;
		SM3 sm3;
		char outHmac[ZW_SM3_DGST_SIZE];

		//���ʱ�䵽G_TIMEMOD��ô����
		int l_datetime=myGetNormalTime(lock->m_datetime,
			lock->m_stepoftime);
			//60*5);	//20140804.1717.Ӧ�ž��ڵĲ���������ʱ��Ϊ5����ȡ��
		//��Ч�ںͱ�������Ҫ���ݲ�ͬ����ֱ���
		int l_validity=lock->m_validity;
		int l_closecode=lock->m_closecode;	
		//�����ʼ������ʱ������ʮ����´��¹̶���ʱ�䣬��Ч�ڣ��������ֵ
		//�Ա�����ض������ߺ�PSK��˵����ʼ��������һ��ʮ������ڵĺ㶨ֵ
		if (JCCMD_INIT_CLOSECODE==lock->m_cmdtype)
		{
			//l_datetime=myGetNormalTime(time(NULL),ZWMEGA);	//��ʼ���������1M��(��Լ12��)��ȡ��ʱ��
			//l_validity=1000;	//��ʼ��Ч��ȡһ����Ч��Χ�ڵĹ���ֵ
			//l_closecode=1000000;	//��ʼ��������ѡһ����Ч��Χ�ڵĹ���ֵ
			myGetInitCloseCodeVarItem(&l_datetime,&l_validity,&l_closecode);
		}		
		if (JCCMD_CCB_CLOSECODE==lock->m_cmdtype)
		{//���������ı����룬����3���̶�����������ض���ȡ��������ʱ�䣬�Լ��̶�����Ч�ں͡������롱��Ϊ����
			myGetCloseCodeVarItem(&l_datetime,&l_validity,&l_closecode);
		}
		JCERROR err=JcLockCheckInput((const int)lock);
		if (EJC_SUSSESS!=err)
		{
			return err;
		}


		SM3_init(&sm3);

		//�޶���С��14��ͷ��ʱ��(1.4G��)���߿�Ҫ����2048M��Ļ����ǷǷ���
		/////////////////////////////���Ԫ�ؽ���HASH����/////////////////////////////////////////////
		//���ȴ���̶��ֶε�HASHֵ����
		mySm3Process(&sm3,lock->m_atmno,sizeof(lock->m_atmno));
		mySm3Process(&sm3,lock->m_lockno,sizeof(lock->m_lockno));		
		mySm3Process(&sm3,lock->m_psk,sizeof(lock->m_psk));

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
	JCMATCH JCLMSCCB2014_API JcLockReverseVerifyDynaCode( const int handle,const int dstCode )
	{		
		JCINPUT *jcp=(JCINPUT *)handle;
		const int MIN_OF_HOUR=60;	//һСʱ�ķ�����
		JCMATCH jcoff;
		//����Ĭ�ϵ�ʧ�ܷ���ֵ
		jcoff.s_datetime=0;
		jcoff.s_validity=0;

		//���ݽ��й㿪���ķ��ֵ����⣬�ӡ������������ӵ�ʱ�俪ʼ����ȥ����
		//ƥ�䣬�Է����������������֮����ʱ����
		int l_datetime=time(NULL)+JC_DCODE_MATCH_FUTURE_SEC;		
		int l_closecode=jcp->m_closecode;
		int l_timestep=jcp->m_stepoftime;
		if (JCCMD_CCB_CLOSECODE==jcp->m_cmdtype)
		{
			int l_validity=jcp->m_validity;	//�����������֤ʱ���ã�ֻ��Ϊ�����㺯������Ҫ��
			//�������֤�����룬�ͻ�һ�ײ���
			//��֤�������ʱ���Ƿ���Ҫ��������ʱ���أ�2014.0729.1509��ΰ
			myGetCloseCodeVarItem(&l_datetime,&l_validity,&l_closecode);
			l_timestep=ZW_CLOSECODE_STEP;
			assert(ZW_CLOSECODE_STEP>0 && ZW_CLOSECODE_STEP<60);
		}

		//����ʱ�����ʼ���������m_stepoftime���������ϣ�������޷�ƥ��
		l_datetime=myGetNormalTime(l_datetime,l_timestep);
		int tail=l_datetime % l_timestep;
		l_datetime-=tail;	//ȡ�������ݽṹ��ָ���Ĳ���
		//����ʱ�䣬��ǰ�����ݽṹ��ָ����һ��ʱ�䣬�����ӵ�һ���첻��
		int tend=l_datetime-jcp->m_reverse_time_length;

		for (int tdate=l_datetime;tdate>=tend;tdate-=l_timestep)			
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
				mySm3Process(&sm3,l_closecode);
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

