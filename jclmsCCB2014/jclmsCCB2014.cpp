// jclmsCCB2014.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
//#include <cassert>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "jclmsCCB2014.h"
#include "hashalg\\sm3.h"

//namespace jclms{
	const int G_TIMEMOD=10;	//默认按照10秒取整进入的数据，用于防止一些1-3秒钟的错误
	//实际上不限于AES,只是作为一个基本的块规整大小单位方便处理
	//#define ZW_AES_BLOCK_SIZE	(128/8)	
	//#define ZW_SM3_DGST_SIZE	(256/8)
	const int ZW_AES_BLOCK_SIZE=(128/8)	;
	const int ZW_SM3_DGST_SIZE=(256/8)	;	

int myGetDynaCodeImplCCB201407a( const JcLockInput &lock );
//从包含二进制数据的字符串输入，获得一个8位整数的输出
unsigned int zwBinString2Int32(const char *data,const int len);

	int getVersion(void)
	{
		//含义是是日期
		return 20140721;	
	}

	//获得规格化的时间，也就是按照某个值取整的时间
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
		assert(data>=0);	//几个整数参数，都是0或者正整数
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
		return myGetDynaCodeImplCCB201407a(lock);
	}

	//jclms::JCERROR zwVerifyDynaCode( const JcLockInput &lock,const int dstDyCode )
	//{
	//	int calCode= myGetDynaCodeImplCCB201407a(lock);
	//	if (calCode==dstDyCode)
	//	{
	//		return EJC_SUSSESS;
	//	}
	//	else
	//	{
	//		return EJC_FAIL;
	//	}
	//}

	//从包含二进制数据的字符串输入，获得一个8位整数的输出
	unsigned int zwBinString2Int32(const char *data,const int len)
	{
		//比1开头的8位数稍微大一些的质数
		const int dyLow=10000019;
		//比9开头的8位数稍微小一些的质数
		const int dyMod=89999969;	
		const int dyMul=257;	//随便找的一个质数作为相乘的因子

		unsigned __int64 sum=0;
		for (int i=0;i<len;i++)
		{
			unsigned char t=*(data+i);
			sum*=dyMul;
			sum+=t;		
		}
		//这两个数字结合使用，产生肯定是8位数的动态码
		sum %=dyMod;
		sum +=dyLow;
		return sum;
	}

	void JcLockInput::SetValidity(const int index,const int val)
	{
		if (index>=0 && index<=NUM_VALIDITY)
		{
			m_validity_array[index]=val;
		}		
	}
//////////////////////////////////////////////////////////////////////////
	JcLockInput::JcLockInput()
	{
		memset(m_atmno,0,JC_ATMNO_MAXLEN+1);
		memset(m_lockno,0,JC_LOCKNO_MAXLEN+1);
		memset(m_psk,0,JC_PSK_LEN+1);
		m_datetime=-1;
		m_validity=-1;
		m_closecode=-1;	
		m_cmdtype=JCCMD_INVALID_START;
		m_status=EJC_FAIL;
		m_stepoftime=60;	//默认在线模式，反推时间步长60秒
		m_reverse_time_length=10*60;	//默认在线模式，反推10分钟
		////将5分钟，4小时这样最常用到的有效期排列在前面，提高效率
		//int valarr[]={5,MIN_OF_HOUR*4,MIN_OF_HOUR*8,MIN_OF_HOUR*12,15,30,60,MIN_OF_HOUR*24};
		m_validity_array[0]=5;
		m_validity_array[1]=60*4;
		m_validity_array[2]=60*8;
		m_validity_array[3]=60*12;
		m_validity_array[4]=15;
		m_validity_array[5]=30;
		m_validity_array[6]=60;
		m_validity_array[7]=60*24;
	}

	void JcLockInput::DebugPrint()
	{
		if (EJC_SUSSESS!=CheckInput())
		{
			printf("JcLock Input Para Error!\n");
		}
		 
		m_datetime=myGetNormalTime(m_datetime,G_TIMEMOD);
		string conn=".";	//连字符号
		//三个固定条件组合在一起
		string allItems=m_atmno+conn+m_lockno+conn+m_psk+conn;
		//可变条件逐个化为字符串，组合到一起
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
		if (m_cmdtype==JCCMD_INVALID_START)
		{
			status=EJC_INPUT_NULL;
		}
		//时间秒数取整到G_TIMEMOD，以便消除一些1-2秒的RTC时钟误差造成无法开锁
		m_datetime=myGetNormalTime(m_datetime,G_TIMEMOD);
		m_status=status;
		return status;
	}

	//生成各种类型的动态码
	int myGetDynaCodeImplCCB201407a( const JcLockInput &lock )
	{
		SM3 sm3;
		char outHmac[ZW_SM3_DGST_SIZE];
		SM3_init(&sm3);

		JCERROR err=CheckInputValid(lock);
		if (EJC_SUSSESS!=err)
		{
			return err;
		}
		//限度是小于14开头的时间(1.4G秒)或者快要超出2048M秒的话就是非法了
		/////////////////////////////逐个元素进行HASH运算/////////////////////////////////////////////
		//首先处理固定字段的HASH值输入
		mySm3Process(&sm3,lock.m_atmno,sizeof(lock.m_atmno));
		mySm3Process(&sm3,lock.m_lockno,sizeof(lock.m_lockno));		
		mySm3Process(&sm3,lock.m_psk,sizeof(lock.m_psk));

		//规格化时间到G_TIMEMOD这么多秒
		int l_datetime=myGetNormalTime(lock.m_datetime,G_TIMEMOD);
		//有效期和闭锁码需要根据不同情况分别处理
		int l_validity=lock.m_validity;
		int l_closecode=lock.m_closecode;	
		//计算初始闭锁码时，采用固定的时间，有效期，闭锁码的值
		//以便对于特定的锁具和PSK来说，初始闭锁码是一个恒定值
		if (JCCMD_INIT_CLOSECODE==lock.m_cmdtype)
		{
			l_datetime=myGetNormalTime(time(NULL),8*60*60);	//初始闭锁码采用8小时的取整时间
			l_validity=(24*60)*365;	//初始有效期特选一个合法有效期之外的值,一整年
			l_closecode=100001111;	//初始闭锁码特选一个超范围的9位非法闭锁码			
		}		
		//继续输入各个可变字段的HASH值
		mySm3Process(&sm3,l_datetime);
		mySm3Process(&sm3,l_validity);
		mySm3Process(&sm3,l_closecode);
		mySm3Process(&sm3,lock.m_cmdtype);
		//////////////////////////////HASH运算结束////////////////////////////////////////////
		memset(outHmac,0,ZWSM3_DGST_LEN);
		SM3_hash(&sm3,(char *)(outHmac));
		//把HASH结果转化为8位数字输出
		unsigned int res=zwBinString2Int32(outHmac,ZWSM3_DGST_LEN);
		return res;
	}



	//离线模式匹配，时间点精度为取整到一个小时的零点，有效期精度为1小时起
	//如果找到了，返回JCOFFLINE中是匹配的时间和有效期，否则其中的值都是0
	JCMATCH zwReverseVerifyDynaCode( const JcLockInput &lock,const int dstCode )
	{
		const int MIN_OF_HOUR=60;	//一小时的分钟数

		JCMATCH jcoff;
		//填入默认的失败返回值
		jcoff.s_datetime=0;
		jcoff.s_validity=0;
		
		int l_datetime=time(NULL);
		int tail=l_datetime % lock.m_stepoftime;
		l_datetime-=tail;	//取整到数据结构中指定的步长
		//结束时间，往前推数据结构所指定的一段时间，几分钟到一整天不等
		int tend=l_datetime-lock.m_reverse_time_length;
		
		for (int tdate=l_datetime;tdate>=tend;tdate-=lock.m_stepoftime)
		{			
			//printf("TDATE=\t%d\n",tdate);
			for (int v=0;v<NUM_VALIDITY;v++)
			{
				SM3 sm3;
				char outHmac[ZW_SM3_DGST_SIZE];

				SM3_init(&sm3);
				/////////////////////////////逐个元素进行HASH运算/////////////////////////////////////////////
				mySm3Process(&sm3,lock.m_atmno,sizeof(lock.m_atmno));
				mySm3Process(&sm3,lock.m_lockno,sizeof(lock.m_lockno));
				mySm3Process(&sm3,lock.m_psk,sizeof(lock.m_psk));

				mySm3Process(&sm3,tdate);
				mySm3Process(&sm3,lock.m_validity_array[v]);
				mySm3Process(&sm3,lock.m_closecode);
				mySm3Process(&sm3,lock.m_cmdtype);
				//////////////////////////////HASH运算结束////////////////////////////////////////////
				memset(outHmac,0,ZWSM3_DGST_LEN);
				SM3_hash(&sm3,(char *)(outHmac));
				unsigned int res=zwBinString2Int32(outHmac,ZWSM3_DGST_LEN);
				if (dstCode==res)	//发现了匹配的时间和有效期
				{
					//填写匹配的时间和有效期到结果
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

	JCERROR CheckInputValid( const JcLockInput &lock )
	{
		const int ZWMEGA=1000*1000;
		//假定这些数字字段在二进制层面都是等同于int的长度的，以便通过一个统一的函数进行HASH运算
		assert(sizeof(lock.m_datetime)==sizeof(int));
		assert(sizeof(lock.m_validity)==sizeof(int));
		assert(sizeof(lock.m_closecode)==sizeof(int));
		assert(sizeof(lock.m_cmdtype)==sizeof(int));

		assert(lock.m_datetime>(1400*ZWMEGA) && lock.m_datetime<((2048*ZWMEGA)-3));
		assert(lock.m_validity>=0 && lock.m_validity<=(24*60));
		assert(lock.m_closecode>=0 && lock.m_closecode<=(100*ZWMEGA));
		assert(lock.m_cmdtype>JCCMD_INVALID_START && lock.m_cmdtype<JCCMD_INVALID_END);

		//限度是小于14开头的时间(1.4G秒)或者快要超出2048M秒的话就是非法了
		if (lock.m_datetime<(1400*ZWMEGA) || lock.m_datetime>((2048*ZWMEGA)-3))
		{
			return EJC_DATETIME_INVALID;
		}
		if (lock.m_validity<0 || lock.m_validity>(24*60))
		{
			return EJC_VALIDRANGE_INVALID;
		}
		if (lock.m_closecode<0 || lock.m_closecode>(100*ZWMEGA))
		{
			return EJC_CLOSECODE_INVALID;
		}
		if (lock.m_cmdtype<=JCCMD_INVALID_START || lock.m_cmdtype>=JCCMD_INVALID_END)
		{
			return EJC_CMDTYPE_INVALID;
		}

		return EJC_SUSSESS;
	}


//}	//end of namespace jclms
