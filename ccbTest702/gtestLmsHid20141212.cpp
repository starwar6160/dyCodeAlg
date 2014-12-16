#include "stdafx.h"
#include "jclmsCCB2014.h"
//#define _ZWLMSHID_TEST1212S1
//#define _ZWLMSHID_TEST1212S2
//#define _ZWLMSHID_TEST1212S3
#define _ZWLMSHID_TEST1212S4
#define _ZWLMSHID_TEST1212S5
void myPureHidTestDataGen20141216(void);

namespace CcbV11Test722Ecies {
	void myHidSecBoxLmsTestGenFixInitCloseCode20141212();

	class jclmsCCBV11_Test:public testing::Test {
		// Some expensive resource shared by all tests.
		//      static T* shared_resource_;
	public:
		static int handle;
		static int pass1DyCode;
		static int verifyCode;
		static int pass2DyCode;
	void myHidSecBoxLmsTestGenFixInitCloseCode20141212();
	protected:
		static void SetUpTestCase() {
			//shared_resource_ = new ;
			//memset(s_priKey,0,sizeof(s_priKey));
			handle = JcLockNew();
			JcLockSetString(handle, JCI_ATMNO, "atm10455761");
			JcLockSetString(handle, JCI_LOCKNO, "lock14771509");
			JcLockSetString(handle, JCI_PSK, "PSKDEMO728");
			JcLockSetInt(handle,JCI_SEARCH_TIME_START,static_cast<int>(time(NULL)));
		} static void TearDownTestCase() {
			//delete shared_resource_;
			//shared_resource_ = NULL;
			JcLockDelete(handle);
			handle = 0;
		}
	};

	int jclmsCCBV11_Test::handle;
	int jclmsCCBV11_Test::pass1DyCode;
	int jclmsCCBV11_Test::verifyCode;
	int jclmsCCBV11_Test::pass2DyCode;

	/////////////////////////////////JCLMS�㷨����/////////////////////////////////////////
#ifdef _DEBUG_JCLMS_GTEST1117

	TEST_F(jclmsCCBV11_Test, CloseCode) {		
		//Newһ�����ݽṹ��ʱ��Ĭ�ϵ�CmdType�������ɱ����룬���Բ�����
		//JCI_CMDTYPE�����ɵĶ�̬�룬���޷�ͨ����֤
		JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_CCB_CLOSECODE);
		JcLockSetInt(handle,JCI_DATETIME,time(NULL));
		int CloseCode = JcLockGetDynaCode(handle);
		cout << "CloseCode729=\t" << CloseCode << endl;
		//���������Ƿ���������Χ��
		EXPECT_GT(CloseCode, 10 * ZWMEGA);
		EXPECT_LT(CloseCode, 100 * ZWMEGA);
		JCMATCH ccodeMatch =
			JcLockReverseVerifyDynaCode(handle, CloseCode);
		EXPECT_GT(ccodeMatch.s_datetime, 1400 * ZWMEGA);
	}


	TEST_F(jclmsCCBV11_Test, inputNew) {
		//�򵥼�鼸��ֵ�������Ϳ����ж��Ƿ��ʼ���ɹ���
		EXPECT_GT(handle, 0);
	}

	TEST_F(jclmsCCBV11_Test, inputCheck) {
		JcLockSetInt(handle,JCI_TIMESTEP,110);
		//���ɳ�ʼ�������ʱ����Ч�ںͱ������ֶζ���Ч�������д�����������Ϳ���
		JcLockSetInt(handle, JCI_VALIDITY, 5);
		JcLockSetInt(handle, JCI_CLOSECODE, 0);
		JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_INIT_CLOSECODE);
		//JcLockDebugPrint(handle);
		//��������Ƿ�Ϸ�
		EXPECT_EQ(EJC_SUSSESS, JcLockCheckInput(handle));
	}



	//��һ���������
	TEST_F(jclmsCCBV11_Test, getDynaCodePass1) {
		JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_INIT_CLOSECODE);
		JcLockDebugPrint(handle);
		int initCloseCode = JcLockGetDynaCode(handle);
		//����ʼ�������Ƿ���������Χ��
		EXPECT_GT(initCloseCode, 0);
		EXPECT_LT(initCloseCode, 100000000);
		printf("initCloseCode=\t%d\n", initCloseCode);
		//�˴��ڴ�ֵ�Ѿ���Ϊ�̶�����1400M���ʱ��ֵ��Ӧ�ò����ٱ��ˡ�
		//20141113.1751����ǰ���쿪����������޸ġ���ΰ
		//������һ���Լ���ԣ����ʧ�ܣ���˵���бȽϴ�������ˣ��������Ʒ�������
		//ARM�������Ż��������⵼�µ����ɴ���Ķ����ƴ���ȵ�
		EXPECT_EQ(38149728, initCloseCode);
		//dynaPass1
		//ע�����ںϷ���ʱ��ֵӦ����1.4G�����ˣ�ע��λ����20140721.1709 
		JcLockSetInt(handle, JCI_DATETIME,
			static_cast < int >(time(NULL)));

		JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_CCB_DYPASS1);
		JcLockSetInt(handle, JCI_CLOSECODE, initCloseCode);
		JcLockDebugPrint(handle);
		pass1DyCode = JcLockGetDynaCode(handle);
		EXPECT_GT(pass1DyCode, 10 * ZWMEGA);
		EXPECT_LT(pass1DyCode, 100 * ZWMEGA);
		printf("dynaPass1=\t%d\n", pass1DyCode);
		JCMATCH pass1Match =
			JcLockReverseVerifyDynaCode(handle, pass1DyCode);
		EXPECT_GT(pass1Match.s_datetime,
			time(NULL) - ZW_MATCHTIME_DIFF_START);
		EXPECT_LT(pass1Match.s_datetime,
			time(NULL) + ZW_MATCHTIME_DIFF_END);
		printf("current time=\t\t%d\n", time(NULL));
		printf("pass1Match Time =\t%d\tValidity=%d\n",
			pass1Match.s_datetime, pass1Match.s_validity);
	}



	//��λ��У�������
	TEST_F(jclmsCCBV11_Test, getDynaCodeVerifyCode) {
		JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_CCB_LOCK_VERCODE);
		//��һ��������ΪҪ�ز�������У����
		JcLockSetInt(handle, JCI_CLOSECODE, pass1DyCode);
		JcLockDebugPrint(handle);
		verifyCode = JcLockGetDynaCode(handle);
		EXPECT_GT(verifyCode, 10 * ZWMEGA);
		EXPECT_LT(verifyCode, 100 * ZWMEGA);
		printf("verCode=\t%d\n", verifyCode);
		JCMATCH verCodeMatch =
			JcLockReverseVerifyDynaCode(handle, verifyCode);
		EXPECT_GT(verCodeMatch.s_datetime,
			time(NULL) - ZW_MATCHTIME_DIFF_START);
		EXPECT_LT(verCodeMatch.s_datetime,
			time(NULL) + ZW_MATCHTIME_DIFF_END);
		printf("current time=\t\t%d\n", time(NULL));
		printf("verCodeMatch Time =\t%d\tValidity=%d\n",
			verCodeMatch.s_datetime, verCodeMatch.s_validity);
	}

	//�ڶ����������
	TEST_F(jclmsCCBV11_Test, getDynaCodePass2) {
		JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_CCB_DYPASS2);
		//У������ΪҪ�ز������ɵڶ�������
		JcLockSetInt(handle, JCI_CLOSECODE, verifyCode);
		JcLockDebugPrint(handle);
		pass2DyCode = JcLockGetDynaCode(handle);
		EXPECT_GT(pass2DyCode, 10 * ZWMEGA);
		EXPECT_LT(pass2DyCode, 100 * ZWMEGA);
		printf("pass2DyCode=\t%d\n", pass2DyCode);
		JCMATCH pass2Match =
			JcLockReverseVerifyDynaCode(handle, pass2DyCode);
		EXPECT_GT(pass2Match.s_datetime,
			time(NULL) - ZW_MATCHTIME_DIFF_START);
		EXPECT_LT(pass2Match.s_datetime,
			time(NULL) + ZW_MATCHTIME_DIFF_END);
		printf("current time=\t\t%d\n", time(NULL));
		printf("pass2Match Time =\t%d\tValidity=%d\n",
			pass2Match.s_datetime, pass2Match.s_validity);
	}

	TEST_F(jclmsCCBV11_Test, zwOpenLockFixTest20141117) {
		int codesum=0;
		//for (int i=0;i<8192;i++)
		for (int i=0;i<3;i++)
		{
			//�̶�����ʱ��,Ӧ�ó����̶��Ľ��
			const int ZWFIX_STARTTIME=1416*ZWMEGA;
			JcLockSetInt(handle,JCI_TIMESTEP,30);
			JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_INIT_CLOSECODE);
			int initCloseCode = JcLockGetDynaCode(handle);
			//�˴��ڴ�ֵ�Ѿ���Ϊ�̶�����1400M���ʱ��ֵ��Ӧ�ò����ٱ��ˡ�
			//20141113.1751����ǰ���쿪����������޸ġ���ΰ
			//������һ���Լ���ԣ����ʧ�ܣ���˵���бȽϴ�������ˣ��������Ʒ�������
			//ARM�������Ż��������⵼�µ����ɴ���Ķ����ƴ���ȵ�
			EXPECT_EQ(38149728, initCloseCode);
			//dynaPass1
			//ע�����ںϷ���ʱ��ֵӦ����1.4G�����ˣ�ע��λ����20140721.1709 
			JcLockSetInt(handle, JCI_DATETIME,ZWFIX_STARTTIME);
			JcLockSetInt(handle,JCI_SEARCH_TIME_LENGTH,8*60);

			JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_CCB_DYPASS1);
			JcLockSetInt(handle, JCI_CLOSECODE, initCloseCode);
			JcLockDebugPrint(handle);
			pass1DyCode = JcLockGetDynaCode(handle);
			codesum+=pass1DyCode;
			EXPECT_EQ(pass1DyCode, 57174184);
			JcLockSetInt(handle,JCI_SEARCH_TIME_START,1416*ZWMEGA+123);
			JCMATCH pass1Match =
				JcLockReverseVerifyDynaCode(handle, pass1DyCode);
			EXPECT_EQ(pass1Match.s_datetime,ZWFIX_STARTTIME);
			//#ifdef _DEBUG
			printf("input time=\t\t%d\n", ZWFIX_STARTTIME);
			printf("pass1Match Time =\t%d\tValidity=%d\n",
				pass1Match.s_datetime, pass1Match.s_validity);
			//#endif // _DEBUG
		}
		printf("%s codesum=%d\n",__FUNCTION__,codesum);
	}


	//���ڲ���ģ����������֮��ͨ�ŵ����������
	TEST_F(jclmsCCBV11_Test, zwHidSecboxLMSemuTest20141124) {
		int codesum=0;
		//assert(sizeof(JCINPUT)==163);		
		//�̶�����ʱ��,Ӧ�ó����̶��Ľ��
		const int ZWFIX_STARTTIME=1416*ZWMEGA;
		JcLockSetInt(handle,JCI_TIMESTEP,30);
		JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_INIT_CLOSECODE);
		//////////////////////////////////////////////////////////////////////////
		JCRESULT lmsRsp;
		printf("zwJclmsReqGenDyCode initCloseCode\n");
		int initCloseCode=0;
		zwJclmsReqGenDyCode(handle,&initCloseCode);


		//int initCloseCode = JcLockGetDynaCode(hnd2);
		//�˴��ڴ�ֵ�Ѿ���Ϊ�̶�����1400M���ʱ��ֵ��Ӧ�ò����ٱ��ˡ�
		//20141113.1751����ǰ���쿪����������޸ġ���ΰ
		//������һ���Լ���ԣ����ʧ�ܣ���˵���бȽϴ�������ˣ��������Ʒ�������
		//ARM�������Ż��������⵼�µ����ɴ���Ķ����ƴ���ȵ�
		EXPECT_EQ(38149728, initCloseCode);
		//dynaPass1
		//ע�����ںϷ���ʱ��ֵӦ����1.4G�����ˣ�ע��λ����20140721.1709 
		JcLockSetInt(handle, JCI_DATETIME,ZWFIX_STARTTIME);
		JcLockSetInt(handle,JCI_SEARCH_TIME_LENGTH,8*60);

		JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_CCB_DYPASS1);
		JcLockSetInt(handle, JCI_CLOSECODE, initCloseCode);
		JcLockDebugPrint(handle);
		//////////////////////////////////////////////////////////////////////////
		printf("zwJclmsReqGenDyCode pass1DyCode\n");
		zwJclmsReqGenDyCode(handle,&pass1DyCode);
		codesum+=pass1DyCode;
		EXPECT_EQ(pass1DyCode, 57174184);
		JcLockSetInt(handle,JCI_SEARCH_TIME_START,1416*ZWMEGA+123);
		//��֤��һ������
		JCMATCH pass1Match ;
		printf("zwJclmsReqVerifyDyCode pass1DyCode\n");
		zwJclmsReqVerifyDyCode(handle,57174184,&pass1Match);						
		EXPECT_EQ(pass1Match.s_datetime,ZWFIX_STARTTIME);
		//#ifdef _DEBUG
		printf("input time=\t\t%d\n", ZWFIX_STARTTIME);
		printf("pass1Match Time =\t%d\tValidity=%d\n",
			pass1Match.s_datetime, pass1Match.s_validity);
		//#endif // _DEBUG
	}
#endif // _DEBUG_JCLMS_GTEST1117

	TEST_F(jclmsCCBV11_Test, zwHidSecboxLMSTest20141203StandTestVector) {
		EXPECT_EQ(0,zwLmsAlgStandTest20141203());
	}


#ifdef _ZWLMSHID_TEST1212S1
	//���ڲ���ģ����������֮��ͨ�ŵ����������
	TEST_F(jclmsCCBV11_Test, zwHidSecboxLMSTest20141211S1) {
		myHidSecBoxLmsTestGenFixInitCloseCode20141212();
	}
#endif	//_ZWLMSHID_TEST1212S1

#ifdef _ZWLMSHID_TEST1212S2
	TEST_F(jclmsCCBV11_Test, zwHidSecboxLMSTest20141211S2) {
		int codesum=0;
		//assert(sizeof(JCINPUT)==163);		
		//�̶�����ʱ��,Ӧ�ó����̶��Ľ��
		const int ZWFIX_STARTTIME=1416*ZWMEGA;
		JcLockSetInt(handle,JCI_TIMESTEP,6);
		JcLockSetInt(handle,JCI_SEARCH_TIME_START,static_cast<int>(time(NULL)));		
		//////////////////////////////////////////////////////////////////////////
		//goto step3;
		JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_INIT_CLOSECODE);		
		int initCloseCode=38149728;
		//dynaPass1
		//ע�����ںϷ���ʱ��ֵӦ����1.4G�����ˣ�ע��λ����20140721.1709 
		JcLockSetInt(handle, JCI_DATETIME,ZWFIX_STARTTIME);
		JcLockSetInt(handle,JCI_SEARCH_TIME_LENGTH,8*60);

		JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_CCB_DYPASS1);
		JcLockSetInt(handle, JCI_CLOSECODE, initCloseCode);
		JcLockDebugPrint(handle);
		//////////////////////////////////////////////////////////////////////////
		printf("zwJclmsReqGenDyCode pass1DyCode\n");
		zwJclmsReqGenDyCode(handle,&pass1DyCode);
		codesum+=pass1DyCode;
		EXPECT_EQ(pass1DyCode, 57174184);
		//#endif // _DEBUG
	}
#endif	//_ZWLMSHID_TEST1212S2

#ifdef _ZWLMSHID_TEST1212S3
	TEST_F(jclmsCCBV11_Test, zwHidSecboxLMSTest20141211S3) {
		int codesum=0;
		//assert(sizeof(JCINPUT)==163);		
		//�̶�����ʱ��,Ӧ�ó����̶��Ľ��
		const int ZWFIX_STARTTIME=1416*ZWMEGA;
		JcLockSetInt(handle,JCI_TIMESTEP,6);
		JcLockSetInt(handle,JCI_SEARCH_TIME_START,static_cast<int>(time(NULL)));		
		//////////////////////////////////////////////////////////////////////////
		//goto step3;
		JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_INIT_CLOSECODE);
		printf("zwJclmsReqGenDyCode initCloseCode\n");
		int initCloseCode=38149728;
		//dynaPass1
		//ע�����ںϷ���ʱ��ֵӦ����1.4G�����ˣ�ע��λ����20140721.1709 
		JcLockSetInt(handle, JCI_DATETIME,ZWFIX_STARTTIME);
		JcLockSetInt(handle,JCI_SEARCH_TIME_LENGTH,8*60);

		JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_CCB_DYPASS1);
		JcLockSetInt(handle, JCI_CLOSECODE, initCloseCode);
		JcLockDebugPrint(handle);
		//////////////////////////////////////////////////////////////////////////
		JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_CCB_DYPASS1);
		JcLockSetInt(handle,JCI_SEARCH_TIME_START,1416*ZWMEGA+123);
		//��֤��һ������
		JCMATCH pass1Match ;
		printf("zwJclmsReqVerifyDyCode pass1DyCode\n");
		zwJclmsReqVerifyDyCode(handle,57174184,&pass1Match);						
		EXPECT_EQ(pass1Match.s_datetime,ZWFIX_STARTTIME);
		//#ifdef _DEBUG
		printf("input time=\t\t%d\n", ZWFIX_STARTTIME);
		printf("pass1Match Time =\t%d\tValidity=%d\n",
			pass1Match.s_datetime, pass1Match.s_validity);
		//#endif // _DEBUG
	}

#endif _ZWLMSHID_TEST1212S3

	void jclmsCCBV11_Test::myHidSecBoxLmsTestGenFixInitCloseCode20141212()
	{
		int initCloseCode=0;
		//�̶�����ʱ��,Ӧ�ó����̶��Ľ��
		const int ZWFIX_STARTTIME=1416*ZWMEGA;
		JcLockSetInt(handle,JCI_TIMESTEP,6);
		//JcLockSetInt(handle,JCI_SEARCH_TIME_START,static_cast<int>(time(NULL)));		
		JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_INIT_CLOSECODE);
		//printf("zwJclmsReqGenDyCode initCloseCode\n");		
		//printf("ZWLINE20141215.1710S1\n");
		zwJclmsReqGenDyCode(handle,&initCloseCode);
		//printf("ZWLINE20141215.1710S2\n");
		//������һ���Լ���ԣ����ʧ�ܣ���˵���бȽϴ�������ˣ��������Ʒ�������
		//ARM�������Ż��������⵼�µ����ɴ���Ķ����ƴ���ȵ�
		EXPECT_EQ(38149728, initCloseCode);
		//////////////////////////////////////////////////////////////////////////
		//��֤��һ������
		JcLockSetInt(handle, JCI_CLOSECODE, initCloseCode);
		JcLockSetCmdType(handle, JCI_CMDTYPE, JCCMD_CCB_DYPASS1);
		JcLockSetInt(handle,JCI_SEARCH_TIME_START,1416*ZWMEGA+123);
		JCMATCH pass1Match ;
		printf("zwJclmsReqVerifyDyCode pass1DyCode\n");
		zwJclmsReqVerifyDyCode(handle,57174184,&pass1Match);						
		EXPECT_EQ(pass1Match.s_datetime,ZWFIX_STARTTIME);
	}

#ifdef _ZWLMSHID_TEST1212S4
	TEST_F(jclmsCCBV11_Test, zwHidSecboxLMSTest20141211S4) {
		for (int i=0;i<3;i++)
		{
			myHidSecBoxLmsTestGenFixInitCloseCode20141212();
			printf("Count %d\n",i);
		}
	}
#endif // _ZWLMSHID_TEST1212S4

#ifdef _ZWLMSHID_TEST1212S5
	TEST_F(jclmsCCBV11_Test, zwHidSecboxLMSTest20141211S5) {
		for (int i=0;i<3;i++)
		{
			myPureHidTestDataGen20141216();
			printf("Count %d\n",i);
		}
	}
#endif // _ZWLMSHID_TEST1212S5

}				//namespace ccbtest722{
