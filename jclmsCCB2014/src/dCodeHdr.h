#ifndef dCodeHdr_h__
#define dCodeHdr_h__
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

//��ù�񻯵�ʱ�䣬Ҳ���ǰ���ĳ��ֵȡ����ʱ��
int myGetNormalTime(int gmtTime,const int TIMEMOD);
//��ȡ��ʼ�������3���ɱ������ġ��̶�ֵ��
void myGetInitCloseCodeVarItem(int *mdatetime,int *mvalidity,int *mclosecode);

//���ɸ������͵Ķ�̬��
int myGetDynaCodeImplCCB201407a( const int handle );

extern const int ZW_CLOSECODE_STEP;	//������ļ��㲽��ʱ�侫��

#endif // dCodeHdr_h__
