#ifndef mydefs_h__
#define mydefs_h__
#include "stdafx.h"
//ʵ���ϲ�����AES,ֻ����Ϊһ�������Ŀ������С��λ���㴦��
#define ZW_AES_BLOCK_SIZE	(128/8)	
class zwHexTool
{
	char *m_bin;
	int m_binLen;
	int m_padLen;
	string m_CArrayStr;
public:
	zwHexTool(const char *HexInput);
	zwHexTool(const void *msg,const int msgLen);
	~zwHexTool();
	//���θ����ڲ�bin��������ַ,�Լ�����
	char * getBin(void);
	int getBinLen(void);
	int getPadedLen(void);
	int getXXTEABlockNum(void);
	void PrintBin(void);
	const char * getCArrayStr(void);
protected:

private:
};


//XXTEA�㷨����
void btea(uint32_t *v, int n, uint32_t const key[4]) ;
#endif // mydefs_h__
