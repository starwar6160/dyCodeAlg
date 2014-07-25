#ifndef zwTools1_h__
#define zwTools1_h__

namespace zwTools{
	//////////////////////////////////////////////////////////////////////////


	class JCLMSCCB2014_API zwHexTool
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
	//////////////////////////////////////////////////////////////////////////
#ifdef _DEBUG_USE_OLD_SM3HMAC20140703
	//��Կ����Ϣ�������ժҪ,���Ƕ����Ƹ�ʽ
	int32_t JCLMSCCB2014_API zwSm3Hmac7(zwHexTool &inPsk,
		zwHexTool &inMessage,
		zwHexTool &outHmac);
#endif // _DEBUG_USE_OLD_SM3HMAC20140703

}
#endif // zwTools1_h__

