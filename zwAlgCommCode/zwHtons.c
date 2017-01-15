//From: http://wxxweb.blog.163.com | Author: wxxweb | E-Mail: wxxweb@163.com 
//���Ŀ�����ת�أ�����ע��ԭ�ĳ���
//	������������������htonl��ntohl�ڲ�ͬ��������������ģ����htonl��ntohl��htons��ntohs����ʵ�֡�
//	ʵ�����£�
typedef unsigned short int uint16;
typedef unsigned long int uint32;

// �����ʹ�С�˻���
#define BigLittleSwap16(A)  ((((uint16)(A) & 0xff00) >> 8) | \
	(((uint16)(A) & 0x00ff) << 8))

// �����ʹ�С�˻���
#define BigLittleSwap32(A)  ((((uint32)(A) & 0xff000000) >> 24) | \
	(((uint32)(A) & 0x00ff0000) >> 8) | \
	(((uint32)(A) & 0x0000ff00) << 8) | \
	(((uint32)(A) & 0x000000ff) << 24))

// ������˷���1��С�˷���0
int checkCPUendian()
{
	union{
		unsigned long int i;
		unsigned char s[4];
	}c;
	c.i = 0x12345678;
	return (0x12 == c.s[0]);
}

// ģ��htonl�����������ֽ���ת�����ֽ���
unsigned long int HtoNl(unsigned long int h)
{
	// ������Ϊ��ˣ��������ֽ���ͬ��ֱ�ӷ���
	// ������ΪС�ˣ�ת���ɴ���ٷ���
	return checkCPUendian() ? h : BigLittleSwap32(h);
}

// ģ��ntohl�����������ֽ���ת�����ֽ���
unsigned long int NtoHl(unsigned long int n)
{
	// ������Ϊ��ˣ��������ֽ���ͬ��ֱ�ӷ���
	// ������ΪС�ˣ���������ת����С���ٷ���
	return checkCPUendian() ? n : BigLittleSwap32(n);
}

// ģ��htons�����������ֽ���ת�����ֽ���
unsigned short int HtoNs(unsigned short int h)
{
	// ������Ϊ��ˣ��������ֽ���ͬ��ֱ�ӷ���
	// ������ΪС�ˣ�ת���ɴ���ٷ���
	return checkCPUendian() ? h : BigLittleSwap16(h);
}

// ģ��ntohs�����������ֽ���ת�����ֽ���
unsigned short int NtoHs(unsigned short int n)
{
	// ������Ϊ��ˣ��������ֽ���ͬ��ֱ�ӷ���
	// ������ΪС�ˣ���������ת����С���ٷ���
	return checkCPUendian() ? n : BigLittleSwap16(n);
}
