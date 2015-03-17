#ifndef DES_H
#define DES_H

#include <stdint.h>

#define ui64 uint64_t
#define ui32 uint32_t
#define ui8  uint8_t

class DES
{
public:
    DES(ui64 key);
    ui64 des(ui64 block, bool mode);

    ui64 encrypt(ui64 block);
    ui64 decrypt(ui64 block);

    static ui64 encrypt(ui64 block, ui64 key);
    static ui64 decrypt(ui64 block, ui64 key);

protected:
    void keygen(ui64 key);

    ui64 ip(ui64 block);
    ui64 fp(ui64 block);

    void feistel(ui32 &L, ui32 &R, ui32 F);
    ui32 f(ui32 R, ui64 k);

private:
    ui64 sub_key[16]; // 48 bits each
};

class DES3
{
public:
	DES3(ui64 k1, ui64 k2, ui64 k3);
	ui64 encrypt(ui64 block);
	ui64 decrypt(ui64 block);

private:
	DES des1;
	DES des2;
	DES des3;
};
#endif // DES_H

#ifndef DESCBC_H
#define DESCBC_H

#include "des.h"

class DESCBC
{
public:
	DESCBC(ui64 key, ui64 iv);
	ui64 encrypt(ui64 block);
	ui64 decrypt(ui64 block);
	void reset();

private:
	DES des;
	ui64 iv;
	ui64 last_block;
};


enum JC3DES_ERROR{
	JC3DES_OK,
	JC3DES_KEY_INVALID_LENGTH,
	JC3DES_KEY_NONHEX,
	JC3DES_KEY_WEAKKEY,
	JC3DES_DYCODE_OUTOFRANGE,
	JC3DES_OUTBUF_NULL
};

//�ж������ַ����Ƿ���HEX�ַ���������ǣ�����HEX�ַ������ȣ�������ǣ�����0
int myHexStringLength(const char *hexStr);
//ʹ�ý��е�ͨѶ������ԿccbComm3DESKeyHex��8λ��̬��dyCode���ܣ������ڳ���outEncDyCodeHex��
//����ͨѶ������Կ���Լ����ܽ������HEX�ַ�������̬��������
JC3DES_ERROR zwCCB3DESEncryptDyCode(const char *ccbComm3DESKeyHex,const int dyCode,char *outEncDyCodeHex);

#endif // DESCBC_H

