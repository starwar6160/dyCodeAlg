#ifndef TESTS_H
#define TESTS_H

#include "des.h"
#include "des3.h"
#include "descbc.h"

void test(ui64 input, ui64 key)
{
    DES des(key);

    ui64 result = des.encrypt(input);
    printf("E: %0I64X\n", result);

    result = des.decrypt(result);
    printf("D: %0I64X\n", result);
    printf("P: %0I64X\n", input);
}

void test1()
{
    ui64 input  = 0x9474B8E8C73BCA7D;

    for (int i = 0; i < 16; i++)
    {
        if (i % 2 == 0)
        {
            input = DES::encrypt(input, input);
            printf("E: %0I64X\n", input);
        }
        else
        {
            input = DES::decrypt(input, input);
            printf("D: %0I64X\n", input);
        }
    }
}

void test2()
{
    ui64 input = 0x9474B8E8C73BCA7D;
    ui64 key   = 0x0000000000000000;
    printf("\n");
    test(input, key);
    printf("\n");
}

void test3()
{
    test(0x0000000000000000, 0x0000000000000000);
    test(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
}

void test4CCB3DES_ECB_EDE2()
{
	//2014/8/16 21:26:47 ���е�3DES��JAVA���Ӵ������н����
	//������Ϊ����ʹ��C#��д��Ӧ����Ĳο�����������
	//����Կ:[0123456789ABCDEF] ����:[F856272510DC7307]
	//���ܽ��Ϊ:[CF8ACCB9945FE89D] ���ܽ��Ϊ: 16-[F856272510DC7307] 
	//���в�������Կ��HEX��ʽΪ3031323334353637 3839414243444546
	//������������Կ��HEX��ʽ��ΪA,B���ݣ��������չ��ABA��ʽ����Կ
	//��ΪEDE��ʽECB���ܵ�3DES�����ǽ��еġ���ʷԭ��"���õ�3DES
	//�˴�����Ѿ����Ͻ���3DES�Ĺ淶��

	DES3 des(0x3031323334353637, 0x3839414243444546, 0x3031323334353637);
	ui64 input = 0xF856272510DC7307;
	ui64 ccbExpectEncResult=0xCF8ACCB9945FE89D;
	ui64 result = des.encrypt(input);
	printf("CCB 3DES Test 20150311\n");
	printf("CCB PlainText:\t\t%0I64X\n", input);    
	printf("CCB Encrypt REAL Result:\t%0I64X\n", result);
	printf("CCB Encrypt EXPECT Result:\t%0I64X\n", ccbExpectEncResult);
	result = des.decrypt(result);
	printf("CCB Decrypt Result:\t%0I64X (shuld same as PlainText)\n", result);   
}

void test5()
{
    DESCBC des(0xFFFFFFFFFFFFFFFF, 0x0000000000000000);

    ui64 input1 = 0x0000000000000000;
    ui64 input2 = 0x0000000000000000;
    ui64 input3 = 0x0000000000000000;

    printf("P1: %0I64X\n", input1);
    printf("E1: %0I64X\n\n", des.encrypt(input1));

    printf("P2: %0I64X\n", input2);
    printf("E2: %0I64X\n\n", des.encrypt(input2));

    printf("P3: %0I64X\n", input3);
    printf("E3: %0I64X  \n", des.encrypt(input3));
}

void alltests()
{
    test1();
    test2();
    test3();
    test4CCB3DES_ECB_EDE2();
    test5();
}

#endif // TESTS_H
