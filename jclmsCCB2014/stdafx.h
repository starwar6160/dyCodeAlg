// stdafx.h : ��׼ϵͳ�����ļ��İ����ļ���
// ���Ǿ���ʹ�õ��������ĵ�
// �ض�����Ŀ�İ����ļ�
//

#pragma once

//#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             //  �� Windows ͷ�ļ����ų�����ʹ�õ���Ϣ
// Windows ͷ�ļ�:
//#include <windows.h>

// TODO: �ڴ˴����ó�����Ҫ������ͷ�ļ�
#include <ctime>
#include <cstdio>
#include <cassert>
#include <string>
#include <vector>
#include <map>
#include <stdint.h>
using std::string;
using std::vector;
using std::map;


//////////////////////�滻windows.h���õ��Ĳ��ֶ��忪ʼ///////////////////////////////
//������µĲ��ֶ��壬��windows.h�и��ƹ���
typedef int                 BOOL;
#define WINAPI      __stdcall
#define APIENTRY    WINAPI
#define DECLARE_HANDLE(name) struct name##__{int unused;}; typedef struct name##__ *name
DECLARE_HANDLE(HINSTANCE);
typedef HINSTANCE HMODULE;      /* HMODULEs can be used in place of HINSTANCEs */
typedef unsigned long       DWORD;
typedef void *            *LPVOID;	//�˴���windef.h��̫һ����ȥ���˹�ʱ��far�ؼ���
#define DLL_PROCESS_ATTACH   1    
#define DLL_THREAD_ATTACH    2    
#define DLL_THREAD_DETACH    3    
#define DLL_PROCESS_DETACH   0    

#define FALSE 0
#define TRUE 1

/* Define NULL pointer value */
#ifndef NULL
#ifdef __cplusplus
#define NULL    0
#else
#define NULL    ((void *)0)
#endif
#endif

#ifdef  __cplusplus
extern "C" {
#endif

void WINAPI OutputDebugStringA(char * lpOutputString);
unsigned int crc32(const unsigned int crc32Input,const char *inputData,const int inputLen);
//�������ڶ��CRC8���㣬��һ��ʹ��ʱ,crc8�����������Ϊ0
unsigned char crc8s(const unsigned char crc8Input,const void *inputData, const int inputLen );

#ifdef  __cplusplus
}
#endif

//////////////////////�滻windows.h���õ��Ĳ��ֶ������///////////////////////////////

	
