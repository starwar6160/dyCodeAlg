// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "stdafx.h"

void zwOutDebugString(const char *pszStr);

static void myShowDLLVersion(const char *fnName)
{
	char version[256];
	memset(version, 0, 256);
	sprintf(version, "%s Version is %s %s\n", fnName, __DATE__, __TIME__);
	zwOutDebugString(version);
	printf("jclmsDLL Version 2014.1114.1156.V205.Fixed zwMergePsk");
}

BOOL APIENTRY DllMain(HMODULE hModule,
		      DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		myShowDLLVersion("jclmsCCB2014.DLL");
		break;
	case DLL_THREAD_ATTACH:
		myShowDLLVersion("jclmsCCB2014.DLL");
		break;
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
