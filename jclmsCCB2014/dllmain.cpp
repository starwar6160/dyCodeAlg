// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "stdafx.h"
int zwLoadExtEXE(const char *exePathName,const char *exeCmdLine);
#include "jclmsCCB2014AlgCore.h"
#include "des.h"

BOOST_PYTHON_MODULE(jccb)  // ʹ��BOOST_PYTHON_MODULE����ģ����Ϊ��example��
{
	boost::python::def("sgen",embPySrvGen);
	boost::python::def("srev",embPySrvRev);	
	boost::python::def("denc",zw3desPyEnc);	
	boost::python::def("ddec",zw3desPyDec);	
	boost::python::def("pskgen",zwGenPSKFromCCB);	
	boost::python::def("pskget",zwGetPSKdemo);	
	
}

BOOL APIENTRY DllMain(HMODULE hModule,
		      DWORD ul_reason_for_call, LPVOID lpReserved)
{
	OutputDebugStringA("JCLMSCCB2014.DLL 20141202.1336");
	//zwLoadExtEXE("C:\\Windows\\notepad.exe", NULL);
	
//////////////////////////////////////////////////////////////////////////
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
