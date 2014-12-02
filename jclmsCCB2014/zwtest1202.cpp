#include <stdio.h>
#include <windows.h>
#include <comutil.h>
//���ڴ���һ���ⲿEXE���̣���������������EXE����DLL���������ڶ����ڣ�
int zwLoadExtEXE( const char *exePathName,const char *exeCmdLine )
{
	STARTUPINFO si;  
	memset(&si,0,sizeof(STARTUPINFO));  
	si.cb = sizeof(STARTUPINFO);  
	si.dwFlags = STARTF_USESHOWWINDOW;  
	si.wShowWindow = SW_SHOW;  
	PROCESS_INFORMATION pi;  
	_bstr_t epath=exePathName;
	_bstr_t eCmd=exeCmdLine;
	BOOL res=CreateProcess(epath,eCmd,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi);
	if (!res)  
	{  
		printf("Create Process Fail\n");
		return -1;
	}  
	else  
	{  
		printf("Create Process Success\n");
	}  
	return 0;
}