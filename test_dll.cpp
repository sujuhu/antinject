#include <stdio.h>
#include <windows.h>

BOOL APIENTRY DllMain( HMODULE hModule,
		      DWORD  ul_reason_for_call,
		      LPVOID lpReserved
		      )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			
		}
	case DLL_THREAD_ATTACH:
		{
			printf("Malware Module is running.\n");
		}
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		{
			//uninit_engine();
		}
		break;
	}
	return true;
}
