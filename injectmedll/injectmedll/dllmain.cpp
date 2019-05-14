// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <psapi.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
		TCHAR fileName[MAX_PATH]; // injected process name
		TCHAR msg[MAX_PATH + MAX_PATH];
		for (int i = 0; i < (MAX_PATH + MAX_PATH); i++) // init msg memory to nulls
		{
			msg[i] = NULL;
		}
		wcscat_s(msg, L"I'm in your process!! :) \n\nInjected Process: ");

		if (GetModuleFileName(NULL, fileName, sizeof(fileName) / sizeof(*fileName)) > 0)
		{
			wcscat_s(msg, fileName);

			MessageBox(NULL, msg, L"injectme.dll", MB_OK | MB_ICONEXCLAMATION);
		}
        break;
    }
    return TRUE;
}

