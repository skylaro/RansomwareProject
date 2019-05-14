#include <windows.h>
#include <iostream>
#include <strsafe.h>

#define BUFSIZE 4096

int main(int argc, char** argv)
{
    std::cout << "*** Executing Injector ***\n\n";

	int processID = 0;
	std::string szInjectDLL;
	HANDLE hVictimProcess = NULL;
	HANDLE hRemoteThread = NULL;
	LPVOID lpInjectDllAddr = NULL;
	LPVOID lpLoadLibraryAddr = NULL;
	char dllPath[MAX_PATH];
	DWORD exitCode;
	SIZE_T dwBytesWritten;

	if (argc == 3)
	{
		processID = atoi(argv[2]);
		szInjectDLL = argv[1];
	}

	printf("Target process ID:   %d\n", processID);
	printf("DLL to Inject:       %s\n", szInjectDLL.c_str());

	GetFullPathNameA((LPCSTR)szInjectDLL.c_str(),
		_MAX_PATH,
		dllPath, //Output to save the full InjectDLL path
		NULL);
	printf("Path to Inject DLL:  %s [%d]\n", dllPath, strlen(dllPath));

	hVictimProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processID);
	printf("OpenProcess hVictimProcess:          0x%x / %p\n", (UINT)hVictimProcess, hVictimProcess);

	lpInjectDllAddr = VirtualAllocEx(hVictimProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	printf("VirtualAllocEx lpDllAddress:         0x%x / %p\n", (UINT)lpInjectDllAddr, lpInjectDllAddr);

	if (WriteProcessMemory(hVictimProcess, lpInjectDllAddr, dllPath, strlen(dllPath)+1, &dwBytesWritten))
	{
		printf("WriteProcessMemory succeeded :)\n");
		printf("WriteProcessMemory # bytes written:  0x%x / %d\n", (UINT)dwBytesWritten, dwBytesWritten);

		lpLoadLibraryAddr = GetProcAddress(GetModuleHandle(L"Kernel32"), "LoadLibraryA");
		printf("GetProcAddress lpLoadLibraryAddr:    0x%x / %p\n", (UINT)lpLoadLibraryAddr, lpLoadLibraryAddr);

		hRemoteThread = CreateRemoteThread(hVictimProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)lpLoadLibraryAddr, lpInjectDllAddr, NULL, NULL);
		printf("CreateRemoteThread hRemoteThread:    0x%x / %p\n", (UINT)hRemoteThread, hRemoteThread);

		if (hRemoteThread != 0)
		{
			WaitForSingleObject(hRemoteThread, INFINITE);
			GetExitCodeThread(hRemoteThread, &exitCode);
			printf("Thread Exit Code: %d\n", exitCode);
			CloseHandle(hRemoteThread);
			VirtualFreeEx(hVictimProcess, lpInjectDllAddr, 0, MEM_RELEASE);
		}
		else
		{
			printf("CreateRemoteThread failed :(\n");

			LPVOID lpMsgBuf;
			DWORD dw = GetLastError();

			FormatMessage(
				FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				dw,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPTSTR)& lpMsgBuf,
				0, NULL);

			printf("CreateRemoteThread Error: %ls\n", (LPTSTR)lpMsgBuf);
		}
	}
	else
	{
		printf("WriteProcessMemory failed :(\n");
	}

	CloseHandle(hVictimProcess);                                                  

	return 0;
}
