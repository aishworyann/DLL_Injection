#include<stdio.h>
#include<Windows.h>
#include<TlHelp32.h>

#define false 0
#define true 1

DWORD GetProcessId(const char* processName) {
	/*
	* CreateToolhelp32Snapshot -> creates a snapshot of the specified processes, as well as the heaps, modules, and threads used 
	*                             by these processes.
	* ARGUMENTS:
	*	1. TH32CS_SNAPPROCESS -> Flag used to indicate that the snapshot should include all process
	*	2. 0 -> The process ID (ignored while creating a snapshot of processes).
	* RETURN_VALUE:
	*	it returns a HANDLE to the snapshot if successful.
	*/
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		printf("error\n");
		return 0;
	}

	/*
	* Process32First -> Retrieves information about the first process encountered in a system snapshot.
	* ARGUMENTS:
	*	1.Snapshot -> The HANDLE to the snapshot returned by CreateToolHelp32Snapshot
	*	2.ProcessEntry -> a pointer to PROCESSENTRY32 structure that receives information about the first process.
	* RETURN_VALUE:
	*	returns TRUE if successful
	*/
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);
		
	if(Process32First(snapshot, &processEntry)){
		do {
			// printf("The process is: %s\n", processEntry.szExeFile);
			if (strcmp(processEntry.szExeFile, processName) == 0) {
				CloseHandle(snapshot);
				printf("Got PID: %x\n", processEntry.th32ProcessID);
				return processEntry.th32ProcessID;
			}
		} while (Process32Next(snapshot, &processEntry));
	}
	CloseHandle(snapshot);
	return 0;
}



int main() {
	char* processName = "notepad.exe";
	char* dllPath = "C:\\Users\\Aish\\Desktop\\dllinject.dll";

	DWORD processID = GetProcessId(processName);
	if (!processID) {
		//cout << "Failed to find target process: " << endl;
		return 1;
	}
	
	// printf("GOT PID: %x\n", processID);

	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	LPVOID allocMem = VirtualAllocEx(process, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	printf("mem_loc: %p\n", allocMem);
	if (!WriteProcessMemory(process, allocMem, (LPVOID)dllPath, strlen(dllPath) + 1, NULL)) {
		// cerr<<"Failed to write DLL path to target process"<<endl;
		printf("Could not write\n");
		VirtualFreeEx(process,allocMem,0,MEM_RELEASE);
		CloseHandle(process);
		return false;
	}
	
	//PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
	HANDLE remoteThread = CreateRemoteThread(process,NULL, 0 ,(LPTHREAD_START_ROUTINE) LoadLibraryA, allocMem, 0, NULL);
		if (!remoteThread) {
			//cerr<<"Failed to create remote thread in target process"<<endl;
			printf("Could not create thread");
			VirtualFreeEx(process, allocMem, 0, MEM_RELEASE);
			CloseHandle(process);
			return false;
		}

	WaitForSingleObject(remoteThread, INFINITE);
	// VirtualFreeEx(process, allocMem, 0, MEM_RELEASE);
	//CloseHandle(remoteThread);
	//CloseHandle(process);

	//cout << "DLL injected " << endl;
	return 0;

}